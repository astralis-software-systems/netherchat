# Invite-store janitor — build-ready plan

Status: **planned** (no code written). Server-internal feature. Additive,
in-memory, no wire-format change. A direct sibling of the existing ephemeral
room-janitor pattern; this closes a slow, unbounded memory leak in the invite
store that the just-shipped webhook spawn cap *mitigates* but does not *fix*.

This plan designs a **background sweep that reclaims expired invite tokens** from
`server/internal/invite/invite.go`'s `Store`. It sweeps on the `expires` field the
`Store` already carries (set on every current mint), under the same mutex and with
the same predicate the existing `Redeem` uses. It deliberately does **not** touch
the wire format, the `Redeem`/`Generate` semantics, or the zero-expiry capability.

---

## 1. Scope & the leak

### 1.1 What persists today, and why

The `Store` (`server/internal/invite/invite.go:18-22`) is an in-memory set of live
invite tokens:

```go
type entry struct {
	room    string
	expires time.Time // zero = no expiry
}
type Store struct {
	mu     sync.Mutex
	tokens map[string]entry
}
```

A token is **only ever removed on a `Redeem` attempt for that exact token string**.
`Redeem` (`invite.go:46-63`) deletes on two paths — an expired-token attempt
(`invite.go:55`) and a successful consume (`invite.go:61`) — but **nothing else
ever touches the map**. There is no background sweep.

Because tokens are 18 random bytes (`invite.go:29-31`, base64-encoded), an
unredeemed token is **unguessable**: no one will ever submit that exact string, so
its `Redeem`-triggered delete never fires. The consequence:

- A token that is **minted but never redeemed persists for the process lifetime.**
- Worse, an **expired-but-never-attempted token also persists** — the lazy delete on
  the expired path (`invite.go:55`) only runs if someone happens to attempt that
  specific expired string, which for a random token they never do.

This is a slow, unbounded memory-growth vector in a long-running relay. Its rate is
bounded by how fast tokens are minted, and the four mint sites all set a positive
TTL today:

| Mint site | TTL | Effective expiry |
|---|---|---|
| `ws/server.go:301` — `/invite` (`OpInviteRequest`) | `inviteTTL = 24 * time.Hour` (`ws/server.go:33`) | 24 h, **decoupled from the room** |
| `ws/server.go:410` — break-glass host token | room TTL (clamped `[1m, 7d]`) | = room deadline |
| `ws/server.go:417` — break-glass invitee tokens | room TTL | = room deadline |
| `api/api.go:229` — `spawnWarRoom` (webhook + alert) | `ephemeral.ClampTTL(rule.TTL)` (`[1m, 7d]`) | = room deadline |

So every token in flight today **already has a concrete `expires`** — the sweep has
a field to act on; no new lifecycle concept is required. The recently shipped
webhook rate/spawn guard bounds the *minting rate* but reclaims nothing — the leak
itself is unaddressed until this sweep lands.

### 1.2 Why a time sweep is necessary (not a room hook)

The reconnaissance confirmed that **no room-teardown path touches the invite store.**
`hub.ExpireRoom` (`hub.go:132-149`), `hub.expireIdleRooms` (`hub.go:328-361`), and
`Scuttle` (`hub.go:208-`) all delete the room and fire exactly one out-of-band
callback — `onClose`, wired solely to `beacons.Delete` (`server.go:68`). None
reclaim invites. Critically, the **`/invite` 24 h tokens outlive their room**: a
normal room can be scuttled or idle-expired in minutes while its 24 h tokens linger
(and then linger forever, since nothing GCs them). A room-teardown hook therefore
*cannot* cover the sharpest case — a standalone time sweep is necessary regardless.

---

## 2. Settled decisions (do not re-litigate)

1. **Standalone time-based sweep — NOT a room-teardown hook.** One simple background
   sweep on `expires`. No coupling to room lifecycle (§1.2). A room-hook would be a
   mere optimization and cannot cover the 24 h `/invite` orphan; excluded.
2. **Skip zero-expiry tokens.** The sweep reclaims only tokens where
   `!expires.IsZero() && now.After(expires)` — byte-identical to `Redeem`'s expiry
   check (`invite.go:54`). Zero `expires` = never expire = never swept. The API's
   `ttl == 0` branch in `Generate` (`invite.go:34-36`) is **left intact**; no caller
   mints a zero-expiry token today, but the capability stays.
3. **No grace period.** Reclaim exactly at expiry, matching `Redeem`. No slack.
   Break-glass tokens are meant to die with the room; `/invite` already has a
   generous 24 h. Adding grace is a new concept with no demand.
4. **Run for process life — house convention.** Both existing janitors run unstopped:
   the hub idle-janitor (`hub.go:319-326`, started in `hub.New` at `hub.go:53`) and
   the ephemeral room-janitor (`ephemeral.go:141-147`, started by `Start`). No stop
   channel. Match that; do not introduce a stoppable janitor (it would diverge from
   the two existing janitors for no benefit).

---

## 3. The design

### 3.1 The load-bearing safety guarantee (same predicate + same mutex)

The sweep runs concurrently with `Redeem`. The single invariant the design **must**
guarantee: **the sweep can only ever delete a token that `Redeem` would already
reject — it can never reclaim a live, unexpired token out from under a valid
redeemer.** This holds by construction from two facts:

1. **Same predicate.** The sweep deletes a token **iff**
   `!e.expires.IsZero() && now.After(e.expires)` — exactly `Redeem`'s expiry check
   at `invite.go:54`. If a token is not yet expired, `now.After(e.expires)` is false
   and the sweep skips it. So the sweep never removes a redeemable token.
2. **Same mutex.** The sweep takes `s.mu.Lock()` — the *same* `sync.Mutex`
   (`invite.go:20`) that `Redeem` (`invite.go:47`) and `Generate` (`invite.go:37`)
   take. There is no `RWMutex`, no second lock, no lock-free read. The operations
   therefore **serialize**; there is no window in which a redeemer observes a token
   the sweep is mid-deleting.

Walk the near-expiry race (token expires at instant *T*; a redeem and a sweep both
fire around *T*):

- **Sweep wins the lock first** → it deletes the (now-expired) token → the following
  `Redeem` sees `!ok` → returns `false`. Identical outcome to `Redeem`'s own expired
  path, which would also have deleted it and returned `false`.
- **Redeem wins first** → its own `time.Now().After(e.expires)` check (`invite.go:54`)
  fires → deletes it → returns `false`. The sweep then finds nothing.

Either ordering yields the *existing* behavior — an expired token's redeem fails. The
sweep introduces **no new redemption-failure mode.** And because wall-clock time is
monotonic-forward, if the sweep's `now` is past `expires`, any *later* `Redeem`'s own
`time.Now()` is also past `expires` — so the sweep can never delete a token that a
concurrent redeemer would have legitimately considered live. The "never reclaim a
live token" property is a direct corollary of predicate identity.

Because reclaiming a token **notifies nobody** (unlike the room janitor's
`onExpire`, which closes member connections), the sweep needs no collect-then-act
dance: it can **iterate-and-delete entirely under the lock** — strictly simpler than
the ephemeral janitor's two-phase sweep (`ephemeral.go:149-167`).

### 3.2 Structure — mirror the ephemeral janitor's `New` / `Start` / `janitor` / `sweep` split

Mirror `server/internal/ephemeral/ephemeral.go` exactly, minus the callback:

- **`New()` — unchanged.** It still only allocates the map (`invite.go:25`); it does
  **not** spawn the goroutine. This parity with `ephemeral.New` (`ephemeral.go:54-59`,
  which also only allocates) is deliberate: callers that build a `Store` without a
  running relay — the api unit tests at `api/webhook_test.go:61` and
  `api/alert_test.go:39` — get **no janitor goroutine** and cannot have tokens
  reclaimed mid-test.
- **`Start()` — new, arg-less.** Spawns the goroutine: `go s.janitor()`. Unlike the
  room janitor's `Start(onExpire func(...))` (`ephemeral.go:64-69`), the invite sweep
  has **no callback**, so `Start` takes **no argument**. (Signature: `func (s *Store) Start()`.)
- **`janitor()` — new, unexported.** The ticker loop, run for process life with no
  stop channel (decision #4), mirroring `ephemeral.go:141-147`:

  ```go
  func (s *Store) janitor() {
  	ticker := time.NewTicker(sweepInterval)
  	defer ticker.Stop()
  	for range ticker.C {
  		s.sweep(time.Now())
  	}
  }
  ```

- **`sweep(now time.Time) int` — new, unexported, testable.** Takes an injected
  `now` (so a unit test can drive it with a synthetic instant, exactly as
  `ephemeral_test.go`'s `TestSweepExpiresPastDeadline` drives `r.sweep(syntheticNow)`),
  iterates and deletes under the lock, and **returns the count reclaimed** (the
  chosen observability surface, §3.4):

  ```go
  func (s *Store) sweep(now time.Time) int {
  	s.mu.Lock()
  	defer s.mu.Unlock()
  	var n int
  	for token, e := range s.tokens {
  		if !e.expires.IsZero() && now.After(e.expires) {
  			delete(s.tokens, token)
  			n++
  		}
  	}
  	return n
  }
  ```

  Deleting from a map during `range` is safe in Go (the spec permits deleting the
  current or not-yet-visited keys during iteration).

### 3.3 Cadence — recommend **30 s** (package-local `sweepInterval` const)

Define a package-local constant (mirroring `ephemeral.go:27`'s `sweepInterval`),
**not** an import of the hub's literal:

```go
const sweepInterval = 30 * time.Second
```

Reasoning:

- **The ephemeral janitor's 1 s tick exists to keep a tight promise** ("vanishes at
  16:00" must not drift past the hub's 30 s idle janitor — `ephemeral.go:138-140`).
  Invites carry **no such deadline promise**: an expired token is already useless
  (`Redeem` rejects it), so whether memory is reclaimed at *expiry + 30 s* or
  *expiry + 5 min* is operationally irrelevant. The leak being fixed is measured in
  *process lifetime* (days/weeks), not seconds.
- **A tighter tick is wasted work.** The sweep iterates the whole map under `s.mu`,
  contending with `Redeem`/`Generate`. A 1 s tick would hold the lock 30× more often
  for no reclamation benefit, since the leak rate is slow (one token per interactive
  `/invite`; a handful per spawn, now further bounded by the webhook spawn cap).
- **30 s matches the closest analog** — the hub idle-janitor (`hub.go:321`), which is
  likewise "background GC of a resource with no tight deadline." Aligning the two slow
  GCs keeps the codebase coherent.
- A **coarser** interval (60 s, or several minutes) is also defensible — the map stays
  small and worst-case held-but-expired memory is tiny either way — but **30 s wins on
  consistency** with the existing slow janitor while keeping reclamation latency
  comfortably tight. Recommend **30 s**; coarsening later is a one-line change.

### 3.4 Observability surface — recommend **`sweep` returns the reclaimed count** (no new public accessor)

The `Store` exposes no `Len`/`Get`/callback today, so a direct `sweep(now)`-style
unit test needs *something* to assert reclamation against. Options weighed:

| Option | Verdict | Reasoning |
|---|---|---|
| **(b) `sweep(now) int` returns count reclaimed** | **recommended** | Adds **zero exported symbols** — `sweep` stays unexported; only its signature gains an `int` return. The count is the natural in-package test signal, and the "survives / is gone" assertions ride the **existing public `Redeem`** (returns `true` for a live token, `false` for a reclaimed one). It can also be debug-logged by the janitor when `n > 0`, giving the return a minor production use too. |
| (a) public `Len() int` accessor | rejected | Adds a public method with **no production consumer today** — over-exposure purely for the test. It invites callers to depend on a live-token count nothing needs yet. If a live-invite gauge is ever wanted, `Len()` can be added *then*, with a real consumer. |
| (c) test reads `s.tokens` directly (white-box) | rejected | Couples the test to the private field name for no gain over (b); (b) asserts through the method boundary instead. |

**Parity argument (decisive):** the ephemeral package added **nothing** for its test
— `TestSweepExpiresPastDeadline` observes via the production `onExpire` callback and
the production `Get` method. By the same principle, invites should add nothing
test-only: the **existing public `Redeem`** is the production observability for "is
this token live," and the unexported `sweep`'s `int` return is the in-package signal.
**Recommend (b).**

### 3.5 Insertion point in the startup path

In `server/server.go`, `func handlerWithStore` constructs the store at line 53 and
starts the ephemeral janitor at line 57:

```go
invites := invite.New()                 // server.go:53
...
eph := ephemeral.New(log)               // server.go:56
eph.Start(h.ExpireRoom)                 // server.go:57
```

Add the invite janitor start **immediately after `invite.New()`**, mirroring
`eph.Start(...)`:

```go
invites := invite.New()
invites.Start()                          // ← new: begin reclaiming expired tokens
```

`Start()` is arg-less (§3.2). This means every full server built via
`server.Handler` / `handlerWithStore` runs the invite janitor — including the
`tui/e2e/` tests, which is fine: they mint with deadlines (room TTL ≥ `MinTTL` =
1 min, or the 24 h `/invite`) far beyond their sub-second runtime, so the 30 s sweep
never reclaims a token they still need. The api unit tests build `invite.New()`
directly (not via `handlerWithStore`) and never call `Start`, so no janitor runs
there (§3.2).

---

## 4. Invariant register (what this must NOT disturb — and why it doesn't)

| Invariant | Status | Why |
|---|---|---|
| Same-predicate-same-mutex safety (§3.1) | **held** | `sweep` reuses `Redeem`'s exact expiry predicate (`invite.go:54`) and the same `s.mu`; serialized + predicate-identical ⇒ it can only delete tokens `Redeem` would reject; monotonic time ⇒ never a live token. |
| `Redeem` / `Generate` semantics | **unchanged** | The sweep is purely additive. The lazy-delete-on-redeem path (`invite.go:55, 61`) and the mint path are untouched. One-time-redeem is preserved: the sweep only removes *already-expired* entries, which can no longer be redeemed anyway. |
| Zero-expiry capability | **preserved** | The predicate's `!e.expires.IsZero()` clause skips no-expiry tokens; `Generate`'s `ttl == 0` branch (`invite.go:34-36`) is not removed or changed. |
| Zero-persistence / in-memory | **held** | The `Store` is already a `map[string]entry` with nothing persisted (package doc, `invite.go:1-3`). The sweep is **pure in-memory GC** — no durable store, no disk, no new state. |
| Blind-relay import boundary (`TestServerBinaryDoesNotLinkClientCrypto`, `tui/e2e/e2e_test.go:231`) | **held** | The janitor adds only `time` (already imported, `invite.go:10`) usage + a goroutine. **No new import**, and certainly not `tui/internal/crypto`. `crypto/rand` already present is stdlib. |
| House janitor convention | **matched** | Run-for-process-life, no stop channel — mirrors `hub.janitor` (`hub.go:319`) and `ephemeral.janitor` (`ephemeral.go:141`). The per-handler goroutine in tests is the same accepted tradeoff those two already make. |
| Indirect exercisers stay green | **held** | `api/webhook_test.go:61` & `api/alert_test.go:39` build `invite.New()` but never `Start` → no janitor, no mid-test reclamation. `tui/e2e/features_test.go` break-glass mint asserts a future deadline (`:146-147`) far beyond test runtime. |
| Wire format / protocol | **untouched** | No new field, no opcode change, no `protocol/` edit. `Generate`'s return shape and `InviteResult`/`BreakGlassInvite` are unchanged. |

---

## 5. Test plan

The reconnaissance confirmed `server/internal/invite/` contains **only `invite.go`,
with no `_test.go`** — so this adds the **package's first direct unit test**. New
file `server/internal/invite/invite_test.go`, **`package invite`** (white-box, so it
can call the unexported `sweep` — exactly as `ephemeral_test.go` is `package
ephemeral` and calls `r.sweep(...)`). The test drives `sweep(syntheticNow)` directly
and **does not call `Start`** (no real ticker needed — deterministic).

Mirroring `ephemeral_test.go`'s `TestSweepExpiresPastDeadline`:

1. **`TestSweepReclaimsExpired`** — `New()`; mint `tok := Generate("room", ttl)` →
   note `exp`.
   - `sweep(exp.Add(-time.Second))` → want **0** (not yet expired); the token
     survives.
   - `sweep(exp.Add(time.Second))` → want **1** (reclaimed).
   - `Redeem(tok, "room")` → want **false** (gone — proves the sweep removed it).
   - `sweep(exp.Add(time.Hour))` → want **0** (idempotent re-sweep; nothing left).
2. **`TestSweepKeepsLiveToken`** — mint `tok` with a `ttl`; `sweep(beforeExpiry)` →
   **0**; then `Redeem(tok, "room")` → **true** (the live token survived the sweep
   and is still redeemable — the safety guarantee, observed end-to-end).
3. **`TestSweepSkipsZeroExpiry`** — mint `tok := Generate("room", 0)` (zero expiry);
   `sweep(time.Now().Add(100 * time.Hour))` → want **0** even at a far-future `now`;
   `Redeem(tok, "room")` → **true** (zero-expiry is immune to the sweep).
4. **(idempotency)** — covered by the final re-sweep step of test 1; optionally a
   dedicated case asserting two consecutive post-expiry sweeps reclaim `1` then `0`.

**Regression — assert green, do not edit:**

- `api/webhook_test.go` and `api/alert_test.go` (build `invite.New()`, never `Start`)
  — unaffected; no janitor runs.
- `tui/e2e/features_test.go` break-glass flow (`:95` mint, `:139`/`:146-147` asserts)
  — runs via `server.Handler`, so the janitor *does* start, but deadlines (≥ 1 min /
  24 h) outlast the sub-second test; tokens are redeemed/asserted before any sweep.

Run, per the repo's Windows/Go notes, one package at a time via PowerShell:
`go test ./server/internal/invite/`, then the api and e2e packages.

---

## 6. What this is NOT doing (anti-bloat)

- **No room-teardown hook.** No coupling to `hub.ExpireRoom` / `onClose` /
  `SetOnClose`. One standalone time sweep (decision #1; a hook can't cover the 24 h
  `/invite` orphan anyway).
- **No grace period.** Reclaim exactly at `expires`, matching `Redeem`. No slack
  constant, no creation-time anchor (creation time isn't even stored).
- **No stoppable janitor.** No stop channel, no `Close`/`Stop` method — run for
  process life, matching the hub and ephemeral janitors.
- **No change to `Redeem` or `Generate` semantics.** The sweep is additive; the
  lazy-delete-on-redeem path and the mint path are untouched.
- **No removal of the zero-expiry capability.** `Generate(room, 0)` still mints a
  never-expiring token; the sweep simply never touches it.
- **No new public accessor.** No `Len()`/`Get()` — observability is the unexported
  `sweep`'s `int` return plus the existing public `Redeem` (§3.4).
- **No wire-format / protocol change.** No new field, opcode, or `protocol/` edit.
- **No persistence.** In-memory GC only; a restart clears the map (consistent with
  zero-persistence — the same accepted tradeoff as every other server-side store).

---

## 7. Open questions for you

1. **Cadence:** **30 s** (recommended — matches the hub idle-janitor; the leak is
   slow so a tighter tick is wasted lock-holding work) — confirm, or prefer coarser
   (60 s / several minutes)?
2. **Observability surface:** **`sweep` returns the reclaimed count, no public
   `Len()`** (recommended — zero new exported symbols, parity with how ephemeral adds
   nothing test-only) — confirm, or do you want a public `Len()` now for a future
   live-invite metric?
3. **Janitor logging:** debug-log the reclaimed count **only when `n > 0`** (keeps
   pure-GC noise out of the logs), or stay fully silent? (Minor; reclaiming a token
   is far less operationally meaningful than a war room closing, which the ephemeral
   janitor logs at `Info`.)
4. **Start placement:** `invites.Start()` in `handlerWithStore` right after
   `invite.New()` (`server.go:53`), mirroring `eph.Start(...)` at `server.go:57`
   (recommended) — confirm. (This starts the janitor in full-server e2e tests too;
   shown harmless in §3.5.)

---

## 8. Git note

- HEAD = `f257794` (the webhook rate/spawn guard commit); branch `main`; working tree
  clean. This plan adds **only** this document; no code, no `go.mod`, no tag, no
  build.
- Suggested commit for the *build* (later, not now), generic:
  `feat(server): background janitor reclaims expired invite tokens`. Per the repo
  workflow, the build lands as its own scoped commit after this plan is reviewed.
