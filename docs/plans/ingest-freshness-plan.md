# Ingest freshness protection — build-ready plan

Status: **planned** (no code written). Server-ingest-internal feature. One commit's
worth of work, additive, no wire-format change.

This plan designs **replay/freshness protection for the inbound alert socket** via a
**timestamp acceptance window** over the `ts` value the alert HMAC already signs. It
is deliberately narrow: it enforces a timestamp the system *already* signs but never
validates, and adds nothing else.

---

## 1. Scope & mechanism

**Mechanism (decided, not re-litigated):** a per-source **timestamp acceptance
window**. `protocol.AlertSigningBytes(source, severity, kind, summary, ref, ts)`
already appends the unix-second `ts` to the HMAC-SHA256 preimage
(`protocol/alert_signing.go`, `ts_be64` at the tail). Today that `ts` is *signed but
never read*. This feature recomputes nothing new — it validates the already-verified
`ts` against `now ± tolerance` after the HMAC check passes and before any war room
spawns.

Because `ts` rides the existing signed bytes:

- **No new signed field, no nonce, no wire-format change.** `connector.Alert`,
  `server/internal/alert.AlertV1`, and `connector.AllowedFields` are untouched, so the
  strict-JSON forward-incompat hazard and the
  `connector.Alert`↔`alert.AlertV1`↔`AllowedFields`↔adapter-boundary-test blast radius
  are avoided entirely.
- **The signed `ts` is tamper-proof in transit.** An attacker replaying a captured
  alert cannot alter its `ts` (that would break the HMAC) and cannot forge a fresh `ts`
  (no secret). So a captured alert carries a *fixed, aging* `ts` — exactly what a
  window defeats.

**State (decided):** in-memory, per-source, ephemeral, living on `alert.Guards`. With
the recommended pure-window design (see §5.4) freshness is **essentially stateless** —
the only mutable state is a small per-source "already warned" set for log de-dup. It
dies with the process. A replay in the seconds after a relay restart can slip through;
that is the honest, on-brand tradeoff of zero-persistence, not a defect.

---

## 2. The narrowness statement — what is already protected, what is the real gap

The read (recon pass) established that the approval/record substrate is **already
replay-resistant**, by construction, in several independent ways. This feature must
**not** touch any of it:

- **Artifact proposals** carry a random `Nonce` *and* an `ExpiresUnix` (~300 s TTL),
  and `client.onArtifactProposal` both dedups by `ProposalID` and drops expired
  proposals (`tui/client/artifact.go`).
- **Artifact approvals** bind `proposal_id‖artifact_hash‖approver_fpr‖nonce`
  (`protocol/artifact_signing.go`) — an approval cannot be replayed across proposals,
  artifacts, approvers, or instances.
- The **proposal/approval path is unreachable from HTTP ingest** — the "second law":
  an inbound alert can only open a room and post a notice; `api.spawnWarRoom`
  "constructs no end-to-end op and cannot approve, seal, or execute."
- The **hash-chained record** rejects re-delivered entries by `seq`/`prev_hash`
  (`record.Chain.AppendRemote`), live and offline.
- The **E2E message layer** binds `room_id‖from_id‖epoch‖nonce‖ciphertext`
  (`protocol/signing.go`).

**The one genuine gap:** the HTTP **alert ingest socket** (`POST /api/v1/alert`). A
replayed, validly-**HMAC-signed** alert re-authenticates (the HMAC over identical bytes
verifies forever; the `ts` is never checked), re-matches its route, and **re-spawns an
ephemeral war room / re-fires the join notice / re-calls the optional `reply_url`** —
bounded by the per-source rate/spawn token buckets (`alert.Guards`) but **not
prevented**. The harm is operational (spurious break-glass rooms, notice/`reply_url`
fan-out, alert fatigue), not a forged approval, tampered record, or content leak.

This feature closes exactly that gap, for exactly the sources where it is meaningful
(HMAC sources — see §5.1), and nothing more.

---

## 3. Precise current flow (what we are inserting into)

`server/internal/api/api.go`, `func (a *API) alert` (the handler), today runs in this
order:

```
1. read body (MaxBytesReader 64 KiB)                              → 413 on overflow
2. alert.Parse(raw)                                              → 400 malformed
3. a.cfg.Source(al.Source)                                       → 401 unknown source
4. a.guards.AllowRequest(src)        (rate_per_minute bucket)    → 429 rate limited
5. headerToken := X-Netherchat-Token / ?token
6. alert.Authenticate(src, al, headerToken)  (token AND/OR HMAC) → 401 auth failed
   ── INSERT FRESHNESS GATE HERE ──
7. route.Match(a.cfg.Routes, al.ToMatchMap())                    → 200 accepted/no-spawn
8. a.guards.AllowSpawn(src)          (spawn_per_hour bucket)     → 429 spawn cap
9. a.spawnWarRoom(...)                                           → 200 spawned
```

`alert.Authenticate` (`server/internal/alert/alert.go:129`) verifies the HMAC over
`protocol.AlertSigningBytes(... a.TS)` for HMAC sources and a constant-time token
compare for token sources; **every declared credential must pass**.

`alert.Guards` (`server/internal/alert/alert.go:167`) is the existing per-source,
`sync.Mutex`-guarded, lazily-built limiter holder (`AllowRequest`, `AllowSpawn`). It is
constructed arg-less by `alert.NewGuards()` at `server/server.go:71` and in two tests
(`server/internal/api/alert_test.go:39`, `server/internal/alert/alert_test.go:137`).

---

## 4. Design recommendations (#1–#4) — tradeoffs and a clear recommendation

### 4.1 Scope — which ingest socket(s) (#1)

There are two inbound write surfaces:

| Socket | Auth | Signed `ts`? | Replay nature |
|---|---|---|---|
| `POST /api/v1/alert` | token and/or **HMAC** | **yes, for HMAC sources** | true signature-replay |
| `POST /webhook/{room}` | per-room **bearer token only** | **no** (no HMAC, freeform JSON) | token-possession |

A timestamp window only adds resistance where the timestamp is **signed**. That is true
**only** for HMAC sources on `/api/v1/alert`:

- For an **HMAC alert source**, `ts` is in the verified preimage — the attacker can
  neither change it nor mint a fresh one. The window bites. ✅
- For a **token-only alert source**, the alert may carry a `ts`, but nothing signs it —
  anyone holding the token can set `ts = now`. A window over an attacker-controlled
  field is theater. ❌ (This source's exposure is token-possession, already bounded by
  the rate/spawn caps; freshness adds nothing.)
- For **`/webhook/{room}`**, there is no HMAC and no signed timestamp at all. Its
  payload is arbitrary JSON; an attacker (or replayer) sets any field freely. A
  freshness window cannot help it. Moreover its exposure is a *different, larger*
  problem: the handler calls **neither** `AllowRequest` **nor** `AllowSpawn`, so it is
  an **unguarded** token endpoint — a held token replays **unbounded**.

**Recommendation: alert-socket-only, and within it, HMAC-sources-only** (enforcement is
inert for token-only sources — see §5.1). The timestamp-window mechanism is the right
tool for, and only for, the signed-`ts` surface.

`/webhook/{room}` is **out of scope and flagged**: its honest fix is the *missing*
rate/spawn guard (reuse the same `alert.Guards` the alert path already has), and — only
if signature-replay resistance is ever wanted there — adding HMAC + a signed `ts`
first, which is a wire-format change explicitly excluded here. Do **not** fold a
freshness window onto `/webhook/{room}`; it would imply a protection that does not
exist. Recommend tracking the webhook rate/spawn guard as a **separate small commit**
(see Open Questions).

### 4.2 `ts` policy / strictness — the backward-compat crux (#2)

Today `ts` is optional and existing adapters legitimately send `0` (the in-repo
adapters set `ts` only when the source event carries one). The spectrum:

- **(a) Strict global** — require `ts` on HMAC sources, reject `ts == 0`. Cleanest
  story; **breaks** every existing adapter that sends `0`, including third-party ones in
  the wild. High migration cost, no grace.
- **(b) Opt-in per-source flag** — off by default. Back-compat, but a source the
  operator *believes* is protected may be silently unprotected — the "loud about what's
  off" footgun (echo of the G8 concern).
- **(c) Enforce-if-present** — validate the window **iff `ts != 0`**; a `ts == 0` alert
  passes but is **logged loudly** (once per source) as freshness-inactive. Adapters
  that send a real timestamp get protection automatically; legacy `ts == 0` sources keep
  working and are visibly flagged.

Key property that makes (c) sound: because `ts` is inside the HMAC preimage, an attacker
**cannot downgrade** a real-`ts` alert to `ts == 0` (that breaks the signature) and
**cannot forge** `ts = now`. So under (c), a source that signs a real `ts` is *fully*
window-protected and an adversary cannot opt it out; a source that signs `ts == 0` is
unprotected but **says so in the logs**. Protection tracks exactly what the source signs.

**Recommendation: (c) enforce-if-present as the always-on baseline, plus a per-source
`require_fresh` flag that escalates to strict (reject `ts == 0` and out-of-window).**

- Baseline (c) cannot harm legitimate traffic: it only rejects an alert whose *signed*
  `ts` is genuinely outside the window. Nothing needs to opt in to get protection once
  its adapter sends real timestamps.
- `require_fresh = true` is the security-conscious operator's "mandate freshness on this
  source" switch, available once they have confirmed their adapter emits `ts`.
- **Loud about what's off:** the first time an HMAC source presents `ts == 0` under the
  baseline, log a `WARN` ("freshness inactive: source sends no timestamp"). De-duped to
  once per source per process via the warned-set.
- **Migration story:** zero forced migration. Existing adapters keep working
  (`ts == 0` → pass + warn; real `ts` → protected). The connector SDK already supports
  sending `ts`; the documented path is "send a real `ts`, then optionally set
  `require_fresh`." No coordinated cross-contract change, no adapter rebuild required.
- **Fail-closed config check:** `require_fresh = true` on a source **without**
  `hmac_secret` is a configuration error (its `ts` is unsigned, so the mandate is
  meaningless). Reject it at config load/validate rather than enforce theater (see Open
  Questions for warn-vs-error).

This reads most honestly to a security reviewer: protection is automatic where the
signature supports it, impossible to silently downgrade, loud where it is inactive, and
escalatable to a hard mandate per source.

### 4.3 Window parameters & clock skew (#3)

Validate the signed `ts` (unix seconds) against the server clock:

- **Past tolerance (acceptance window):** how old `ts` may be. **Default `5m` (300 s)**,
  deliberately anchored to the existing ~300 s artifact-proposal expiry so the product
  has a *single* freshness horizon that is easy to reason about. Wide enough to absorb
  normal webhook delivery, retry, and queue latency; tight enough that the replay window
  is small.
- **Future skew tolerance:** how far `ts` may lead `now` (clock drift). **Default `60s`**.
  Asymmetric on purpose: legitimate *past* latency (retries/queues) routinely exceeds
  legitimate *future* drift, and a far-future `ts` is more suspicious. 60 s is
  NTP-tolerant and matches the per-minute rate granularity.
- **Configuration:** a new global `[ingest.freshness]` table provides the defaults;
  per-source overrides follow the existing `0 = use default` precedent
  (`rate_per_minute`/`spawn_per_hour`). Use the existing `config.Duration` TOML type
  (`"5m"`, `"60s"`).

```toml
[ingest.freshness]          # global defaults (new, optional)
window      = "5m"          # max age of a signed ts (past tolerance)
future_skew = "60s"         # max lead of a signed ts over server time

[[source]]
name        = "scanner"
hmac_secret = "..."
require_fresh         = true    # escalate to strict (reject ts==0 / stale); needs hmac_secret
freshness_window      = "10m"   # optional per-source override (unset/0 → global)
freshness_future_skew = "30s"   # optional per-source override (unset/0 → global)
```

`config.normalize()` fills `[ingest.freshness]` with `5m`/`60s` when unset or
non-positive (mirroring how the limits defaults are repaired), so the resolved global is
always sane; the per-source override is applied at use-site in `AllowFresh`. Operators
with slow batch sources widen `freshness_window` per source. (Defaults are justified,
not arbitrary: 300 s ties to the existing proposal horizon; 60 s is standard NTP slack.)

### 4.4 Optional per-source last-seen high-water-mark (#4)

A pure window accepts a replay that arrives *within* the window. A per-source
high-water-mark (reject `ts ≤ last_seen_ts`) would additionally catch in-window replays
with O(1) ephemeral state.

Tradeoff:

- **For:** closes the in-window replay (an attacker capturing and re-sending the *same*
  alert within `window` seconds).
- **Against:** it assumes per-source **strictly increasing** timestamps. Real sources
  emit multiple alerts in the same second, from parallel workers, or out of order via
  retries — all of which carry equal or decreasing `ts`. A monotonic reject would **drop
  legitimate distinct alerts**, i.e. *miss a real incident* — a strictly worse failure
  mode than the bounded duplicate spawn it prevents. The residual in-window replay is
  already bounded by the existing `spawn_per_hour` cap.

**Recommendation: do NOT include the high-water-mark in v1. Pure window only.** It keeps
freshness essentially stateless (strongest fit with zero-persistence), avoids
false-negatives on real alerts, and is proportionate to a bounded operational-noise
risk. Note it as a *possible future escalation* only if (a) a stronger guarantee is
needed **and** (b) sources are known to emit strictly-increasing per-source `ts`. The
correct tool for exact-once is a signed nonce — explicitly out of scope here.

---

## 5. Build-ready spec

### 5.1 The freshness gate (the verification change)

Add a method to `alert.Guards` (alongside `AllowRequest`/`AllowSpawn`), keeping the
per-source, concurrency-safe model:

```go
// AllowFresh reports whether an alert's already-HMAC-verified timestamp ts (unix
// seconds) is within the source's acceptance window. It is meaningful ONLY for HMAC
// sources: a token-only source's ts is unsigned (attacker-controllable), so freshness
// is inert there and AllowFresh returns (true, "").
//
// Policy (enforce-if-present + optional strict): for an HMAC source,
//   - ts == 0  → inactive: (true, "") under the baseline (logged once as a warning by
//                the caller via the returned warn flag); REJECTED if src.RequireFresh.
//   - ts older than the window           → (false, "stale timestamp").
//   - ts further ahead than future_skew  → (false, "future timestamp").
//   - otherwise                          → (true, "").
//
// def is the resolved global default ([ingest.freshness]); per-source overrides
// (FreshnessWindow / FreshnessFutureSkew, 0 = use def) win. The window/skew arithmetic
// is pure (no per-source mutable state); the only state touched is the warned-set used
// to log a ts==0 source once. A nil receiver allows everything.
func (g *Guards) AllowFresh(src config.SourceConfig, ts int64, def config.FreshnessConfig) (ok bool, reason string)
```

`Guards` gains two zero-value-safe fields (no `NewGuards()` signature change, so
`server/server.go:71` and both test call sites are untouched):

```go
type Guards struct {
    mu     sync.Mutex
    rate   map[string]*rate.Limiter
    spawn  map[string]*rate.Limiter
    warned map[string]bool        // per-source, ts==0 "freshness inactive" logged once
    now    func() time.Time       // nil ⇒ time.Now (injectable in alert-package tests)
}
```

`now()` defaults to `time.Now` via a small helper (`g.clock()`), settable directly in
same-package tests for deterministic boundaries. `warned` is lazily initialized under
`mu`.

Arithmetic (seconds): `n := g.clock()().Unix()`; `age := n - ts`. Stale if
`age > window`; future if `-age > futureSkew`. Enforcement is gated on
`src.HMACSecret != ""` (token-only ⇒ inert).

### 5.2 Handler insertion point (`server/internal/api/api.go`)

Immediately **after** `alert.Authenticate` returns nil (so we only trust a `ts` the
HMAC has covered) and **before** `route.Match` (so *every* replay is rejected and
visible, not only ones that happen to match a route):

```go
if err := alert.Authenticate(src, al, headerToken); err != nil {
    a.log.Warn("alert rejected: auth failed", "source", al.Source, "err", err.Error())
    http.Error(w, "unknown or unauthenticated source", http.StatusUnauthorized)
    return
}

// Freshness gate (NC-?): the ts is inside the HMAC preimage that just verified, so a
// replayed alert carries an old, signed ts and is rejected here — before it can spawn.
if ok, reason := a.guards.AllowFresh(src, al.TS, a.cfg.Ingest.Freshness); !ok {
    a.log.Warn("alert rejected: "+reason, "source", al.Source, "ts", al.TS, "now", time.Now().Unix())
    http.Error(w, "alert rejected: "+reason, http.StatusBadRequest)
    return
}

idx, rule, matched := route.Match(a.cfg.Routes, al.ToMatchMap())
```

Chosen placement = after-auth/before-match (max observability; harm-reduction
identical since nothing spawns either way). *Alternative considered:* after `route.Match`
/ before `AllowSpawn` (only would-spawn replays are gated, non-matching replays stay
invisible) — rejected for poorer observability.

### 5.3 Config surface (`server/config/config.go`)

Additive only:

- New `IngestConfig` / `FreshnessConfig`:
  ```go
  type IngestConfig struct { Freshness FreshnessConfig `toml:"freshness"` }
  type FreshnessConfig struct {
      Window     Duration `toml:"window"`      // past tolerance (default 5m)
      FutureSkew Duration `toml:"future_skew"` // future tolerance (default 60s)
  }
  ```
  add `Ingest IngestConfig `toml:"ingest"`` to `Config`.
- New `SourceConfig` fields (overrides; `0`/unset ⇒ global default):
  ```go
  RequireFresh        bool     `toml:"require_fresh"`
  FreshnessWindow     Duration `toml:"freshness_window"`
  FreshnessFutureSkew Duration `toml:"freshness_future_skew"`
  ```
- `normalize()` fills `Ingest.Freshness.Window`/`FutureSkew` with the built-in defaults
  (`defaultFreshnessWindow = 5*time.Minute`, `defaultFreshnessFutureSkew = 60*time.Second`)
  when non-positive — mirroring the existing limits-repair precedent and clamping to a
  sane ceiling.
- **Fail-closed validation:** `require_fresh = true` with empty `hmac_secret` is a
  config error surfaced by `Parse`/`Load` (and therefore by
  `POST /api/v1/config/validate`), so a meaningless mandate fails the operator's plan
  rather than running as theater. Follows the existing "no default-open ingress" /
  explicit-state precedent.

### 5.4 State summary

With the recommended pure-window design, freshness adds **no seen-store** and **no
per-source mutable counters** — only the cosmetic `warned` log-de-dup set. It is
in-memory, dies with the process, and never persists. (If a high-water-mark were ever
added per §4.4, a `lastSeen map[string]int64` would slot into the same `Guards`
struct under the same `mu`.)

---

## 6. Error & observability behavior

- A stale/replayed alert is **rejected with HTTP 400** and a **distinct, greppable log
  reason** — `alert rejected: stale timestamp` or `alert rejected: future timestamp` —
  separate from `alert rejected: rate limited` (429) and `auth failed` (401). The log
  carries `source`, `ts`, and `now` (metadata only — **never** `summary`), so a real
  replay is **visible**, not silently dropped.
- A `ts == 0` HMAC source under the baseline logs **once** per source:
  `freshness inactive: source sends no timestamp` (`WARN`). This is the "loud about
  what's off" guarantee — no silent unprotected gaps.
- The response body to an (authenticated) caller may name the reason
  (`alert rejected: stale timestamp`); since the gate is post-auth, this is not an info
  leak.
- Status-code choice (400) is a recommendation; 422 is a defensible alternative (see
  Open Questions). The *distinct reason string* matters more than the code.

---

## 7. Invariant register (what this must NOT disturb — and why it doesn't)

| Invariant | Status | Why |
|---|---|---|
| Façade surface-guard (`sealedrecord/surface_test.go`) | **untouched** | All changes live in `server/internal/alert`, `server/internal/api`, `server/config`. Nothing under `tui/record\|report\|attest`; no new exported symbol to re-export. |
| Byte-identical record back-compat | **untouched** | No record/seal/approval/entry bytes change. |
| Golden signing vectors (`protocol/*_signing_test.go`) | **untouched** | `protocol` is not modified. `AlertSigningBytes` is only **read from**, not changed — no field added, layout unchanged. |
| Domain-tag separation | **untouched** | No new preimage, no new tag. |
| Wire format / contract tests | **untouched** | `connector.Alert`, `alert.AlertV1`, `AllowedFields` unchanged → `connector` round-trip test (`TestSendHMAC`) and adapter boundary tests stay green; strict-JSON decoders see no new field. |
| Blind-relay / import boundary (`TestServerBinaryDoesNotLinkClientCrypto`) | **held** | Freshness code uses only `time` + `config` (HMAC already via stdlib `crypto/hmac`+`sha256` in `alert.go`). It must **not** import `tui/internal/crypto`. |
| `doctor --paranoid` ciphertext-only proof | **unaffected** | Freshness is HTTP-ingest-side; it never enters WS relay frames and carries no content. `ts` is pre-existing metadata. |
| Zero-persistence identity | **held** | No durable store; pure-window is effectively stateless; restart-replay slip is accepted by design. |

---

## 8. Test plan

New tests in `server/internal/alert/` (window unit tests, `now` injected) and
`server/internal/api/` (handler-level, real clock with extreme `ts` so no injection
needed):

1. **Stale rejection** — HMAC source, `ts = now − window − 1` → rejected, reason
   `stale timestamp`.
2. **In-window acceptance** — `ts = now − window/2` → accepted (spawns if a route
   matches).
3. **Future within skew** — `ts = now + skew/2` → accepted; `ts = now + skew + 1` →
   rejected, reason `future timestamp`.
4. **`ts` policy (#2):**
   - baseline (no `require_fresh`): `ts == 0` on HMAC source → accepted **and** a single
     `freshness inactive` warning emitted (assert once, not per request).
   - `require_fresh = true`: `ts == 0` → rejected.
5. **Token-only inertness (#1/§5.1):** token-only source with an out-of-window `ts` →
   **not** rejected (freshness inert without `hmac_secret`).
6. **Config fail-closed:** `require_fresh = true` + empty `hmac_secret` → `Parse`/`Load`
   error (and `POST /api/v1/config/validate` returns `valid:false`).
7. **Per-source isolation:** source A out-of-window rejected while source B in-window
   accepted in the same `Guards`.
8. **Per-source override:** source with `freshness_window = 10m` accepts a 6-minute-old
   `ts` the 5-minute global default would reject.
9. **End-to-end happy path:** a legitimately fresh, route-matching alert still spawns a
   war room (api handler test) and returns `spawned:true`.
10. **Distinct rejection codes/reasons:** stale (400, `stale timestamp`) is
    distinguishable in logs/status from rate-limit (429) and auth (401).
11. **Green-stays regression (must remain unchanged & passing):**
    `protocol` signing-vector tests; `connector` round-trip (`TestSendHMAC`); adapter
    boundary tests; existing `alert` auth/rate/spawn tests (freshness is additive and
    defaults are non-breaking).

(High-water-mark tests are **N/A** in v1 — not included. If added later: "in-window
duplicate `ts` rejected" and "legitimate out-of-order alert not dropped".)

---

## 9. What this is NOT doing (anti-bloat)

- **No new signed field, no nonce.** `ts` already exists in the signed bytes.
- **No wire-format change.** `connector.Alert` / `alert.AlertV1` / `AllowedFields`
  untouched; no adapter rebuild, no cross-contract coordination.
- **No durable / persistent seen-store.** In-memory only; restart-replay slip accepted.
- **No high-water-mark in v1.** Pure window (see §4.4).
- **No approval / record / seal / E2E / façade / golden-vector change.** Already
  replay-resistant; out of scope.
- **No `/webhook/{room}` work.** Distinct token-possession problem a window can't fix;
  its rate/spawn-guard fix is flagged separately (Open Questions).
- **No exact-once delivery guarantee.** That is nonce territory, explicitly excluded.
- **No clock-sync infrastructure.** Relies on operator NTP; the window absorbs skew.

---

## 10. Git note

- HEAD = `867a58c` (`v1.10.0-3-g867a58c`); branch `main` **in sync** with `origin/main`;
  working tree clean.
- Correction to the task framing: HEAD is **3 commits past v1.10.0** (the Pass C docs
  commit `5447f24` plus the two genericization commits `55e5337`, `867a58c` — all
  pushed), not 1.
- This feature is its own commit (suggested subject, generic:
  `feat(ingest): timestamp acceptance window for signed alerts`). Per the repo's stated
  workflow, develop on a topic branch and open a PR against `main`. **No tag is implied
  by this plan** — a release/tag decision comes after the build lands and CI is green.

---

## 11. Open questions for you

1. **Scope confirm:** alert-socket / HMAC-sources only (recommended), with the
   `/webhook/{room}` rate/spawn-guard tracked as a separate small commit? Or fold that
   webhook guard into this change as an adjacent fix?
2. **`ts` policy confirm:** enforce-if-present baseline + per-source `require_fresh`
   (recommended)? Or strict-global from day one (accepting adapter breakage)?
3. **Defaults confirm:** `window = 5m`, `future_skew = 60s`, global with per-source
   override? Any known source with legitimate >5-minute delivery latency that should
   widen the default?
4. **High-water-mark confirm:** excluded in v1 (recommended pure-window)?
5. **Config placement:** dedicated `[ingest.freshness]` table (recommended) vs. folding
   into `[limits]`?
6. **`require_fresh` without `hmac_secret`:** hard config **error** (recommended,
   fail-closed) vs. load-time **warning** + inert?
7. **Reject status:** `400` (recommended) vs. `422`/`403` for a stale/replayed alert?
