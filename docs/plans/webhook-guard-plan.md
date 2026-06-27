# Webhook ingress rate/spawn guard — build-ready plan

Status: **planned** (no code written). Server-ingest-internal feature. Additive,
in-memory, no wire-format change. Sibling of the just-shipped alert-socket freshness
work and modeled on the same config/normalize/override precedents.

This plan designs **rate and spawn guarding for `POST /webhook/{room}`**, the one
inbound write surface that today has **no rate or spawn limiting at all**. Its
authenticated twin, `POST /api/v1/alert`, already has both (`alert.Guards`:
`AllowRequest` + `AllowSpawn`). This closes that asymmetry as defense-in-depth, plus
folds in one adjacent security fix (constant-time token compare). It deliberately
does **not** touch the alert path, the wire format, or the sealed-record layer.

---

## 1. Scope & the two-vector exposure

### 1.1 What the gap actually is (honest framing)

The exposure is **authenticated-token-holder abuse**, not open/unauthenticated abuse.
An unauthenticated attacker is stopped at the token check
(`server/internal/api/api.go:97-100`, HTTP 401). The realistic threat is a
**leaked, shared, committed, or buggy** webhook token producing a storm — exactly
the class the alert path's per-source caps exist to contain as a second layer
*over* authentication. So this is **moderate severity** (operational
resource/amplification, no confidentiality or integrity impact; the blind-relay and
"second law" properties are untouched) — and it is a **symmetry/defense-in-depth**
fix, not an emergency.

### 1.2 Two distinct unbounded vectors (both must be covered)

The webhook handler (`api.go:86-143`) branches on `route.Match` (`api.go:115`):

- **Route-matching path** → `fireRoute` → `spawnWarRoom` (`api.go:173-209`): each
  matching POST spawns an ephemeral room, mints one invite token per `rule.Invite`
  entry (`api.go:195`), broadcasts a `route_fired` event, and fires the optional
  `reply_url` as a **new goroutine** with a 5 s timeout (`api.go:206`, `postReply`
  `api.go:315-331`). Unbounded → unbounded spawns, invite-token minting,
  goroutine creation, and amplification toward the operator's own `reply_url`
  target.
- **Route-non-matching path** → `a.hub.Broadcast(room, "", env)` (`api.go:140`):
  a plaintext, server-originated message delivered to every room member.
  `hub.Broadcast` (`server/internal/hub/hub.go:247`) has **no rate limit of any
  kind**, and the per-connection WS limiter (`server/internal/ws/server.go:201,216`)
  meters only *inbound client* `OpMessage` frames — it never touches
  server-originated broadcasts. Unbounded → a plaintext flood into the room.

**Consequence for the design:** a spawn-only guard is insufficient. `AllowSpawn`
never runs on the non-matching path, so the broadcast flood would stay wide open.
The **rate** guard is the *only* cover for the broadcast-flood vector; the **spawn**
guard bounds the room-spawn/invite/`reply_url` vector. They are not redundant — both
ship.

---

## 2. Settled decisions (do not re-litigate)

1. **Keying: per-token, hashed.** Meter the per-credential limiter on the webhook
   **token**, not per-room and not per-IP. Key on `sha256(token)` (hex), **never**
   the raw token — the limiter map must not hold, log, or be able to leak the
   secret. Per-token is the correct authority unit and keeps the multi-token-per-room
   future open (each integration gets its own bucket; a noisy source cannot throttle
   a sibling sharing the room).
2. **Placement: two-tier.** A coarse **pre-auth** ceiling that bounds raw rejected
   churn and is *structurally incapable* of locking out a legitimate token-holder,
   plus the precise **per-token post-auth** guard that meters authenticated abuse.
3. **Both rate AND spawn guards** (mirror `AllowRequest` + `AllowSpawn`).
4. **Reuse `alert.Guards` by generalize + namespace**, not drop-in — avoiding the
   `SourceConfig` type mismatch and the shared-map key collision. `NewGuards()`'s
   signature stays unchanged (additive, zero-value-safe).
5. **429 on limit-exceeded**, with distinct, greppable log reasons separate from the
   existing 401/404 and from the alert path's reasons.
6. **Add api-package unit tests** — the webhook has zero api-unit coverage today.
7. **(this plan recommends)** Defaults and config surface — §5.6 / §5.7.
8. **(adjacent fix, folded in)** Upgrade the webhook token compare to
   `subtle.ConstantTimeCompare` — §5.8.

---

## 3. Precise current flow (what we insert into)

`server/internal/api/api.go`, `func (a *API) webhook` (`api.go:86-143`), today:

```
1. room := r.PathValue("room")                                    (api.go:87)
2. policy := a.cfg.Room(room); if !policy.Webhook → 404           (api.go:88-92)
3. token := X-Netherchat-Token header, else ?token query          (api.go:93-96)
4. if policy.WebhookToken == "" || token != policy.WebhookToken → 401   (api.go:97-100)   ← non-constant-time
5. read body (MaxBytesReader 64 KiB) → 413                        (api.go:102-106)
6. json.Unmarshal into map[string]any → 400                       (api.go:107-111)
7. if route.Match(...) → fireRoute(spawn) and RETURN              (api.go:115-118)
8. else: require "text" → hub.Broadcast plaintext → 200           (api.go:120-142)
```

No `AllowRequest`/`AllowSpawn` anywhere in this function or in `fireRoute`/
`spawnWarRoom`. Confirmed unguarded.

For reference, the alert path's guard points are `AllowRequest` at `api.go:274`
(after source lookup, *before* auth) and `AllowSpawn` at `api.go:297` (after
`route.Match`, before spawn). `alert.Guards` lives at
`server/internal/alert/alert.go:171-222`; source caps default to
`defaultRatePerMinute = 60` / `defaultSpawnPerHour = 20` (`alert.go:38-41`).

---

## 4. The two-tier design and its stress test (the centerpiece)

Two threats with asymmetric cost demand two limiters at two points.

### 4.1 Tier 1 — pre-auth global ceiling, consumed **only on rejection**

**Key: a single GLOBAL bucket** (not per-room, not per-token, not per-IP).
**Consumption: only by requests that are being rejected** — a non-webhook room
(404) or a failed/empty token (401). A request that **authenticates successfully
never touches this bucket.**

This is the synthesis of the two candidate pre-auth designs:

- *Global in key* → an attacker cannot target a specific room/token's pre-auth
  bucket to deny it (the amplifier attack the recon flagged requires keying the
  pre-auth limiter on room/token; we deliberately do not).
- *Consumed only on rejection* → legitimate traffic is exempt from the bucket, so
  the global-ness can never collateral-damage a real sender.

A naive "global, consumed on **every** request" limiter would *not* have this
property: under a flood it would drain and 429 legitimate holders too. The
"denies nobody legitimate" claim only holds because consumption is gated to the
rejection branches. This is a **checkable code-path invariant**:

> The pre-auth limiter is consulted **only inside the `!Webhook` and failed-auth
> branches**. The success path never reads it.

**Recommended pre-auth key: GLOBAL, consume-on-rejection** (the above). Rejected
alternatives and why:

| Pre-auth key | Verdict | Reason |
|---|---|---|
| **Global, consume on rejection** | **recommended** | Cannot deny a legit holder (they never enter the bucket); cannot be targeted (one global key); only effect under flood is "attacker gets 429 instead of 401." |
| Per-IP | rejected | Defeated by NAT / proxies / distribution; and produces **unbounded, never-evicted** map keys (`alert.go:210-222` never evicts) — a memory-growth vector the recon flagged as the per-IP failure mode. |
| Per-room / per-token (pre-auth) | rejected | An attacker who knows a valid room name (no token) could spam it, drain that room's pre-auth bucket, and **deny the legitimate holder** — the exact amplifier attack we are avoiding. |
| Global, consume on **every** request | rejected | Under flood it 429s legitimate holders too; breaks availability. |

**Cheap-work note:** because consumption is gated to failure, we run the
constant-time compare (and a `cfg.Room` map lookup) on every request before
shedding. That is intentional and acceptable: the compare is O(token length) with
no allocation, and the genuinely expensive surface — the 64 KiB body read, JSON
unmarshal, route match, spawn, broadcast, `reply_url` goroutine — is **all behind
successful auth**, where Tier 2 meters it. The pre-auth tier exists to bound
*rejected-request churn* (connection/goroutine/log pressure), not to protect a
trivial compare.

### 4.2 Tier 2 — per-token post-auth rate + spawn

After a request authenticates, meter it on **two** limiters keyed by the **hash of
its token** (§5.1):

- **Rate** (per-minute): consumed on **every** authenticated webhook POST — placed
  **before the body read** (we can, because the token identity is known from the
  URL/header *before* the body, unlike the alert path whose source is in the body).
  This single guard covers **both** the broadcast-flood and the matching path, and
  additionally shields the 64 KiB read + unmarshal under authenticated flood.
- **Spawn** (per-hour): consumed only when `route.Match` returns a match, **before**
  `fireRoute`. Bounds the spawn/invite/`reply_url` vector specifically.

An attacker without the token can never reach or drain a specific token's Tier-2
buckets. A holder of a leaked token *is* that credential from the system's view and
is bounded by that token's caps — the intended containment.

### 4.3 Stress test — is it secure AND available simultaneously?

Adversary walk-through (H = legitimate holder of token T on room R):

1. **Attacker floods bad tokens at R.** Each consumes the **global pre-auth** bucket
   → attacker gets 401 until the ceiling, then 429. H's correct-token requests
   authenticate, **never touch pre-auth**, and flow to H's own Tier-2 bucket
   (keyed `sha256(T)`), which the attacker cannot drain (no valid token). → **H
   unaffected.** ✓
2. **Attacker floods bad tokens across many rooms.** Same: one global bucket
   absorbs/sheds; no per-room/token bucket is targeted; no legit holder is rejected.
   ✓
3. **Attacker holds H's leaked token** (the threat this feature addresses). They
   share H's Tier-2 buckets and are bounded by R's configured rate/spawn caps —
   containment of a compromised credential, not denial of a distinct legitimate
   user. ✓
4. **Sibling isolation (multi-token-per-room future).** Each token hashes to its
   own bucket, so one integration's flood cannot throttle a sibling sharing the
   room. ✓

**Conclusion:** No tier can deny a *distinct legitimate token-holder*: Tier 1 is
global but exempts success; Tier 2 is per-token but only the token's own holder can
drain it. Meanwhile both vectors are bounded (rate covers the broadcast flood, spawn
covers amplification, pre-auth covers unauth churn). **Secure and available
simultaneously.**

---

## 5. Build-ready spec

### 5.1 Keying — per-token, hashed, namespaced (the secret never leaks)

- The bucket key for an authenticated request is
  `"wh-rate:" + hex(sha256(token))` (rate) and `"wh-spawn:" + hex(sha256(token))`
  (spawn). The pre-auth bucket uses the fixed key `"wh-unauth"`.
- The **raw token is never** used as a map key, never logged, and never placed in an
  error string or HTTP response body. It enters the guard only as a **transient
  function argument** that is immediately hashed; nothing retains it.
- Hashing helper (in package `alert`, alongside the guard):
  `func tokenKey(token string) string { sum := sha256.Sum256([]byte(token)); return hex.EncodeToString(sum[:]) }`.
- **Namespacing prevents cross-path collision.** Existing alert source limiters are
  keyed by **bare** `src.Name` (operator-chosen short identifiers). Webhook keys are
  **prefixed** (`wh-rate:` / `wh-spawn:` / `wh-unauth`) and the per-token ones carry
  a 64-hex-char digest suffix. The two key spaces are therefore disjoint — a source
  named `"alerts"` and a room/token can never share a bucket (the collision the
  recon flagged for a naive drop-in). No change to the alert path's existing keys.

### 5.2 Guard structure — extend `alert.Guards` (recommended)

Reuse the existing in-memory, lazy-limiter ingress-hardening holder rather than
adding a new type. It is already the single guard on the `API`
(`api.guards *alert.Guards`), already constructed once at `server/server.go:71`,
already uses the exact `rate`/`spawn` lazy-`limiter()` pattern, and already lives
outside the crypto boundary. New additive methods (all nil-receiver-safe, matching
`AllowRequest`/`AllowSpawn`):

```go
// Global pre-auth ceiling (Tier 1). perMin is the configured unauth rate.
func (g *Guards) AllowWebhookUnauth(perMin int) bool

// Per-token authenticated rate (Tier 2). token is hashed internally; perMin is the
// effective per-room rate (override or global default), resolved by the caller.
func (g *Guards) AllowWebhookRequest(token string, perMin int) bool

// Per-token spawn cap (Tier 2). token hashed internally; perHour effective.
func (g *Guards) AllowWebhookSpawn(token string, perHour int) bool
```

Each routes through the existing private `limiter(into, key, perSec, burst)`:
`AllowWebhookUnauth` → `g.rate["wh-unauth"]`; `AllowWebhookRequest` →
`g.rate["wh-rate:"+tokenKey(token)]`; `AllowWebhookSpawn` →
`g.spawn["wh-spawn:"+tokenKey(token)]`. **No struct field is required** (the existing
`rate`/`spawn` maps suffice via namespaced keys), so **`NewGuards()`'s signature is
unchanged** and its three call sites (`server.go:71` and two tests) are untouched.
Package `alert` gains a `crypto/sha256` + `encoding/hex` import (stdlib — boundary
safe; §6).

*Alternative considered:* a dedicated `WebhookGuards` type with its own maps for hard
isolation. Rejected as heavier (new API field + new construction site in `server.go`
+ more surface) and unnecessary, since namespacing already guarantees disjoint keys.
Noted for the reviewer.

### 5.3 The guarded handler flow (`server/internal/api/api.go`)

```
1. room := r.PathValue("room"); policy := a.cfg.Room(room)
2. if !policy.Webhook:
       if !a.guards.AllowWebhookUnauth(unauthRate) → 429 "webhook flood (pre-auth)"
       else → 404 (unchanged message)
       return
3. token := header X-Netherchat-Token, else ?token
4. authed := policy.WebhookToken != "" &&
             subtle.ConstantTimeCompare([]byte(token), []byte(policy.WebhookToken)) == 1
5. if !authed:
       if !a.guards.AllowWebhookUnauth(unauthRate) → 429 "webhook flood (pre-auth)"
       else → 401 (unchanged message)
       return
   ── authenticated past here; the pre-auth bucket is never read again ──
6. if !a.guards.AllowWebhookRequest(token, roomRate) → 429 "webhook rate limit (per-token)"
       return                              # BEFORE the body read — covers broadcast flood + shields the read
7. read body (64 KiB) → 413; json.Unmarshal → 400        # unchanged
8. if idx, rule, ok := route.Match(...); ok:
       if !a.guards.AllowWebhookSpawn(token, roomSpawn) → 429 "webhook spawn cap (per-token)"
           return
       a.fireRoute(...); return                            # unchanged
9. else: plaintext delivery via hub.Broadcast              # unchanged
```

`unauthRate`, `roomRate`, `roomSpawn` are resolved in §5.6. The success-path bodies
(spawn / broadcast / `reply_url`) are **unchanged** — this pass only inserts guards
and the constant-time compare.

### 5.4 Error & observability behavior

- Every limit rejection is **HTTP 429** with a **distinct, greppable log reason**,
  separate from `404`/`401` and from the alert path's `alert rejected: rate limited`:
  - `webhook rejected: flood (pre-auth)` (Tier 1)
  - `webhook rejected: rate limit (per-token)` (Tier 2 rate)
  - `webhook rejected: spawn cap (per-token)` (Tier 2 spawn)
- Logs carry the **room name** (non-secret, already in the URL) and the reason —
  **never** the token or its hash. The room is sufficient operator identity today
  (tokens are 1:1 with rooms); in the multi-token future a non-secret token *label*
  (not the secret) would be the right added field. Noted, not built.
- The 429 **response body** is generic (e.g. `webhook rate limit exceeded`) — no
  token, no hash, no reason that aids enumeration beyond what auth already reveals.

### 5.5 Constant-time token compare (adjacent fix)

Replace `token != policy.WebhookToken` (`api.go:97`) with
`subtle.ConstantTimeCompare([]byte(token), []byte(policy.WebhookToken)) != 1`,
keeping the `policy.WebhookToken == ""` "no token configured rejects all" guard
(secure by default). This matches the alert path, which already uses
`subtle.ConstantTimeCompare` (`alert.go:139`). `crypto/subtle` is stdlib and is
**not** `tui/internal/crypto`, so the blind-relay boundary
(`TestServerBinaryDoesNotLinkClientCrypto`) is unaffected (§6). (As in the alert
path, a length mismatch short-circuits to 0; leaking only token *length* is the
accepted, pre-existing posture.)

### 5.6 Config surface

Follow the just-shipped `[ingest.freshness]` precedent: a global table under
`[ingest]` plus per-room overrides with `0 = use default`.

```toml
[ingest.webhook]                  # global defaults (new, optional)
rate_per_minute        = 120      # per-token authenticated rate cap
spawn_per_hour         = 60       # per-token war-room spawn cap
unauth_rate_per_minute = 600      # GLOBAL pre-auth ceiling (rejected requests only)

[rooms.alerts]
webhook            = true
webhook_token      = "..."
webhook_rate_per_minute = 240     # optional per-room override (0/unset → global)
webhook_spawn_per_hour  = 120     # optional per-room override (0/unset → global)
```

Types (additive; mirrors `FreshnessConfig`):

```go
type IngestConfig struct {
    Freshness FreshnessConfig `toml:"freshness"`
    Webhook   WebhookConfig   `toml:"webhook"`   // new
}
type WebhookConfig struct {
    RatePerMinute       int `toml:"rate_per_minute"`        // per-token rate (default 120)
    SpawnPerHour        int `toml:"spawn_per_hour"`         // per-token spawn (default 60)
    UnauthRatePerMinute int `toml:"unauth_rate_per_minute"` // global pre-auth ceiling (default 600)
}
```

New `RoomConfig` fields (overrides; `int`, `0`/unset ⇒ global default):

```go
WebhookRatePerMinute int `toml:"webhook_rate_per_minute"`
WebhookSpawnPerHour  int `toml:"webhook_spawn_per_hour"`
```

- Counts are `int` (not `Duration`), matching the alert path's `RatePerMinute` /
  `SpawnPerHour`.
- `Default()` sets the three `[ingest.webhook]` values; `normalize()` repairs any
  non-positive global to the built-in default (mirroring the limits-repair and
  freshness precedent). Built-in constants:
  `DefaultWebhookRatePerMinute = 120`, `DefaultWebhookSpawnPerHour = 60`,
  `DefaultWebhookUnauthRatePerMinute = 600`.
- **Resolution** (use-site, like freshness `resolveDuration`): a small helper returns
  the effective per-room rate/spawn — per-room override if `> 0`, else the
  (normalized) global default, else the built-in. The **pre-auth ceiling is global
  only** — deliberately *not* per-room (a per-room pre-auth ceiling would reintroduce
  the targetable-bucket problem of §4.1). No `validate()` fail-closed rule is needed
  here (unlike freshness's `require_fresh`-needs-`hmac_secret`): every value is a
  cap with a safe default, and there is no "mandate over an unsigned field" footgun.

### 5.7 Defaults — reasoning (the real product risk)

The webhook intake is a **designed fan-in** point (CI, monitoring, deploy bots —
many senders under one token). A too-tight cap throttles legitimate bursts (a deploy
storm, a monitoring fan-out) — **strictly worse** than the bounded operational noise
it prevents, because dropping a real incident alert is the failure mode operators
fear most. So defaults are **more forgiving than the alert path's per-source 60/min +
20/hr**:

| Cap | Default | Reasoning |
|---|---|---|
| Per-token **rate** | **120/min** (2/sec, burst 120) | A fan-in intake under one token legitimately bursts; 2/sec sustained (7200/hr) is generous for an intake while a real flood is thousands/sec. Burst 120 absorbs a momentary deploy-storm spike. |
| Per-token **spawn** | **60/hr** (1/min avg, burst 60) | Spawns are heavyweight (room + invites + `reply_url` + member churn). 3× the alert path's 20/hr because a fan-in intake may open several incident rooms during a major event, yet 1/min average still bounds amplification. |
| Global **pre-auth** ceiling | **600/min** (10/sec, burst 600) | Meters only rejected requests; legitimate traffic never touches it. 10/sec of bad-token attempts dwarfs any benign misconfiguration (a few stale-token senders during a rollout), while a brute-force flood is shed cheaply past the ceiling. Set high because its **only** failure mode is "attacker gets 429 instead of 401" — there is no legitimate-traffic cost, so we err generous. |

These are a **product decision**, surfaced as defaults and made per-room overridable
so an operator with an unusually busy intake widens `webhook_rate_per_minute` /
`webhook_spawn_per_hour` for that room without touching the global.

**They keep the existing e2e tests green** (§7): each test posts 1–3 requests against
a fresh `NewGuards()` (a new `server.Handler` per test), far under every cap, and the
single bad-token request in the auth tests draws 1 of the 600-burst pre-auth bucket →
still **401, not 429**.

---

## 6. Invariant register (what this must NOT disturb — and why it doesn't)

| Invariant | Status | Why |
|---|---|---|
| Façade surface-guard (`sealedrecord/surface_test.go`) | **untouched** | All changes are in `server/internal/api`, `server/internal/alert`, `server/config`. Nothing under `tui/record\|report\|attest`; no new exported symbol to re-export. |
| Blind-relay / import boundary (`TestServerBinaryDoesNotLinkClientCrypto`, `tui/e2e/e2e_test.go:231`) | **held** | New imports are `golang.org/x/time/rate` (already linked), `crypto/subtle`, `crypto/sha256`, `encoding/hex` — all stdlib, none is `tui/internal/crypto`. Re-run `go list -deps cmd/netherchat-server`; it must still not contain `tui/internal/crypto`. |
| Zero-persistence / ephemeral identity | **held** | Limiters are in-memory `rate.Limiter`s, no durable store. Keys are **config-bounded** (per-token ≈ per config room; one global pre-auth key) — **not per-IP**, so the never-evicting `limiter` map has no unbounded-key growth (the per-IP failure mode is avoided by decision #1). |
| `NewGuards()` signature | **unchanged** | New methods reuse existing `rate`/`spawn` maps via namespaced keys; no constructor arg, no struct field required. `server.go:71` and both test call sites untouched. |
| Alert path (`POST /api/v1/alert`) behavior | **unchanged** | No edit to `AllowRequest`/`AllowSpawn`/`limiter` or its bare source keys; webhook keys are disjointly namespaced. |
| Wire format / contract tests | **untouched** | No HMAC, no signed timestamp, no new JSON field, no change to `connector.Alert`/`alert.AlertV1`/`AllowedFields`/`AlertSigningBytes`. The webhook payload remains free-form `map[string]any`. |
| Existing `tui/e2e/` webhook tests | **stay green** | §7 enumerates each; sane defaults + fresh per-test guards mean no cap is reached and bad-token requests still 401. |
| `doctor --paranoid` ciphertext-only proof | **unaffected** | HTTP-ingest-side; never enters WS relay frames; carries no content. |

---

## 7. Test plan

### 7.1 New api-package unit tests (`server/internal/api/webhook_test.go` — new file)

The webhook has **zero** api-unit coverage today (only `alert_test.go`,
`freshness_test.go`; its contract is pinned solely by `tui/e2e/`). Add focused
handler-level tests (httptest server, real clock, low per-test caps via config so
trips are cheap to provoke):

1. **Happy path passes** — authenticated POST under all caps: a matching payload
   spawns (200 + room + links); a non-matching payload delivers plaintext (200).
2. **Per-token rate trip** — exceed `webhook_rate_per_minute` for one token → 429
   with reason `rate limit (per-token)`; a request just under passes.
3. **Per-token spawn trip** — matching route, exceed `webhook_spawn_per_hour` (set
   spawn cap below rate so spawn trips first) → 429 with reason `spawn cap
   (per-token)`, distinct from the rate reason; nothing spawned/broadcast on trip.
4. **Per-token isolation** — token A (room A) tripped while token B (room B) still
   passes in the same `Guards` — confirms hash keying isolates credentials.
5. **Pre-auth availability (the stress-test property)** — flood **bad-token**
   requests until the pre-auth ceiling: first N get 401, beyond get 429; **and** a
   **valid-token** request interleaved at any point **still passes** — proving a
   saturated pre-auth bucket cannot deny the legitimate holder.
6. **Pre-auth exempts success** — many **successful** authenticated POSTs never
   produce a pre-auth 429 (only Tier 2 governs them); confirms the success path
   never consumes the global bucket.
7. **Constant-time compare behavior preserved** — wrong/empty token still → 401;
   empty `webhook_token` rejects all. (Timing itself is not unit-testable; the
   constant-time property is a code-review guarantee.)
8. **Config resolution** — a room with `webhook_rate_per_minute = N` is metered at
   `N` (override wins); `0`/unset uses the global default; `normalize()` fills the
   global defaults from the built-ins.

### 7.2 Regression — existing tests stay green (assert, do not edit)

- `tui/e2e/features_test.go::TestWebhookDeliversPlaintext` (`:51`) — 200 plaintext;
  wrong token → 401 (1 < 600 pre-auth burst, so not 429).
- `tui/e2e/incident_test.go::TestAutoWarRoomFires` — match → 200 + room + 2 links.
- `tui/e2e/incident_test.go::TestWebhookFallThroughAndAuth` (`:96`) — no-match → 200
  plaintext; non-webhook room → 404; bad token → 401.
- `tui/e2e/incident_test.go::TestRouteFiredInTailStream` — match → `route_fired`.
- `tui/e2e/incident_test.go::TestRouteReplyURLFiresAsync` — match + `reply_url` →
  async POST.
- `server/config` tests (Default/Load/freshness) — additive fields, defaults
  filled by `normalize()`.

Each e2e test posts 1–3 requests against a fresh `server.Handler` (fresh
`NewGuards()`), so no cap is reached and no behavior changes.

---

## 8. What this is NOT doing (anti-bloat)

- **No invite-store janitor.** The recon found `invite.Store`
  (`server/internal/invite/invite.go`) has no background sweep, so orphaned,
  unredeemed invite tokens persist for the process lifetime — the sharpest memory
  vector. The rate/spawn guard **mitigates** it (it bounds the spawn rate that mints
  those tokens) but does **not fix** it. An invite-store TTL janitor is **separate
  future work, explicitly out of scope** here — flagged so it isn't lost.
- **No HMAC / signed timestamp / wire-format change.** The webhook stays
  token-authenticated over free-form JSON. Freshness/replay protection is
  **inapplicable** (nothing signs a timestamp; an attacker sets any field) — the
  webhook's replay nature is token-possession, addressable only by the rate/spawn
  caps here. Adding HMAC would be a wire change, excluded.
- **No alert-path change.** `POST /api/v1/alert` and the existing
  `AllowRequest`/`AllowSpawn`/`limiter` are untouched.
- **No per-IP or per-room metered keying.** Per-token (hashed) only; the pre-auth
  ceiling is global. (Per-IP would be unbounded-key + NAT-defeated; per-room metered
  would let one source throttle a sibling.)
- **No persistence.** In-memory limiters only; restart resets them (consistent with
  zero-persistence; the same accepted tradeoff as the alert guards and freshness).
- **No sealed-record / façade / approval / E2E change.** Server-ingest-internal
  only.

---

## 9. Open questions for you

1. **Defaults confirm:** per-token **120/min** rate + **60/hr** spawn, global
   pre-auth **600/min** — acceptable for the fan-in assumption, or do you have an
   intake whose legitimate burst is higher (widen the global, or rely on per-room
   override)?
2. **Pre-auth consumption scope:** consume the global ceiling on **both** the
   non-webhook-room 404 **and** the bad-token 401 (recommended), or only on 401?
3. **Guard structure:** extend `alert.Guards` with namespaced webhook methods
   (recommended), or a dedicated `WebhookGuards` type for hard isolation?
4. **Log identity on a webhook 429:** the **room name** (non-secret; recommended) —
   confirm that's the right operator-facing field, and that the token/hash must
   never appear.
5. **Status code:** **429** for all three reasons (recommended), with the distinct
   reason strings of §5.4 — or differentiate the pre-auth tier further?
6. **Rate guard placement:** **before** the body read (recommended, since the token
   identity is known pre-body — strictly better than the alert path) — confirm.
7. **Config table name:** `[ingest.webhook]` as a sibling of `[ingest.freshness]`
   under `[ingest]` (recommended) — confirm the naming.
8. **`reply_url` amplification:** the spawn cap bounds it; do you also want a note
   tracking a future per-`reply_url` outbound cap, or is bounding spawns sufficient?

---

## 10. Git note

- HEAD = `ea72a2a` (the alert-socket freshness commit); branch `main`; working tree
  clean. This plan adds **only** this document; no code, no `go.mod`, no tag.
- Suggested commit for the *build* (later, not now), generic:
  `feat(ingest): two-tier rate/spawn guard for the webhook socket`. Per the repo
  workflow, the build lands as its own scoped commit after this plan is reviewed.
