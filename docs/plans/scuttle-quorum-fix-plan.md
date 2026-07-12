# Scuttle Two-Person-Rule Bypass — Fix Plan

> **Status:** DESIGN — not yet built. This document is the only deliverable; no code
> has been changed.
>
> **Goal:** Make the configured `[action.scuttle]` (and `[action.break_glass]`)
> two-person rule *effective from every caller*, closing a live governance bypass in
> which a configured Two-Person Rule on a destructive action does nothing. Mirror the
> codebase's own correct pattern (the artifact gate) rather than inventing a new one.
>
> **Repo / baseline:** `main`, HEAD `7f48d44` (tag `v1.10.0` is 9 commits behind HEAD;
> no tag at HEAD; working tree clean at read time).
>
> **Threat model (scope-setting, read this first):** the two-person rule is an
> **honest-client governance control** enforced client-side over signed approvals; the
> relay (and the relay-less coordinator) are **blind by design** and act on the burn
> control without reading quorum. This fix guarantees that the *official client*, on
> *every* code path, consults quorum before it emits a destruction control. It does
> **not** — and, without server-side enforcement, cannot — stop a participant running a
> modified binary from emitting a raw burn control. That is a different threat
> (requires giving up the blind relay) and is explicitly out of scope. Making that
> boundary explicit is part of the deliverable, not a gap in it.

---

## 1. The bug (corrected diagnosis)

The read established the defect precisely; it is restated here as settled fact, not
re-derived.

### 1.1 Root cause — wrong layer, and conditional

The scuttle two-person rule is enforced **only in the TUI command handler** and **only
when `q > 1`**:

- `tui/ui/app/commands.go:440` `runScuttle` reads `q := m.quorumFor(protocol.ActionScuttleAction)`
  and, when `q > 1`, routes through `r.client.RequestAction(ActionScuttleAction, params, q, r.client.ScuttleNow)`.
- The client-core destruction primitives have **no quorum check at all**:
  - `tui/client/client.go:353` `ScuttleNow()` — runs the receipt co-sign round, then
    enqueues `OpControl{Action: ActionScuttle}`. Unconditional.
  - `tui/client/client.go:365` `ScuttleArm(seconds)` — enqueues `OpControl{Action: ActionScuttleArm}`.
    Unconditional.

Therefore **any caller that is not the exact TUI `runScuttle` path bypasses the gate
entirely.**

### 1.2 The live, shipping bypass — relay-less mode

- `tui/sneakernet/session.go:243` — the relay-less REPL maps `/scuttle` directly to
  `c.ScuttleNow()`. No quorum is consulted; `netherchat pair` never loads config
  (`cmd/netherchat/paircmd.go` builds `sneakernet.Options` from flags only), so the
  relay-less client has *zero* quorum knowledge.
- `tui/sneakernet/coordinator.go:238` — the coordinator burns the room on receiving any
  `ActionScuttle` control (`co.scuttle()`), the relay-less mirror of `hub.Scuttle`.

In relay-less mode `[action.scuttle]` quorum is **completely absent**: unilateral
destruction regardless of config. Headless/library callers of `client.ScuttleNow()`
bypass it identically (this is what the e2e tests do: `tui/e2e/scuttle_test.go:92`,
`receipt_test.go:49`, `beacon_test.go:186`).

### 1.3 The twin — `break_glass`

`break_glass` has the identical structural flaw: `tui/client/client.go:387`
`BreakGlass(invitees, ttl)` is ungated; the gate lives only in
`tui/ui/app/commands.go:492` `runBreakGlass` (`if q > 1`). Lower severity (it *creates*
a war room rather than destroying one, and no non-TUI caller invokes it today — the
coordinator explicitly excludes break-glass, `coordinator.go:221`), but it is the same
defect and must be fixed in the same stroke, not left as a known twin.

### 1.4 The correct pattern already in-tree (what to mirror)

The **artifact gate** (`tui/client/artifact.go`) is the codebase's own proof that
core-side enforcement works:

- The gate lives in the client core; `Propose`/`ApproveArtifact`/`countArtifactApproval`
  are reached by *every* caller (TUI, headless, tests).
- It is **unconditional**: even `quorum == 1` requires a distinct non-proposer approver.
- The proposer's fingerprint is excluded in **two** places — `ApproveArtifact`
  (`artifact.go:174`) and `addApprover` (`artifact.go:66`) — so quorum is counted
  cryptographically and no caller can reach the sealed outcome without a second signer.

`runbook` shows the *other* valid pattern: enforced in its sole executor, the agent
binary (`cmd/netherchat/agent.go:97-108`, `loadRunbookQuorum:140`). Both patterns share
the principle the scuttle path violates: **the gate lives where the action is
performed, not one layer above it, and the enforcer owns the quorum rather than
trusting a caller to pass it.**

### 1.5 Secondary defect — silent config degradation (how it hid)

`cmd/netherchat/main.go:140` `clientConfig` auto-loads `netherchat.toml` **from the
current working directory only**, with no `--config` flag. If it is not found,
`config.Default()` applies and *every* `[action.*]` quorum silently becomes `1`, with no
warning. A configured `quorum = 2` can therefore be inert while the operator believes
the control is on. Because scuttle's gate is *conditional* (`q > 1`) while artifact's is
*unconditional*, the same silent degradation makes scuttle fail open but leaves artifact
still requiring a second person — which is exactly the "artifact works, scuttle doesn't"
asymmetry that surfaced the bug.

### 1.6 The receipt is not a gate (do not regress, do not conflate)

`ScuttleNow` collects a co-signed scuttle receipt (`tui/client/receipt.go:68`
`startReceiptRound`). This is **not** consent:

- Peers **auto-sign** on request — `receipt.go:131` `onScuttleReceiptRequest` signs and
  returns an ack after only a `room == c.room` check. No human prompt.
- The round finalizes on a **30s timeout** and burns anyway (`sealTimeout`,
  `client.go:149`; `finalizeReceipt`, `receipt.go:183`).

A co-signed receipt **proves destruction happened**; it never **authorized** it. In a
two-member room the receipt collects two signatures whether or not any gate fired — the
signature of the ungated `ScuttleNow` path. The receipt is correct at what it does and
must not be regressed; it must simply stop being mistaken for the gate.

---

## 2. Settled decisions (constraints — not re-litigated)

| # | Decision |
| --- | --- |
| D1 | **Preserve instant unilateral scuttle at `quorum = 1` / unset.** The gate engages only for `q > 1`; `q <= 1` keeps today's emergency dead-man's-switch behavior. `q == 0` disables the action. |
| D2 | **Approver-never-responds → the existing 60s TTL expiry (`actionRequestTTL`, `action.go:40`) with the room SURVIVING is the correct fail-safe.** An unapproved manual scuttle simply does not happen; the room must never hang half-destroyed. |
| D3 | **Keep the receipt co-sign round running after the gate opens** (as the gated TUI path already does). The multi-party VALID receipt is unchanged. |
| D4 | **Automatic/server-originated scuttles stay ungated** (idle-timeout, owner-loss, armed-elapse — `scuttle.Manager`/`hub.Scuttle`). There is no one to approve; a two-person rule must not block them. Only manual `/scuttle now|arm` gates. |
| D5 | **Fail closed on the intended-but-unresolvable case.** If a `quorum >= 2` is intended but cannot be *enforced*, the action refuses with a clear message rather than silently running at `quorum = 1`. This targets the gap between *"a quorum was intended"* and *"a quorum is active"* — **not** the absence of config. A user who never configured a quorum is in the documented default single-actor mode, which is legitimate. Mirrors the house precedent (`config.validate`, `config.go:500`: `require_fresh` without an `hmac_secret` is a hard config error). |
| D6 | **Loud config provenance.** Make the loaded-config path explicit and visible (a `--config` flag; surface which config loaded and from where at startup / in status), so *"no config found, running defaults"* is visible rather than inferred. |

---

## 3. Design

### 3.1 Decision A — Where the gate belongs (the core fix)

**Recommendation: (i) push the gate into the client core, in the refined form of a
*raw internal primitive + a gated public entry point*, with the client owning its own
quorum policy.** Reject (ii).

#### The two candidates, weighed

| Criterion | (i) Gate in the client core | (ii) Keep raw primitive; one gated entry all callers must use |
| --- | --- | --- |
| Closes all bypasses | **Yes.** TUI, sneakernet, headless, and library callers all go through the same core entry point. | Only if *every* caller remembers to call the gated entry — the exact discipline that already failed. |
| Structural robustness | **Robust.** The bypass becomes *unreachable*: the raw burn is unexported. | **Fragile.** Re-establishes "callers must remember," the root cause. |
| Test churn | **Low** (see below) — hinges on the raw/public split + default `quorum = 1`. | Low, but at the cost of robustness. |
| Precedent | **Matches** the artifact gate (`tui/client/artifact.go`) and the runbook gate (agent-side) — the codebase's own proof (i) works. | No in-tree precedent; contradicts the two working ones. |

The artifact pattern is decisive: the two mechanisms that *work* both put enforcement
where the action is performed and let the enforcer own the quorum. (ii) is the pattern
that *failed*. Choose (i).

#### Why "core-side" for scuttle means *the client owns the quorum*, not *the caller passes it*

Artifact passes `quorum` as a parameter to `Propose(..., quorum)` and is still safe —
**because its gate is unconditional**: even `quorum = 1` requires a distinct approver,
so a caller passing `1` still gates. Scuttle's gate is **conditional** (`q > 1`, per D1):
a caller that passes `1` (or omits it) gets unilateral destruction. Parameter-passing
therefore re-creates the bypass for scuttle. So the **client must own the quorum**: it
is handed the policy once, at construction, and `ScuttleNow()` resolves it internally.
No caller can weaken the gate by mis-passing or omitting a value.

#### The raw/public split (this is what keeps test churn low *and* prevents a double-gate)

Splitting is not merely convenient — it is **required for correctness**. If the gate
lived in a single `ScuttleNow()` that internally calls `RequestAction(..., onApprove=ScuttleNow)`,
the `onApprove` callback would re-enter the gate → an infinite/duplicate request. So:

```
// Sketch — shape of the change, NOT committed code.

// raw, UNEXPORTED destruction primitive — today's ScuttleNow body verbatim
// (receipt round + trigger burn). No quorum check. This is what onApprove runs.
func (c *Client) scuttleBurn() { /* == current ScuttleNow body */ }

// gated PUBLIC entry — the only scuttle door callers can open.
func (c *Client) ScuttleNow() error {
    q := c.quorumFor(protocol.ActionScuttleAction)
    switch {
    case q == 0:
        return errScuttleDisabled                       // [action.scuttle] quorum = 0
    case q <= 1:
        c.scuttleBurn(); return nil                     // D1: instant unilateral
    case !c.canGateQuorum():                            // e.g. relay-less, no approval routing
        return errQuorumUnenforceable(q)                // D5: FAIL CLOSED, do NOT burn
    default:                                            // q >= 2, enforceable
        _, err := c.RequestAction(protocol.ActionScuttleAction, scuttleParams(c.room), q, c.scuttleBurn)
        return err                                      // if it can't be sent, we return err and DO NOT burn
    }
}
```

`ScuttleArm(seconds)` gets the identical treatment (raw `armCountdown(seconds)` + gated
`ScuttleArm`), gating the *request to arm* (arming starts a countdown that later burns
server-side — the elapse burn stays ungated per D4). `BreakGlass(invitees, ttl)` gets
the same split (raw `breakGlassSend` + gated `BreakGlass`), resolving `ActionBreakGlass`
quorum internally.

**Why existing direct-call tests do not churn:** a client with no policy set defaults
every action to `quorum = 1` (mirroring `quorumFor`/`ActionQuorum` today). The e2e tests
that call `client.ScuttleNow()` on `config.Default()` clients
(`scuttle_test.go:81`, `receipt_test.go:49`, `beacon_test.go:186`) therefore still take
the `q <= 1` instant branch → immediate burn → unchanged. The **only** test that must be
revised is the one that hand-rolls `RequestAction("scuttle", ..., 2, func(){ ScuttleNow() })`
(`tui/e2e/action_test.go:52`), which after the fix should either drive the real gated
`ScuttleNow()` on a `quorum = 2`-policy client (better coverage — see §6) or be retained
as an explicit engine-level test with a comment that production no longer hand-rolls it.

#### Signature note

`ScuttleNow`/`ScuttleArm`/`BreakGlass` gain an `error` return. In Go a call statement may
ignore a return, so existing `c.ScuttleNow()` call statements still compile; callers that
want to surface "disabled / awaiting approval / refused" read the error. `runScuttle`
and `runBreakGlass` collapse to *call the client entry, render the returned error* — the
TUI stops duplicating the gate.

#### Where the quorum reaches the client (injection sites)

Add a post-construction setter, mirroring the existing `UseInviteToken`
(`client.go:324`) precedent — **not** a `client.New` signature change (which would break
every construction site and test helper):

```
// Sketch. Stores a copy; consulted by quorumFor at action time.
func (c *Client) SetActionQuorum(policy map[string]int)
func (c *Client) quorumFor(action string) int   // policy[action], else 1
```

Injection points (all before `Connect`/`ConnectWith`):

| Surface | Construction site | Wiring |
| --- | --- | --- |
| Relay TUI | `tui/ui/app/model.go:178` `connectRoom` → `client.New(...)` | pass `m.actionQuorum` into `connectRoom` and call `c.SetActionQuorum(...)`. The TUI's `m.actionQuorum` (set in `Run`, `model.go:84`) already carries the map from `actionQuorums(cfg)`. |
| Relay headless | `cmd/netherchat/main.go` `dialErr`/`dial` → `client.New(...)` | call `c.SetActionQuorum(actionQuorums(cfg))` — headless callers now inherit the gate too. |
| Relay-less | `tui/sneakernet/session.go:76` (and RunJoin/RunLAN) `client.NewWithIdentity(...)` | plumb a quorum policy through `sneakernet.Options` and call the setter (see §3.2). |

The TUI's `m.actionQuorum`/`quorumFor` may remain for *display* (help text, "governance"
status line), but the **client is authoritative for gating**. Recommended: the TUI reads
nothing back for enforcement — it just calls the client entry and renders the error.

### 3.2 Decision B — The relay-less (Sneakernet) problem

**Recommendation: do not leave a silent bypass, and do not pretend relay-less enforces a
quorum it cannot yet honor. Ship a fail-closed refusal now; flag full relay-less gating
as a bounded follow-up.**

Concretely, in relay-less mode with `q >= 2` configured, `ScuttleNow()` **refuses** with
a clear message and does **not** burn — `canGateQuorum()` returns false for the direct
transport. `q <= 1` / unset keeps instant relay-less scuttle (D1). This *is* the D5
fail-closed rule applied to the transport that cannot (yet) enforce.

#### Why not "just gate it" (the seductive but incomplete answer)

The engine frames already route relay-less: the coordinator forwards
`OpActionRequest / OpActionApproval / OpActionVeto` (`coordinator.go:248`), and it only
short-circuits the final `ActionScuttle` control into a burn — which an honest,
core-gated client emits *post-quorum*. So a naive read says "the core gate works
relay-less for free." It does not, because **the relay-less REPL has no approval UI**:
`tui/sneakernet/session.go` exposes only `/whoami /peers /decide /ack /vanish /seal
/scuttle /quit` — there is no `/approve`, `/veto`, or `/pending`, and no request notice.
A gated relay-less scuttle would open a request **no present peer has any command to
approve**, so it would *always* expire at 60s (D2 fail-safe) — safe, but a broken,
confusing UX (a 60s hang then "expired") and a feature that never actually works
relay-less.

#### Why fail-closed-refuse over the alternatives

| Option | Verdict |
| --- | --- |
| Silently burn (status quo) | **Rejected.** This is the bug — a security auditor would (correctly) flag "you fixed relay mode but left relay-less bypassing the configured quorum." |
| Gate + rely on 60s expiry | Safe but poor UX (hang-then-expire) and dishonest (implies enforcement that can't complete without an approve command). |
| Document as "single-actor, ungated" (pure B(b)) | Honest about the limitation but still *burns unilaterally* when `q = 2` was configured — the same governance bypass, merely documented. |
| **Fail-closed refuse (recommended)** | **Safe** (no unilateral destruction when a quorum was intended), **honest** (explicit refusal + reason), **bounded** (no approval UI required), and it **respects operator intent** (`q = 1` relay-less works instantly; `q = 2` relay-less refuses rather than silently downgrading their control). |

#### What B requires (bounded scope)

1. `netherchat pair` loads config (add `--config`, and the same cwd-default + loud
   provenance as `connect`, §3.4), so the relay-less client *knows* its quorum. Plumb the
   resolved policy through `sneakernet.Options` → `SetActionQuorum`.
2. `canGateQuorum()` returns false for the direct transport (the client can already tell
   its transport type — cf. `transportLabel`/`t.PeerID()` in `commands.go:1096-1102`).
3. Loud documentation of the limitation: `pair --help`, the README/self-hosting doc
   Sneakernet section, and a **runtime line** when a relay-less `/scuttle` is refused
   ("relay-less mode cannot route approvals for `[action.scuttle]` quorum = N; refusing.
   Use the relay for two-person-gated scuttle, or set quorum ≤ 1 for single-actor
   relay-less scuttle").

#### Follow-up (flagged, not built)

Add `/approve`, `/veto`, `/pending` and the request notice to the relay-less REPL. Once
present, relay-less flips from *refuse* to *gate* for connected peers (the frames already
route); the air-gapped/offline case still degrades to the D2 fail-safe (no reachable
approver → expiry → room survives), which is the correct outcome for a store-and-forward
transport. This is a UX build, not a protocol change.

### 3.3 Decision C — `break_glass`: same fix or separate?

**Recommendation: covered by A, in the same change.** The core fix — raw/public split,
client owns quorum — applied to `BreakGlass` (`client.go:387`) closes its identical
bypass at the same structural stroke. `break_glass` is relay-only (the coordinator
excludes it), so it has no relay-less dimension and no B-style refusal to design; the
core gate is sufficient. Do not ship the scuttle fix while leaving `break_glass` as a
known-unfixed twin.

### 3.4 The fail-closed config mechanism (D5) + provenance (D6)

Two complementary layers; neither forces a config file on a user who never wanted one.

**Layer 1 — runtime gate fail-closed (the primary mechanism).** The core gate has **no
code path that burns when `q >= 2` without a completed `RequestAction`.** If the gate
cannot be *initiated* — room key not ready, or a transport that cannot route approvals
(relay-less, §3.2) — `ScuttleNow` returns an error and does **not** fall through to
`scuttleBurn`. This is the mechanism that closes "a quorum was intended but the action
ran anyway."

**Layer 2 — config-load fail-closed + provenance.** Add `--config <path>` to `connect`
and `pair`, and change loading semantics (a small, testable helper, e.g.
`loadClientConfig(path) (config.Config, provenance, error)`):

| Situation | Behavior |
| --- | --- |
| `--config X` given, load/parse fails | **FATAL** (exit non-zero, clear message). No silent fallback to `Default()`. |
| No `--config`, `./netherchat.toml` present but unparseable | **FATAL** — a present-but-broken config is an operator error (mirrors the `require_fresh`/`hmac_secret` precedent). |
| No `--config`, no `./netherchat.toml` | `config.Default()` (legitimate single-actor) **+ a loud provenance line**: *"config: none found — running single-actor defaults; [action.*] two-person rules are OFF."* |
| Config loaded | Provenance line: *"config: loaded from `<path>` — governance: scuttle quorum N, break-glass quorum M"* (or "single-actor" when none configured). |

**Provenance surfacing (D6):** the startup line above (stderr for headless; a system
message in the TUI), plus the active governance policy shown in `/whoami` and the status
segment (`netherchat status` / the statusline file, `statusline` in `model.go:99`). The
degradation that hid this bug — *"no config found, running defaults"* — becomes a line
the operator sees, not a state they must infer.

> **Note on the boundary of D5:** once config *has* loaded, "operator meant 2 but typed
> the file path wrong so we saw no `[action.scuttle]`" is indistinguishable from
> "operator deliberately left scuttle single-actor" — the intent is simply not present.
> Layer 2's fatal-on-explicit-failure and loud-on-absence make that case *visible*; the
> gate cannot *infer* an unstated intent, and per D5 it is not asked to. What it
> guarantees is that a *resolved* `q >= 2` is never silently downgraded.

### 3.5 No wire-format change (asserted, with the proof)

Moving the gate into the core sends the **identical frames the gated TUI path sends
today**: `OpActionRequest / OpActionApproval / OpActionVeto` (`protocol/protocol.go:106-108`)
carrying `ActionRequestBody` with `Action == "scuttle"` / `"break_glass"`
(`protocol/ext.go:226-227`), and the eventual `OpControl{ActionScuttle}`. The relay and
coordinator already route all of these. **No protocol type, tag, or op changes; no
versioning event.** If any future refinement (e.g. the §8 receipt-embeds-approvals
follow-up) touches the wire, that must be called out loudly and versioned separately —
this fix does not.

---

## 4. Invariant register (confirm each; cite the enforcing test)

| # | Invariant | How the design preserves it | Enforcing test |
| --- | --- | --- | --- |
| INV1 | **Receipt correctness not regressed** (multi-party receipt verifies VALID with all present signatures) | The receipt round lives inside the *unchanged* raw `scuttleBurn`, called post-quorum by `onApprove` (D3). No change to `startReceiptRound`/`finalizeReceipt`/`onScuttleReceiptRequest`. | `tui/e2e/action_test.go` `TestTwoPersonRuleScuttleExecutes` (asserts `attest.VerifyReceipt … Valid`); `tui/e2e/receipt_test.go` |
| INV2 | **`q <= 1` / unset → instant scuttle preserved** (D1) | `ScuttleNow` takes the `q <= 1` branch → direct `scuttleBurn`. Default (no-policy) client resolves `q = 1`. | `tui/e2e/scuttle_test.go` `TestScuttleNow` (must stay green unchanged) |
| INV3 | **Server-originated scuttles stay ungated** (D4) | Idle / owner-loss / armed originate in `scuttle.Manager`/`hub.Scuttle` and arrive as `ActionScuttle` controls; `onControl` (`client.go:1094`) burns unconditionally — untouched. The gate is only on the client-*initiated* manual path. | `TestScuttleIdle`, `TestScuttleOwnerLoss`, `TestScuttleArm` (`scuttle_test.go`) |
| INV4 | **Blind-relay / import boundary held** | The gate is client-side crypto reusing `tui/client/action.go` (already in `tui/`, already imports `tui/internal/crypto`). **No** code added to `server/`; **no** server-side quorum; **no** crypto import across the boundary. | `just check-boundary` → `TestServerBinaryDoesNotLinkClientCrypto` (must stay green) |
| INV5 | **60s TTL fail-safe** (D2) | `q >= 2` routes through `RequestAction`, whose `actionRequestTTL` (`action.go:40`) expires an unapproved request → `EvActionExpired`, room survives. No new timer. | `TestTwoPersonRuleSingleActorBlocked` (`action_test.go`), + new real-dispatch test (§6) |

CI gates that must also stay green: `gofmt -l .` (empty), `go vet ./...`,
`go test -race ./...`, `just check-boundary`.

---

## 5. Files expected to change (for review scoping — no edits made)

All within `tui/` and `cmd/netherchat/` (INV4: nothing under `server/`).

- `tui/client/client.go` — split `ScuttleNow`/`ScuttleArm` into raw + gated; gate
  `BreakGlass`; add `SetActionQuorum`/`quorumFor`/`canGateQuorum`; canonical params
  builders. (`Vanish`, receipt code, `onControl` untouched.)
- `tui/ui/app/commands.go` — `runScuttle`/`runBreakGlass` collapse to call-the-entry +
  render-error; the `q > 1` branching moves into the core.
- `tui/ui/app/model.go` — pass `actionQuorum` into `connectRoom`; call `SetActionQuorum`.
- `cmd/netherchat/main.go` — `--config` flag; fail-closed `loadClientConfig` + provenance;
  `SetActionQuorum` on headless dial paths.
- `cmd/netherchat/paircmd.go` + `tui/sneakernet/{session,coordinator}.go` +
  `sneakernet.Options` — load config, plumb policy, `canGateQuorum` false for direct
  transport, refusal message + `--help`/doc text.
- Docs: `README` / `docs/self-hosting.md` Sneakernet section (relay-less scuttle
  limitation); `docs/commands.md` if governance-status surfacing is documented.

---

## 6. Test plan

The read found the gap that let this hide: **no test drives the real
`runScuttle`/`runCommand("scuttle")` dispatch with a populated `actionQuorum`** — every
"two-person scuttle" test hand-rolls `RequestAction(...)` directly (`action_test.go:52`,
`tui/ui/app/action_test.go:75`), so the actual dispatch path a user takes is untested and
a wiring gap passes CI green. The plan closes that.

### 6.1 Real-dispatch tests (the path a user actually takes)

Drive the client's **public** entry (and, for the TUI, `runCommand("scuttle now")`) with
a client whose policy is set via `SetActionQuorum`:

- `q > 1` → the **gated** branch is chosen: a `RequestAction` opens (observe
  `EvActionRequest`), and **no burn** occurs without a second approval; a peer approve
  reaches quorum → `EvActionExecuted` → burn + VALID receipt.
- `q <= 1` → the **instant** branch: burn fires immediately, no request.
- `q == 0` → **disabled**: refuses, no request, no burn.
- Same three for `ScuttleArm` (gates the arm request) and `BreakGlass`.

### 6.2 Bypass-surface regression tests (the regression test *for this bug*)

These are the tests that would have caught the original defect — assert the core is
gated regardless of caller:

- `client.ScuttleNow()` on a client with `SetActionQuorum({"scuttle": 2})` and a lone
  actor → **must not burn / must not ratchet the epoch**; opens a gate (relay) or refuses
  (relay-less). This is the headline regression test.
- `client.ScuttleArm(secs)` with `q = 2` → same.
- `client.BreakGlass(...)` with `q = 2` → same (no war-room stand-up without a second
  endorser).
- **Relay-less:** a `pair`/coordinator session where a member runs `/scuttle` with
  `q = 2` → **refuses, room survives** (fail-closed, §3.2); with `q = 1`/unset → instant
  scuttle. (Uses the in-process loopback coordinator, as the sneakernet tests do.)

### 6.3 Fail-closed config tests

- `loadClientConfig("<bad path>")` (explicit) → error/fatal, not a silent `Default()`.
- present-but-unparseable `netherchat.toml` → error/fatal.
- absent config → `Default()` **and** the provenance signal is emitted (single-actor
  defaults visible).

### 6.4 Invariant regression (must stay green, mostly unchanged)

`TestScuttleNow`, `TestScuttleIdle`, `TestScuttleOwnerLoss`, `TestScuttleArm`,
`receipt_test.go`, `TestTwoPersonRuleScuttleExecutes`/`SingleActorBlocked`/
`InitiatorCannotApprove`/`Veto`/`QuorumThree`/`RunbookGate`. The only expected revision:
the hand-rolled `TestTwoPersonRuleScuttleExecutes` may be re-pointed at the real gated
`ScuttleNow()` (§3.1) or kept with a clarifying comment.

> **Test-execution notes (from project memory):** run Go tests via the PowerShell tool,
> one package at a time (the Bash tool hangs `go test` on Windows); `go` invocations are
> slow (~20s) here, and tests that shell out to `go` (e2e binary builds) may time out
> without being real failures.

---

## 7. What this is NOT doing (anti-bloat)

- **No server-side enforcement.** The relay and the relay-less coordinator stay blind;
  they forward action frames and burn on the control. No quorum logic in `server/` or in
  the coordinator (INV4).
- **No change to the receipt mechanism.** The co-sign round is correct at what it does
  (proving destruction); it stays exactly as-is, now running *after* the gate on the
  gated path (D3, INV1).
- **No new approval engine.** Reuse `tui/client/action.go` `RequestAction` — it is
  correct and thoroughly tested (single-actor blocked, initiator-cannot-approve,
  duplicate-approval, veto, quorum-N). Do **not** build a parallel gate.
- **No wire-format / protocol change** (§3.5). If one were ever required it would be a
  loudly-flagged versioning event; this fix requires none.
- **No change to the artifact or runbook paths** — they already enforce correctly and are
  the reference patterns, not subjects of this fix.
- **No defense against a modified-binary insider.** Out of scope by construction (blind
  relay); stated plainly in the threat model rather than papered over.
- **No relay-less approval UI in this fix.** Relay-less `q >= 2` refuses (fail-closed);
  the approval UI is a flagged follow-up (§3.2), not scope creep here.

---

## 8. Follow-up flag (do NOT build in this fix): offline-provable *authorization*

Today a gated scuttle produces a receipt that proves destruction *happened*; the
*authorization* (who approved, cryptographically) lives only in the transient
`RequestAction` approvals and is not embedded in the surviving artifact. A gated
scuttle's receipt could additionally embed the approval proofs — the same mechanism the
artifact flow already uses (`SealedRecord.ArtifactApprovals`; cf. the role-typed
approval work) — so that *"this destruction was authorized by these N distinct
approvers"* is verifiable offline from the receipt alone. This is a genuinely compelling
property for a governance/audit story and a natural companion to this fix. It **would**
touch the receipt bytes (a versioning event, §3.5) and is therefore a **separate,
deliberate follow-up**, explicitly out of scope here.

---

## 9. Open questions (for sign-off before build)

1. **Relay-less end-state (B):** ship fail-closed-refuse now (recommended) and defer the
   approval UI, or invest in the relay-less `/approve`/`/veto`/`/pending` UI as part of
   this fix? (Recommendation: refuse now; UI is a bounded follow-up. Confirm.)
2. **`pair` config default:** should `netherchat pair` auto-load `./netherchat.toml`
   like `connect` (recommended, for symmetry and provenance), or require an explicit
   `--config`?
3. **Refuse-immediately vs gate-and-expire relay-less:** recommendation is to refuse
   immediately with a clear message (better UX than a 60s hang-then-expire) and flip to
   gating when the approval UI lands. Confirm the immediate-refusal wording/behavior.
4. **Quorum injection API:** post-construction `SetActionQuorum` setter (recommended,
   mirrors `UseInviteToken`, no signature churn) vs a `client.New` parameter (breaks all
   construction sites/tests). Confirm the setter.
5. **TUI `quorumFor` fate:** keep `m.actionQuorum`/`quorumFor` for *display only* (help,
   status) with the client authoritative for gating (recommended), or remove it entirely
   and read policy back from the client?
6. **Params canonicalization:** moving the human-readable `params` string
   ("room=…, reason=manual" / "invite=…, ttl=…") into the core makes it canonical
   (defined once, bound into `params_hash`) — confirm no external consumer depends on the
   current TUI-built params text (low risk: params are display + approval-binding, not a
   stable external contract).
