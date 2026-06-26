# Netherchat — Build Roadmap: Persona Carry-Over + Universal Connector System

*Wrap the outstanding persona features, then build the universal alert-ingress
and record-egress system from the design doc — Foundation first, Tier 1 next.*

**Version 1.0 · June 2026 · Build reference**

Companion to `netherchat-connector-design.md` (the connector design + the
boundary law). Feed both to the Netherchat build chat. The design doc is the
*what and why*; this is the *in-what-order and done-when*.

---

## 0. How to use this

The build agent should treat this as the authoritative sequence. **Sprint NC-0
captures unfinished persona work first** (so it doesn't fall into the void), then
**NC-1 builds the keystone socket**, then connector Tiers roll out in priority
order. Before editing, produce a short inventory + migration plan and confirm it.

### Note on two different "tier" schemes — do not conflate

- **Persona tiers (A/B/C + your prior numbering):** your existing backlog of
  persona-specific features. Captured in NC-0.
- **Connector tiers (Foundation / Tier 1 / 2 / 3):** from the design doc.
  Built in NC-1 onward.

This roadmap keeps them in separate sprints so nothing collides.

---

## 1. Design posture (the quality bar — stated generically on purpose)

Build to the standard that **auditable, high-stakes environments** expect:
attributable, tamper-evident, verifiable-offline, least-trust, content-minimizing.
State it that way in code and docs. Netherchat is for incident response, security
operations, sensitive coordination, and regulated work **of all kinds** — do not
brand features to a single vertical. The bar happens to satisfy the strictest
regulated buyers precisely because it's set generically high.

---

## 2. Architecture invariants — DO NOT BREAK

1. **Server-blind relay.** Crypto stays physically unreachable from the server
   binary; CI enforces the import boundary. No connector may route content the
   relay could read.
2. **Zero telemetry, zero persistence by default.** Connectors are opt-in,
   config-driven; no default external endpoint; an empty destination is rejected.
3. **Pure-Go, `CGO_ENABLED=0`, single static binary, minimal deps.** Connectors
   talk plain HTTPS/stdlib — no heavy vendor SDKs. (Teams, Slack, ServiceNow,
   SIEMs are all plain webhook/REST — no SDK needed.)
4. **E2E for content; inbound alerts are marked plaintext** (the one bounded,
   documented exception) — therefore inbound carries **metadata only**.
5. **The boundary law:** only metadata, signals, and signed attestations cross.
   Raw sensitive content and the ephemeral E2E discussion never cross.
6. **Detection raises alarms; only humans authorize actions.** An inbound source
   can open a room and post a marked notice — never approve, seal, or execute.
   The Two-Person Rule stays human and cryptographic.
7. **Sealed records stay hash-chained, signed, and offline-verifiable.**

Flag — do not implement — anything that would violate one of these.

---

## Sprint NC-0 — Persona carry-over (do this first so it's not lost)

*Goal: land the outstanding persona-specific features from the prior backlog.
These are mostly independent of the connector system and can ship now.*

> **Precedence note:** these items come from your earlier persona backlog. If the
> build chat already holds a precise prior spec for any of them, **that spec
> governs** — the descriptions below are a faithful capture, not a redefinition.
> Enumerate the full backlog from your own context; the list below is the known
> set plus an explicit catch-all.

Deliverables:
- **A1 — Incident clock.** A visible elapsed-time clock in a war room, started at
  room spawn; the resolution timestamp and total duration are captured into the
  sealed record as metadata. *(Independent — ship now.)*
- **B1 — Terraform provider.** Manage Netherchat resources as code — rooms,
  routes, trust pins, webhooks, action quorums — via a Terraform provider,
  matching the existing config-as-code ethos. *(Independent — ship now.)*
- **C1 — Engagement-in-a-box.** A packaged, turnkey deployment for a security
  engagement: a pre-configured relay + rooms + trust set + sealed-record reporting
  a consultant can stand up per client. *(Independent — ship now; high value to a
  consulting/channel motion.)*
- **C2 — Duress mode.** A duress credential that, on entry under coercion,
  triggers a safe predefined response (e.g., silent scuttle / decoy view) without
  signaling the coercer. Document the threat model precisely. *(Independent — ship
  now; treat as a security-sensitive feature and test the safe-path thoroughly.)*
- **B3 — CI ephemeral war room.** A failed CI/deploy opens a short-TTL war room
  that auto-scuttles. **Dependency flag:** this naturally rides the generic
  ingress socket (NC-1). Either ship a thin standalone version now and generalize
  it onto the socket in NC-5, or defer B3 one sprint and build it as the first
  socket consumer. Recommended: **defer to NC-5** to avoid throwaway work — but if
  it's wanted for an imminent demo, a thin version now is acceptable, marked for
  refactor.
- **Any remaining persona-backlog items ("etc.").** Pull the rest from your
  context and fold them here, tagged with their original persona IDs.

Acceptance criteria:
- Each shipped feature has tests and is documented in industry-neutral language.
- A1's timing data appears in the sealed record as metadata (never content).
- C2's safe-path is verified under test; no telemetry, no signal leak.
- No invariant in Section 2 is violated.

---

## Sprint NC-1 — Foundation: the generic signed ingress socket (keystone)

*Goal: any authenticated tool can POST a schema-valid metadata alert that spawns
a war room by routing rules. Everything inbound rides this. No app-specific code.*

Deliverables:
- **Generic alert schema:** `{source, severity, kind, summary, ref, ts,
  signature}` — metadata only. Strict validation; reject unknown/oversized fields.
- **Per-source auth:** token or HMAC signature per registered source; drop +
  metadata-log anything unauthenticated or malformed (spawns nothing).
- **Route → war room:** extend the existing `[[route]]` mechanism so a matching
  alert spawns a break-glass room with one-time invites; marked-plaintext notice
  posted into the room.
- **Ingress hardening:** rate limit + spawn cap per source/window; size limits.
- **The second-law guard, enforced in code:** an inbound alert can open a room and
  post a notice; it is structurally incapable of approving, sealing, or triggering
  edge-exec. Add a test that proves this.

Acceptance criteria:
- A signed, schema-valid POST spawns a room and invites per route; an
  unauthenticated/malformed one does not and is logged metadata-only.
- Test proves no inbound field reaches a sealed record as raw content.
- Test proves an inbound source cannot approve/seal/execute.
- Pure-Go, no new heavy deps; server-blind boundary intact (CI still passes the
  import-graph check).

---

## Sprint NC-2 — Connector Tier 1 inbound + the detect→respond→attest loop

*Goal: the demo loop is real and the "any alert source opens a war room" claim is
true. Adapters are thin typed sugar over the NC-1 schema — zero core coupling.*

Deliverables:
- **Third-party scanner adapter** — emits the generic schema; documented config + example,
  not a code dependency. (Keeps your IP untangled from the scanner.)
- **AI-egress monitor adapter** — a critical egress signal POSTs the generic schema and
  routes to a war room. (Same arms-length pattern.)
- **One SIEM adapter (Sentinel or Splunk)** — a correlation alert opens a room.
- **The end-to-end loop:** detection → auto-spawned war room → human coordination
  under Two-Person Rule → `/seal` → offline-verifiable record.

Acceptance criteria:
- Each adapter triggers a room using only the generic schema; removing an adapter
  removes no core functionality.
- An offline demo script runs the full loop and verifies the sealed record.
- No adapter carries raw content across the boundary (tested per adapter).

> **Demo-readiness milestone:** after NC-2, the lab demo's Act 3 is live. This is
> the natural point to run the lab demo session (see the lab demo runbook).

---

## Sprint NC-3 — Connector Tier 1 notify / initiate surface (Teams)

*Goal: meet people where they live, with pointers only. Teams first — the
priority surface for regulated enterprises.*

Deliverables:
- **Microsoft Teams connector:** posts "war room open / decision sealed" notices
  and a one-time join link to a channel; optional one-command room initiation from
  Teams. Plain HTTPS (incoming webhook / bot), no SDK.

Acceptance criteria:
- Notices contain only pointer + metadata; a test proves **no message content**
  ever leaves to Teams.
- Initiation creates a room and returns a join link; the sensitive discussion
  stays E2E in Netherchat.

---

## Sprint NC-4 — Connector Tier 1 outbound to system of record (ITSM)

*Goal: the sealed record becomes the authoritative artifact on the incident
ticket.*

Deliverables:
- **ITSM connector (ServiceNow or Jira):** on `/seal`, attach the signed,
  verifiable record (or a reference + summary) to the incident ticket via the
  existing provenance-stamped outbound bridge.

Acceptance criteria:
- The attached artifact verifies offline (`netherchat verify`); the provenance
  header is present and checkable.
- Only the deliberately-sealed attestation is sent — never the room transcript
  (tested).

---

## Sprint NC-5 — Connector Tier 2 expansions

*Goal: broaden coverage once Tier 1 is proven. Build on the NC-1 socket; no new
core mechanisms.*

Deliverables:
- **Slack** — Teams-equivalent notify/initiate for Slack-native orgs; same
  pointer-only guardrail.
- **Prometheus Alertmanager** — critical infra alert → ops war room.
- **PagerDuty / Opsgenie** — page fires → sealed-record war room alongside it.
- **CI/CD (GitHub Actions / GitLab)** — failed deploy → war room. **Generalize B3
  here** onto the socket (retire any thin standalone version from NC-0).
- **SIEM outbound** — stream metadata-only room events back for a unified audit
  trail.

Acceptance criteria:
- Each is a thin adapter over the generic schema/bridge; all pointer-only or
  metadata-only guarantees hold and are tested.
- Server-blind boundary and pure-Go invariants intact.

---

## Sprint NC-6 — Connector Tier 3 (strategic, heavy, later)

*Goal: the deepest system-of-record integration, gated until a pilot justifies
the lift.*

Deliverables:
- **eQMS (Veeva Vault / MasterControl)** — file the sealed incident/deviation
  record into the quality system as evidence, via the provenance bridge.

Acceptance criteria:
- Filed record verifies offline; only the attestation crosses; provenance intact.
- Build this only with a real design partner in sight — it's the heaviest lift and
  the most enterprise-gated.

---

## 3. Cross-cutting acceptance bar (every sprint)

- No new telemetry; connectors opt-in and config-driven; empty destination
  rejected; no default external endpoint anywhere.
- Pure-Go, `CGO_ENABLED=0`, single static binary preserved; plain HTTPS over SDKs.
- Server-blind import-graph check still passes in CI.
- For every connector: a test that proves the boundary law (metadata/attestation
  only, never content/chatter) and, for inbound, the detection-can't-act guard.
- Documentation stays industry-neutral — no single vertical named in feature copy.

---

## 4. Handoff brief for the build chat (paste this)

> New work for Netherchat. Read `netherchat-connector-design.md` (the connector
> design + the boundary law) and this roadmap — together they're the authoritative
> spec.
>
> Before editing: give me a short repo inventory and a plan mapping NC-0 and NC-1
> to specific files/PRs, and wait for my go-ahead.
>
> Then execute in order: **NC-0 first** (the persona carry-over — A1 incident
> clock, B1 Terraform provider, C1 engagement-in-a-box, C2 duress mode, plus any
> other persona-backlog items from your context; B3 CI war room is dependency-
> flagged — prefer deferring it to NC-5). If you hold a prior spec for any persona
> item, that spec governs over my capture. Then **NC-1**, the generic signed
> ingress socket — this is the keystone every inbound connector rides.
>
> Hard invariants (Section 2): server-blind relay, zero telemetry/persistence,
> pure-Go single binary with minimal deps and no heavy SDKs, E2E for content with
> inbound as marked-plaintext metadata only, the boundary law, detection-can't-act,
> and offline-verifiable sealed records. Flag — do not implement — anything that
> violates these.
>
> Keep all feature language industry-neutral. After NC-0 and NC-1, stop and
> report; we proceed through the connector tiers from there.