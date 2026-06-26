# Netherchat — Universal Connector System (Design)

*The one rule that lets it connect to anything, the architecture, and the
curated app set. Roadmap follows once the set is confirmed.*

**Version 1.0 · June 2026 · Founder reference**

---

## The design law (read this first — everything depends on it)

Netherchat's entire value is that the relay is blind and sensitive coordination
never leaks. A connector system threatens that the instant it lets the wrong
data cross the boundary. So one rule governs every connector, in or out:

> **Only metadata, signals, and signed attestations cross the boundary. Raw
> regulated content and the ephemeral E2E discussion never do.**

- **Inbound** = *"something happened, here's the signal"* → triggers a war room.
  Carries severity, source, finding type, an ID/reference — **never PHI, never
  the raw data, never secrets.** (Inbound alert text rides the relay as *marked
  plaintext*, not E2E — which is exactly why it must be metadata-only.)
- **The sensitive middle** — the actual incident discussion — stays **E2E inside
  the room** and crosses nothing.
- **Outbound** = *"here's the signed record of what we decided"* → filed to a
  system of record, or *"go to the secure room"* → a pointer posted where people
  live. Carries the deliberately-retained attestation, never the chatter.

This is what keeps the compliance posture intact while connecting to tools that
are themselves non-compliant. A pointer to a secure room is safe to post in
Slack; the conversation it points to is not in Slack at all.

### Second law: detection raises alarms; only humans authorize actions

An inbound connector can **open a room and post a marked notice**. It can **never**
approve anything, seal anything, or trigger the edge-exec runbook. Actions stay
behind the human, cryptographic Two-Person Rule inside the E2E room. Machines
ring the bell; people (provably) decide and act. This separation is both the
security model and a clean GxP control (detection is segregated from authorized
action), and it's what stops the universal socket from becoming an abuse vector.

---

## Architecture — one generic socket, typed adapters on top

No connector-specific code lives in the core. The scanner and the egress monitor are
**not** special — they are two clients of a generic mechanism. That's what keeps
your IP untangled from a third-party scanner and from your own egress monitor.

- **Ingress (inbound):** an authenticated, schema-validated, rate-limited alert
  endpoint per room. A POST that matches a `[[route]]` rule spawns a break-glass
  war room and issues one-time invites. (The webhook + route mechanism already
  exists; this hardens and generalizes it.)
- **Generic alert schema:** `{source, severity, kind, summary, ref, ts,
  signature}` — metadata only, strictly validated, oversized/unknown fields
  rejected. Every "integration" is just a tool emitting this shape. A typed
  adapter is optional sugar over the generic shape, never a core dependency.
- **Egress (outbound):** the existing two-way bridge, posting sealed events with
  Ed25519 provenance headers so receivers can verify attribution, not just trust
  it. Outbound carries attestations and pointers — never the room transcript.
- **Source auth:** per-source token or HMAC signature; an unauthenticated or
  malformed POST is dropped, logged (metadata), and never spawns a room.

---

## What crosses the boundary

| Direction | Crosses ✅ | Never crosses ❌ |
|---|---|---|
| Inbound | severity, source, finding type, reference ID, timestamp | PHI, raw secrets, the underlying sensitive data |
| Outbound | signed sealed records, decision/approval attestations, "join here" pointers | the ephemeral E2E discussion, anything not deliberately sealed |

---

## The curated connector set

Tiered by priority. Each line is the role in ≤20 words, plus the
compliance-fit note. **Foundation + Tier 1 is the MVP**; the rest are expansions.

### Foundation (build this; everything else rides on it)

- **Generic signed webhook** — any tool POSTs a schema-valid, authenticated
  metadata alert; routing rules spawn a war room. *Every connector below is an
  adapter on this.*

### Tier 1 — inbound triggers (detection → war room)

- **Third-party AWS scanner** — pushes a cloud/infra finding; severity routes it to an
  auto-spawned, sealed-record war room. *Fit: finding metadata only.*
- **AI-egress monitor** — pushes a critical AI-egress signal; routes to a war room
  for coordinated response. *Fit: the signal, never the data.*
- **SIEM (Sentinel / Splunk / Elastic)** — a correlation rule opens a war room
  with the right responders. *Fit: alert metadata, not log content.*

### Tier 1 — notify / initiate surface (meet people where they live)

- **Microsoft Teams** *(priority — pharma is a Microsoft world)* — posts "room
  open / decision sealed" notices and a join link to a channel; a pointer, never
  content. *Fit: notifications only; the sensitive talk stays E2E in Netherchat.*

### Tier 1 — outbound to system of record

- **ITSM (ServiceNow / Jira)** — on seal, attaches the signed, verifiable record
  to the incident ticket as the authoritative artifact. *Fit: the retained
  attestation, provenance-stamped.*

### Tier 2 — high-value expansions

- **Slack** — same role as Teams for Slack-native orgs: notify, plus
  one-command room initiation; a pointer, never the discussion. *Fit: identical
  guardrail to Teams.*
- **Prometheus Alertmanager** — a critical infrastructure alert opens an ops war
  room instead of dying in a dashboard. *Fit: labels/metadata only.*
- **PagerDuty / Opsgenie** — when a page fires, a sealed-record war room opens
  alongside it. *Fit: complements paging, doesn't replace it; incident metadata.*
- **CI/CD (GitHub Actions / GitLab)** — a failed deploy or pipeline opens a war
  room for the responding engineers. *Fit: build metadata; developer-facing.*
- **SIEM (outbound)** — streams metadata-only room events back for one unified,
  tamper-evident audit trail. *Fit: bidirectional; metadata only.*

### Tier 3 — strategic, heavy, later

- **eQMS (Veeva Vault / MasterControl)** — files the sealed incident/deviation
  record into the quality system as evidence. *Fit: the deepest pharma fit and
  the heaviest lift; a flagship target once a pilot justifies it.*

---

## Explicit exclusions (saying no is part of the design)

- **Inbound email-to-room triggering** — parsing/injection risk on a security
  tool; at most a notify-*out* target later, never an inbound trigger.
- **Mirroring messages into Slack / Teams / any cloud** — defeats relay
  blindness and breaks the compliance posture. Never. Pointers out, content
  never.
- **Consumer messaging (WhatsApp, etc.)** — wrong audience, no enterprise or
  regulated fit.

---

## Ingress hardening (because inbound is untrusted input)

The alert endpoint is an attack surface. Non-negotiables: per-source
authentication; strict schema validation with reject-on-unknown; rate limiting
and a spawn cap per source/window; size limits; and the second-law guarantee
that an inbound POST can open a room and post a marked notice but can **never**
approve, seal, or execute. All rejections logged as metadata only.

---

## Next step

Confirm or trim the connector set above. The MVP I'd recommend is **Foundation +
Tier 1** (generic webhook, scanner, AI-egress monitor, one SIEM, Teams, one ITSM) —
that alone makes the note's "any alert source opens a war room" claim true and
demos the full detect → respond → attest loop. Once you lock the set, the
roadmap sequences the generic socket first, then the typed adapters, then the
outbound systems of record.