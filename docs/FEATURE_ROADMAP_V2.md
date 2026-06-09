# FEATURE_ROADMAP_V2.md

**Netherchat — Astralis Software Systems**
*The out-of-band, self-hosted, server-blind communication layer for high-stakes operational moments.*

---

## 0. The framing question that drives everything below

> What do incident responders, red teamers, and platform engineers reach for in a crisis that **does not yet exist** as a polished, self-hostable, ephemeral-first tool?

After working through the personas, the answer clusters in five places. Every Tier 1 feature lives in one of them:

1. **"The thing I'm proving doesn't survive."** You already let people choose what becomes a record (`/seal`). The unsolved half is proving what *didn't* survive — that the room, the keys, and the roster are provably gone. Destruction is currently asserted, not attested.
2. **"Who can read this right now?"** Epochs already define a membership set cryptographically. Nothing surfaces that set as a portable, signed answer to the single most-asked question in any investigation.
3. **"The relay might be part of the incident."** The entire thesis is *the normal channel cannot be trusted.* The relay is currently the one component the thesis never turns on. If the relay is suspect or down, the war room dies with it.
4. **"Some actions are too dangerous for one person."** You count acks (`3/6`). You do not *gate* anything on a quorum. The two-person rule is a missing primitive, not a missing UI.
5. **"The people who need the answer aren't in the room — and shouldn't be."** Execs, support leads, and clients need status *out of band from the war room itself.* Putting them in the room is the leak; leaving them blind is the failure.

These five are the gap inside the gap. Everything else is delight or persona depth.

A note on discipline used throughout: the test is not "is this useful," it's **"does this make the war room better, or does it make us more like Slack?"** Several obviously-useful features are rejected in §4 precisely because they pass the first test and fail the second.

---

## 1. TIER 1 — NEXT MUST-HAVES

Six features. Each deepens all four filters and serves all three revenue personas. Each has a convincing Show HN comment in §6 — that was the gate for inclusion.

---

### 1.1 Sneakernet Mode — relay-less, peer-to-peer war room

**One-liner:** When even the relay can't be trusted, two or more clients form a war room with *no server at all* — LAN auto-discovery or a copy-pasteable handshake blob, same crypto, zero infrastructure.

**The engineer story:**
It's 02:40. The breach involves your internal network and you do not know how deep it goes. Someone says the words nobody wants to hear: *"We can't assume the relay host is clean."* In every other tool the conversation ends there — Slack is the adversary's read access, Signal needs the open internet and a phone number, and your own relay is now a question mark. With Sneakernet, the incident commander runs `netherchat pair`, reads a 4-line base64 blob over the phone (or it auto-discovers on the bridged-out laptop's LAN), and the war room re-forms with the relay completely out of the picture. The comms layer outlived the infrastructure it was supposed to depend on. *That* is the moat made physical.

**Why competitors cannot copy it:**
Server-dependence is architecturally load-bearing for every incumbent. Slack/Teams *are* the server. Signal/WhatsApp route everything through a central service tied to phone-number identity. Matrix is store-and-forward by design — the homeserver is the point. None of them can degrade gracefully to "no server"; their entire identity, routing, and persistence model assumes one. Netherchat already has BYO-key identity and a relay-blind envelope, which means the identity and crypto layers *already don't need the server* — the only missing piece is an alternate transport. That's a feature for you and a re-architecture for them.

**Implementation sketch (Go):**
- Introduce a `Transport` interface; the existing WebSocket relay becomes `RelayTransport`, add `DirectTransport`.
- **LAN path:** mDNS advertise/discover via `github.com/grandcat/zeroconf`, service `_netherchat._udp.local`. Discovered peers are *candidates only* — they still must pass existing Ed25519 trust pinning, so discovery never implies trust.
- **Manual path:** `netherchat pair` emits an offer blob = `{ed25519_pub, x25519_ephemeral, reachable_addrs[], nonce, expiry}`, base64-armored, ~4 short lines. Peer pastes it; their client returns an answer blob; both establish a QUIC session (`quic-go`) authenticated by the *existing* identity keys.
- Reuse the **entire** NaCl group scheme + epoch forward secrecy unchanged — same envelope, different pipe. This is the design payoff of having kept the relay blind: the message layer is transport-agnostic already.
- **Honest scope for the MVP:** LAN auto + manual blob. *No STUN/TURN.* General NAT traversal requires a rendezvous server, which is infrastructure cost and re-introduces a trusted third party — both violate the product's constraints. Ship LAN + manual now; document the boundary loudly rather than pretending P2P-over-internet is free.

**Viral mechanic:**
This is the headline. "An E2E chat tool that *removes its own server* when the server might be compromised" is a one-sentence blog post that writes itself, and it's the rare security claim that's also a flex. It reframes Netherchat from "ephemeral Slack" to "the comms layer that survives infrastructure compromise," which is a category nobody else can credibly claim.

**Priority:** must-have (flagship). See §5 for why it gets its own cycle rather than being crammed into the 60-day window.

---

### 1.2 Status Beacon — read-only, out-of-band status the war room doesn't have to expose

**One-liner:** `/beacon set "..."` publishes a single mutable status line readable through a short-TTL link, encrypted to a *separate* key so beacon readers can see the status without ever being able to read the room.

**The engineer story:**
You're 40 minutes into a SEV1. The VP of Eng, two support leads, and a customer-facing PM are all DMing the incident commander "what's the status?" — pulling the one person who can't be interrupted into status-relay duty. You can't drop the VP into the war room (now your raw incident chatter is in front of leadership, forever-ish, and you've widened the blast radius of who-saw-what). You can't *not* tell them. Beacon solves the exact shape of this: the IC types `/beacon set "Cause isolated, mitigation deploying, ETA 20m"`, runs `netherchat beacon-link #sev1 --ttl 2h`, drops the link in the (untrusted, persisted) corporate chat, and goes back to work. Stakeholders watch a live status line. They learn nothing about the room.

**Why competitors cannot copy it:**
The closest analog is a hosted status page (Statuspage, Instatus) — persistent SaaS, separate product, separate billing, leaks "we are having an incident" into a vendor's database forever. Slack's answer is "add them to the channel," which is the exact failure mode. Beacon is the only design where the *status* and the *room* have different cryptographic visibility boundaries derived from the same ephemeral session — that requires the dual-key model and the ephemeral-by-default posture as foundations, neither of which an engagement-maximizing product wants.

**Implementation sketch (Go + TS):**
- Beacon content is encrypted to `beacon_key = HKDF(room_secret, "beacon")` — a derived key distinct from the message group key. The relay stores **one ciphertext blob per beacon**, mutable, TTL'd, auto-purged. It still can't read it (E2E to `beacon_key`, which the relay never sees).
- `netherchat beacon-link #room --ttl 2h` mints a URL embedding `beacon_key` (read-only; it cannot decrypt messages and confers no membership).
- Read view = a stripped fork of the existing thin web client that fetches + decrypts only the beacon blob and renders the line + a last-updated timestamp. No message stream, no roster, no join.
- **Honest callout:** this is the one place the relay holds state. It's defensible because it's a single, bounded, opt-in, auto-expiring value encrypted to a key the relay never sees — but it *is* a small deviation from "zero persistence," so it must be opt-in per room and visibly TTL'd, never default-on.

**Viral mechanic:**
"Self-hosted, ephemeral status page that doesn't require putting your execs in the war room" is an immediately recognizable pain for anyone who's run an incident. It's the feature support leads and EMs will specifically ask their SREs to set up — pulling Netherchat *up* the org chart from the people who already love it.

**Priority:** must-have.

---

### 1.3 Two-Person Rule — cryptographic quorum *gating* on dangerous actions

**One-liner:** Any privileged action (break-glass to prod, scuttle, signed-runbook execution) can require *N-of-M* independent Ed25519 approvals before it fires — the two-person rule as a protocol primitive, not a policy you hope people follow.

**The engineer story:**
The runbook that will restart the payments cluster is sitting in the war room, signed and ready (`netherchat agent --allow`). At 03:10, exhausted, one engineer is about to run it solo. In a healthy org this needs a second set of eyes — but "needs a second set of eyes" is currently a sticky note, not an enforced control. With the two-person rule, the action emits an `ActionRequest`; it physically does not execute until a second authorized member signs the same request hash. No second signer, no restart. You've turned "we always get a second person to confirm" from a cultural norm that evaporates at 3am into a cryptographic gate that doesn't get tired.

**Why competitors cannot copy it:**
Slack workflow approvals exist but are server-trusting (the server enforces and can be coerced/misconfigured) and persistent. Nobody offers *client-verified, signature-based* M-of-N where the gate is enforced by cryptography over a request hash rather than by a server's good behavior. This is only possible because you already have per-message Ed25519 signatures and ack-quorum counting — you're 70% of the way there; you just don't gate anything yet.

**Implementation sketch (Go):**
- Per-action policy in `netherchat.toml`: `[action.scuttle] quorum = 2`, `[action.break_glass] quorum = 3`, `[action.runbook] quorum = 2`.
- Initiator emits signed `ActionRequest{action, params_hash, nonce, expiry}`. Members respond with `ActionApproval{request_hash, signer_fp, sig}`.
- Client collects N **distinct-signer** valid sigs over `request_hash` before the privileged code path runs (and, for relay-side privileged commands, the relay refuses the command unless the bundle of N sigs is attached — it verifies signatures without reading content).
- Reuse the `3/6` ack-quorum UI for the approval prompt; reuse existing signature verification. Pure protocol + client; no new dependencies.

**Viral mechanic:**
"Cryptographic two-person rule for the 3am prod restart" is a senior-engineer magnet — it's the kind of control people *wish* their CI/CD had. It also quietly de-risks the most dangerous existing feature (`agent --allow`), which makes the whole product more defensible to security buyers (Persona A's compliance motivation).

**Priority:** must-have.

---

### 1.4 Signed Roster Attestation — a portable, verifiable answer to "who can read this?"

**One-liner:** `/roster --signed` produces an artifact in which every current member co-signs the exact set of fingerprints that hold the keys for this epoch — a cryptographic answer to *who could decrypt this conversation at time T.*

**The engineer story:**
Three weeks after the incident, legal asks the question that always comes: *"Who had access to the breach discussion?"* In Slack the answer is a channel membership list the server vendor controls, which is both over-broad and not something you can independently prove. In Netherchat the honest answer was, until now, "the people who held the epoch key — trust us." Roster attestation makes it provable: at the moment of the incident, the IC ran `/roster --signed`, every present member's client signed the membership-set hash, and you kept that one small artifact (a deliberate `/seal`-style choice). Now "who could read this" is a signed, offline-verifiable fact, not an assertion.

**Why competitors cannot copy it:**
Membership-as-cryptographic-fact requires epoch-based group keys where the key-holder set *is* the access set. Slack/Teams membership is a server-side ACL — the server says who's in, and you trust the server. Signal doesn't expose group state as a portable signed attestation. Matrix membership events are server-mediated. Only a tool whose access control *is* its key distribution can answer this question without appealing to a trusted server, and that's precisely the architecture you already shipped.

**Implementation sketch (Go):**
- Each epoch already has a known membership set (the group-key holders). `/roster --signed` constructs `RosterAttestation{room_id, epoch, member_fp_set, set_hash, ts}`; each present member signs `set_hash` with their Ed25519 identity key.
- Collect co-signatures into one artifact (`roster.json`) listing fingerprints + their signatures.
- `netherchat verify roster.json` checks every signature and that the listed fingerprints hash to `set_hash`.
- Reuses fingerprints, epoch membership, and the existing offline `verify` plumbing. Output is ephemeral-by-default — it only persists if someone chooses to keep it.

**Viral mechanic:**
Compliance and IR professionals will recognize this instantly as the artifact they always have to manufacture by hand after the fact. "It produces a signed, verifiable roster of exactly who could decrypt the incident channel" is a sentence that ends procurement objections. It's also a natural pairing with the sealed-record story in talks and docs.

**Priority:** must-have.

---

### 1.5 Scuttle Receipt — cryptographic proof of destruction

**One-liner:** When a room is scuttled (manually, by dead-man's switch, or by owner-loss), the scuttling client emits a signed `ScuttleReceipt` — the *only* surviving artifact — proving the room and its keys were destroyed, without revealing anything about the content.

**The engineer story:**
A red team finishes a 6-week engagement. The contract says all comms must be destroyed at engagement end — and the client's security team, reasonably, wants *proof,* not a promise. "We deleted it" is unfalsifiable and therefore worthless in a deliverable. With a scuttle receipt, the consultancy hands over `receipt.json`: a signed statement that room `X`, epochs `1–N`, was scuttled at time `T`, keys zeroized, co-signed by the engagement lead's identity key. The client runs `netherchat verify receipt.json` and gets a cryptographic answer. The thing that was the *liability* (the record) is replaced by the thing that's an *asset* (proof the record is gone). This is the entire product thesis compressed into one artifact.

**Why competitors cannot copy it:**
Destruction proof is the inverse of every incumbent's value proposition. Their products are *built to retain*; "prove you destroyed it" runs directly against retention, e-discovery posture, and the data they monetize or are obligated to keep. They cannot ship a feature whose purpose is to make data provably unrecoverable, because that's a liability for *them.* For Netherchat it's the logical endpoint of zero-persistence + auto-scuttle, which you already have — you're proving a property the architecture already enforces.

**Implementation sketch (Go):**
- Hook the existing scuttle paths (`/scuttle now`, `/scuttle arm`, `idle_after`, `owner_loss_burn`). Before zeroizing, build `ScuttleReceipt{room_id, epoch_range, reason, member_fp_set, ts, key_zeroized:true}` and sign it; optionally collect co-signatures from present members for a stronger multi-party proof.
- Zeroize keys (existing behavior), then surface the receipt as the lone surviving output.
- `netherchat verify receipt.json` validates signatures and structure. Reuses Ed25519 + existing scuttle hooks + the `verify` command surface.

**Viral mechanic:**
This is the single most quotable artifact the product can produce. "It hands you a signed certificate proving the conversation is cryptographically gone" is a screenshot people post. For consultancies it becomes a line item in the deliverable, which means *their clients* see Netherchat branding in a context of trust — distribution into exactly the environments Persona C carries tools into.

**Priority:** must-have.

---

### 1.6 Two-Way Bridge — closing the alert → ack → resolve loop, honestly

**One-liner:** `netherchat bridge` runs a *decrypting member* daemon that turns in-room decisions/acks/actions into signed, templated outbound callbacks — so a human acking in the war room can resolve the PagerDuty alert that started it, with verifiable provenance.

**The engineer story:**
Inbound already works: Alertmanager fires a webhook, the war room auto-spins (`[[route]]`), the on-call sees it. But the loop is open — the human acks *in chat*, then has to context-switch back to the alerting tool to actually resolve the page, and the two systems never learn about each other. With the bridge, `/ack pager-1234` in the room emits a typed event; the bridge daemon (a normal, key-holding member) POSTs a signed payload back to Alertmanager's resolve endpoint. One ack, loop closed, and the resolve callback carries the *original in-room Ed25519 signature* so the receiver can verify the ack genuinely came from a room member rather than a forged curl.

**Why competitors cannot copy it:**
The honest version of this is the hard part. The *relay cannot do it* — it's blind, it can't read a decision to act on it. So the bridge has to be a decrypting client member, which means provenance flows from the in-room signature, not from a server's say-so. Slack apps do outbound callbacks, but they're server-trusting, persistent, and live in a vendor cloud. Nobody offers a *blind-relay-compatible* outbound bridge where the outbound payload is cryptographically attributable to a specific room member. The architectural honesty constraint is the moat: doing this *correctly* requires the relay-blind design.

**Implementation sketch (Go):**
- `netherchat bridge #room --on decision,ack,action --post <url> --template tmpl.json` joins as a normal member (reuses the client join + decrypt path).
- Subscribes to typed events (you already emit `decision`/`action`/`ack`/`seal` semantics via the slash commands); renders a Go `text/template` payload; POSTs locally/to the configured endpoint.
- Attaches the in-room Ed25519 signature of the triggering event so the receiver can verify provenance against `github.com/user.keys`.
- **Ephemerality guard:** retries are *in-memory and bounded* — no on-disk queue. If the bridge process dies, undelivered callbacks die with it. This is a deliberate trade: a durable queue would re-introduce persistence and is explicitly out of scope. Distinct from `tail --json | curl` because it's typed, templated, provenance-carrying, and integrated with the action model rather than a raw firehose.

**Viral mechanic:**
"Ack the page from your encrypted war room and it actually resolves in PagerDuty — and the resolve is cryptographically signed by whoever acked" is catnip for platform engineers. It's the integration that makes Netherchat part of the ops loop rather than a side channel, which is what turns "neat tool" into "load-bearing tool we now depend on."

**Priority:** high (must-have for Persona B; sequenced last in §5 because it depends on stable typed-event semantics).

---

## 2. TIER 2 — ENGINEER DELIGHT

Seven features whose job is to make a senior engineer say "oh that's clever" and tell a colleague unprompted. None are load-bearing for the moat; all are cheap, on-thesis, and free.

---

### 2.1 Local desktop notifications — the honest answer to "no push"

**One-liner:** `@mention` and configurable events trigger native desktop notifications via `notify-send` / `osascript` / Windows toast — zero push infrastructure, all client-side.

**Engineer story:** You're heads-down in your editor with the TUI in another pane. Your handle gets mentioned in the SEV1. Today you find out when you happen to look. With this, `notify-send "⚡ @you in #sev1"` fires locally. You explicitly rejected APNs/FCM (ongoing cost, server dependency) — and you were right. But *local* notifications cost nothing and require no server. This is the version of notifications that passes the four-filter test.

**Why competitors can't copy it:** They can, technically — but they won't, because their notification story is a cloud push pipeline they monetize and operate. The delight here is the *contrast*: "notifications with zero push infrastructure" is a statement of values, not just a feature.

**Implementation:** Shell out per-OS — `notify-send` (Linux), `osascript -e 'display notification …'` (macOS), PowerShell `BurntToast`/toast (Windows), terminal bell fallback. Trigger rules in `netherchat.toml` (`notify_on = ["mention","decision"]`). ~150 lines, one small platform shim.

**Viral mechanic:** "Desktop notifications with no push server, no APNs, no FCM — it just calls notify-send" is exactly the kind of architectural honesty homelabbers (Persona D) blog about.

**Priority:** high.

---

### 2.2 Live log streaming with an ephemeral ring buffer

**One-liner:** `tail -f app.log | netherchat stream #room` renders as a single live-updating, collapsed block in everyone's TUI — fixed-size ring buffer, never persisted.

**Engineer story:** Mid-incident, three people are pasting snippets of the same log and they're already out of sync. With `stream`, the person at the affected host pipes the live log into the room; everyone watches the same tail update in place. When the room scuttles, so does the buffer. Nobody ever asks "can you paste the last 50 lines again."

**Why competitors can't copy it:** A live, *ephemeral*, ring-buffered stream is anti-persistence by construction — incumbents render pasted logs as permanent messages because permanence is the product. The ring buffer (last N lines, in place, gone at scuttle) only makes sense in an ephemeral-first tool.

**Implementation:** New `stream` message type; client reads stdin, batches, and updates a single collapsible block (you already have collapsible code blocks + `/expand`). TUI keeps a fixed-size ring (e.g., 200 lines). Reuses send + the chroma-highlighted renderer.

**Viral mechanic:** "I piped `tail -f` straight into the war room and everyone watched the same log live, then it vanished" is a demo-in-one-line.

**Priority:** high.

---

### 2.3 Statusline / prompt segment

**One-liner:** `netherchat status --prompt` emits a compact segment (e.g. `⚡#sev1 3↑`) for tmux / PS1 / starship — war-room awareness without opening the TUI.

**Engineer story:** You don't want the TUI open all day, but during an active incident you want a glanceable pulse. A starship segment showing the active war room and unread count gives you ambient awareness in the shell you already live in.

**Why competitors can't copy it:** They could, but consumer chat tools don't think in terms of shell prompts — this is CLI-native delight that only makes sense for an engineer-first tool.

**Implementation:** Trivial. Reads local client state, prints one line, exits fast. Document starship/tmux/PS1 snippets in the README.

**Viral mechanic:** Dotfile repos. Someone's starship config with a Netherchat segment is free, durable, peer-to-peer advertising among exactly the right audience.

**Priority:** medium.

---

### 2.4 QR join for the link-join web client

**One-liner:** `netherchat invite #room --qr` renders the one-time join link as a terminal QR code for instant cross-device or in-person join.

**Engineer story:** The on-call needs the IC's manager in the room *now*, and she's standing at the desk with a phone. Reading a one-time URL aloud is error-prone. Show the QR on screen, she scans, she's in via the thin web client. Thirty seconds, no install, no typo.

**Why competitors can't copy it:** Trivially copyable — but it composes with your *one-time-link, no-account, ephemeral-session* web client, which is the part they can't match. The QR is just the fastest path into a join model they don't have.

**Implementation:** `github.com/skip2/go-qrcode` (PNG) or a terminal-ANSI QR for in-pane display. Pure client-side, ~50 lines.

**Viral mechanic:** Conference/whiteboard demos. A QR that drops someone into an encrypted ephemeral room with no signup is a memorable live demo.

**Priority:** medium.

---

### 2.5 Slash-command macros in `netherchat.toml`

**One-liner:** Define team-specific macros (`sev1 = "/break-glass --route oncall; /beacon set 'SEV1 declared'"`) as config-as-code; the slash engine expands them.

**Engineer story:** Declaring a SEV1 is six commands done under stress in a fixed order. Codify it once as `/sev1` and the runbook becomes muscle memory that can't be fat-fingered at 3am.

**Why competitors can't copy it:** They have slash commands, but not *config-as-code* macros versioned in a TOML you commit to your infra repo. This is GitOps culture meeting chat — only natural for a config-as-code-native tool.

**Implementation:** `[macros]` table in `netherchat.toml`; expand in the existing slash engine before dispatch. Reuses Tab-autocomplete to surface team macros.

**Viral mechanic:** Teams commit their `netherchat.toml` to a public dotfiles/infra repo; the macros become a shared pattern others copy.

**Priority:** medium.

---

### 2.6 `netherchat report` — signed, self-contained incident timeline

**One-liner:** `netherchat report record.json --out incident.html` renders a sealed record into a standalone HTML/MD timeline with the hash chain and verification status embedded — a human-readable artifact that's still cryptographically checkable.

**Engineer story:** The post-mortem needs a clean timeline for people who won't run a CLI verifier. `report` turns the sealed JSON into a single self-contained HTML file (inline CSS, no external fetches) showing decisions/actions/marks in order, the hash-chain status, and the exact `netherchat verify` command to re-check it. The doc is readable by a director and verifiable by an engineer.

**Why competitors can't copy it:** It's downstream of the sealed-record hash chain, which they don't have. A "timeline export" from Slack is just a transcript; this is a *verifiable* timeline.

**Implementation:** Template the existing sealed `record.json` into HTML/MD via Go `html/template`. **No PDF** — PDF rendering pulls in heavyweight deps and grows the binary, violating the no-bloat rule; HTML/MD only. Reuses `verify`.

**Viral mechanic:** Post-mortems get shared widely inside companies; a verifiable, branded timeline artifact circulates Netherchat to everyone who reads the retro.

**Priority:** medium.

---

### 2.7 Accessible web link-join client

**One-liner:** Make the thin browser client screen-reader friendly (ARIA live regions for new messages, keyboard-only flows, a high-contrast theme).

**Engineer story:** Your philosophy explicitly says "engineer-first without alienating non-technical emergency joiners." A blind support lead pulled into an incident via a one-time link must be able to participate. Today the web client is visual-first.

**Why competitors can't copy it:** They can — accessibility isn't a moat. But it directly serves the stated "non-technical emergency joiner" persona and removes a real objection from security/compliance buyers who have accessibility requirements.

**Implementation:** Front-end only (TS). ARIA roles, `aria-live="polite"` message region, focus management, high-contrast palette. No crypto changes.

**Viral mechanic:** Quiet but real — accessibility wins are the kind of thing that gets a tool onto an approved-vendor list and earns goodwill in the self-hosted community.

**Priority:** medium.

---

## 3. TIER 3 — PERSONA-SPECIFIC

### Persona A — Incident Commander / Security Engineer

**A1. Incident clock + automatic MTTR capture**
`/clock start` begins a shared, monotonic incident timer visible in the TUI; `/clock stop` records elapsed time and writes start/stop markers into the sealed record so MTTR falls out of the timeline automatically instead of being reconstructed later. *Why uncopyable:* it ties timing to the hash-chained sealed record, so MTTR is an attested fact, not a guess. *Implementation:* monotonic timer in client state + two seal markers. *Priority:* high.

**A2. Comms-blackout detector → auto-fallback**
The client watches for signals that the normal channel is compromised or gone — relay TLS pin change, `doctor` canary failure, relay unreachable for N seconds — and, on trip, prompts (or auto-triggers under policy) `/break-glass` *into Sneakernet mode* (§1.1). *Why uncopyable:* it composes the blind-relay canary (`doctor`) with relay-less fallback — both Netherchat-only primitives. *Implementation:* health-watch goroutine wired to the existing canary + the new transport. *Priority:* high (depends on §1.1).

**A3. Severity ladder wired to Beacon**
`/sev1`/`/sev2`/`/sev3` set a structured severity that auto-updates the Status Beacon (§1.2) and adjusts routing. *Why uncopyable:* severity-as-state that drives an *out-of-band* beacon, not an in-channel pin. *Implementation:* small state field + macro wiring to §1.2. *Priority:* medium.

### Persona B — Platform / DevOps Engineer

**B1. Terraform provider for room topology**
A `terraform-provider-netherchat` exposing rooms, `[[route]]` rules, and webhook tokens as IaC, so ops comms topology lives in the same repo as the rest of the infra and reviews through the same PR flow. *Why uncopyable:* config-as-code room topology already exists in `netherchat.toml`; wrapping it in a provider is natural for you and conceptually foreign to SaaS chat. *Implementation:* separate Go module using the TF plugin SDK against your config API; ships as its own binary so the core stays lean. *Priority:* high.

**B2. Blind metrics exporter (Prometheus)**
`netherchat exporter` exposes `/metrics`: active rooms, members per room, message *rates*, epoch counts — **never content, never plaintext metadata that breaks blindness**. *Why uncopyable:* the interesting constraint is that a blind relay can only export shape, not substance — "metrics that are structurally incapable of leaking content" is a selling point, not a limitation. *Implementation:* `prometheus/client_golang`, counters incremented at the relay on envelopes it already routes blind. *Priority:* medium.

**B3. CI ephemeral war room (GitHub Action / CI step)**
A reusable Action that, on pipeline failure, opens an ephemeral room, posts the failing job's logs (via §2.2 stream), drops a join link in the PR, and auto-scuttles on green. *Why uncopyable:* ephemeral-room-per-failure that *self-destructs on fix* is only sane in an ephemeral-first tool; Slack would leave a graveyard of dead channels. *Implementation:* thin wrapper over `send`, `--file`/stream, break-glass, and `idle_after`. *Priority:* high.

### Persona C — Red Team / Security Consultancy

**C1. Engagement-in-a-box**
A single signed `engagement.toml` that bootstraps the full comms topology for an engagement (rooms, routes, scoped TTLs, owner keys) and, at engagement end, drives scuttle + emits a **Scuttle Receipt** (§1.5) as the closeout deliverable. *Why uncopyable:* per-engagement room-as-code that provably vanishes is the exact gap noted for this persona; it's the composition of config-as-code + scuttle receipt. *Implementation:* a profile loader over existing config + scuttle hooks. *Priority:* high.

**C2. Duress mode**
A pre-registered duress passphrase that, when entered, presents a plausible empty/innocuous room while silently scuttling the real room and emitting a duress beacon to the rest of the team. *Why uncopyable:* coercion-resistance is squarely in your threat model and absent from mainstream tools; it only makes sense for ephemeral, BYO-key comms. *Implementation:* alternate KDF path on unlock → triggers `/scuttle now` + a signed duress event to teammates. Document limits honestly (it resists casual coercion, not forensic memory capture). *Priority:* medium.

**C3. Pluggable obfuscated transport (authorized engagements)**
Allow the relay/transport to run behind an obfuscation layer (e.g., obfs4-style pluggable transport, standard Tor-ecosystem tech) so authorized-engagement comms survive aggressive DPI on a client network where plain TLS/Tor is fingerprinted and blocked. *Why uncopyable:* extends your existing `--tor` posture; consumer tools won't ship traffic-shape obfuscation. *Implementation:* wrap the transport in a pluggable-transport adapter; reuse the `Transport` interface from §1.1. **Scope/ethics note:** this is comms-security for *contracted, in-scope* engagements — gate it behind explicit configuration and document the authorization expectation, the same way the existing Tor flag is positioned. *Priority:* medium.

---

## 4. FEATURES TO EXPLICITLY REJECT

These will be requested — repeatedly, by smart people, with good arguments. Refusing them is the product. The given reject-list stands; below are the *new* ones you'll face plus the reasoning that makes each refusal a decision rather than a gap.

**Message editing / undo-send.** Requested because "I made a typo." Rejected because the value of a Netherchat message is that it was *signed and said exactly this at this time*; editability after signing weakens the hash-chain integrity story that makes sealed records defensible. The correct mitigation is a short client-side send delay, not server-side mutation. *Refusal = the integrity guarantee is the product.*

**Scheduled / delayed messages.** Requested for "send this at 9am." Rejected because it requires durable server-side queued state — persistence by another name, and a thing the blind relay would have to hold. *Refusal = zero-persistence is not negotiable for convenience.*

**"Just a little" scrollback persistence / search.** The most dangerous request, because it's reasonable-sounding and incremental. Rejected because retention is a ratchet: the moment a little history is kept, it becomes discoverable, then expected, then mandated, and the entire four-filter moat collapses into "ephemeral-ish Slack." *Refusal = the camel's nose; the whole moat is here.*

**Server-side / cloud AI summarization of the live war room.** Tempting given Astralis builds Scrubadubber. Rejected in its tempting form because summarizing the live room requires *reading* the room — which either breaks server-blindness (if relay-side) or creates retention pressure (you can't summarize what you don't keep). The *acceptable* form, if ever built: a purely local, offline-model, opt-in pass over an *already-sealed* record after the fact, producing an ephemeral summary. Anything touching the live room or a cloud API is a hard no. *Refusal = server-blindness and zero-persistence outrank a marquee AI feature.*

**Mobile app with push notifications.** Reaffirming the existing rejection: APNs/FCM is ongoing cost + a server dependency + a central identity, all moat-breaking. The honest substitute is §2.1 local desktop notifications and the install-free web join. *Refusal = no ongoing infra cost, ever.*

**Hosted / managed tier.** Reaffirming, with the sharpest reason: a hosted Netherchat means *you* hold the relay, and the entire pitch is "the relay is blind and you run it." A managed tier asks customers to trust you with the exact thing you've spent the whole product proving they don't have to trust anyone with. *Refusal = the business model cannot contradict the security claim.*

**Federation / cross-server identity.** Reaffirming: store-and-forward federation is Matrix's model and is fundamentally at odds with ephemeral, relay-blind, self-host-in-one-line. *Refusal = different product.*

**Reactions / threads / rich social UI.** Reaffirming: these are engagement features. The war room is not a place you want people to enjoy spending time. *Refusal = we are not optimizing for time-in-app.*

---

## 5. THE 60-DAY BUILD ORDER

**Honest constraint first:** six Tier 1 features do not fit 60 days of solo work, and pretending otherwise produces a bad plan. Sneakernet Mode (§1.1) is a flagship that touches the transport contract and deserves its own dedicated cycle *after* this window — cramming it into a sprint would ship a half-working P2P layer, which is worse than no P2P layer for a security tool. So the 60-day order delivers the **five** features that reuse existing primitives, sequenced by risk: pure-crypto-on-existing-state first (lowest surface), transport-touching last.

**Sprint 1 (Days 1–14) — Roster Attestation + Scuttle Receipt.**
Both are pure crypto over state you already have (epoch membership, Ed25519, the `verify` surface). No transport changes, smallest blast radius, immediate moat value. Ship them together because they share the attestation/signing scaffolding and the `verify <artifact>.json` pattern. *Independently shippable:* yes — two new commands, two new artifact types, one verifier extension.

**Sprint 2 (Days 15–28) — Two-Person Rule.**
Builds on ack-quorum counting + per-message signatures. Adds `ActionRequest`/`ActionApproval` and per-action `quorum` policy in `netherchat.toml`, gating break-glass / scuttle / runbook. Notably hardens the existing `agent --allow` feature (see §7). *Independently shippable:* yes — opt-in per action, defaults to current single-actor behavior when no quorum is configured.

**Sprint 3 (Days 29–42) — Status Beacon.**
The first feature that adds a (tiny, bounded, TTL'd) relay-side state, plus a read-only fork of the web client. Higher surface than Sprints 1–2, but self-contained. *Independently shippable:* yes — `/beacon`, `beacon-link`, and a stripped read-only web view; rooms without a beacon are unaffected.

**Sprint 4 (Days 43–56) — Two-Way Bridge.**
Depends on stable typed-event semantics (decision/ack/action/seal), which by now are exercised by Sprints 2–3. Adds the `bridge` daemon as a decrypting member with templated, provenance-carrying, in-memory-retry callbacks. *Independently shippable:* yes — it's an additive daemon; nothing else depends on it.

**Days 57–60 — Hardening + a Tier 2 quick win.**
Buffer for the inevitable Sprint-4 integration friction, plus ship one cheap delight (§2.1 local notifications or §2.4 QR join) to keep the release narrative warm.

**Then (post-60, its own ~30–45 day cycle): Sneakernet Mode.** LAN auto-discovery + manual handshake MVP, NAT traversal explicitly out of scope. This is the flagship; give it the room it needs.

*Sequencing logic in one line:* start where the crypto already exists and the relay contract is untouched; end where you must touch transport — and quarantine the biggest transport change (P2P) into its own cycle.

---

## 6. THE SHOW HN COMMENT TEST

The comment a delighted engineer posts after discovering each Tier 1 feature. If I couldn't write a convincing one, the feature didn't make Tier 1.

**§1.1 Sneakernet Mode**
> Wait — this thing *removes its own server* when you tell it the relay might be compromised? You run `netherchat pair`, read four lines of base64 over the phone, and the war room re-forms peer-to-peer with no relay in the loop. Every other "secure" chat I've used assumes the server is the one thing you can trust. This one assumes it's the first thing that's compromised. The whole identity layer is BYO-key so the server was never doing anything but relaying ciphertext anyway — pulling it out is almost anticlimactic once you see how it's built. LAN-only without a STUN server, which they're honest about. Exactly the trade I'd want.

**§1.2 Status Beacon**
> The clever bit isn't "status page," it's that the beacon is encrypted to a *different key* than the room. So I can drop a read-only link in our (compromised, persisted, who-knows-who's-reading) corporate Slack and the execs get live status without me having to put them in the actual incident channel. The status and the room have different cryptographic visibility. I've wanted exactly this every single incident and never had a name for it.

**§1.3 Two-Person Rule**
> They turned the two-person rule into a protocol primitive. The runbook that restarts payments literally won't execute until a second authorized key signs the same request hash — it's not a Slack approval workflow the server can be talked out of, it's N-of-M Ed25519 sigs checked client-side. The 3am-prod-restart use case alone sold me. Bonus: it quietly fixes the scariest part of their edge-exec runbook feature.

**§1.4 Signed Roster Attestation**
> "Who could read the breach channel?" is the question I always have to answer by hand weeks later from a server-side membership list I can't independently prove. This produces a signed artifact where every member co-signs the exact set of fingerprints holding the epoch key, and you can `verify` it offline. Because access control *is* key distribution here, the membership set is a cryptographic fact, not an ACL you trust the vendor about. IR teams are going to love this.

**§1.5 Scuttle Receipt**
> So when a room self-destructs, the *only* thing that survives is a signed certificate proving it was destroyed — room ID, epoch range, keys zeroized, timestamp, co-signed — and nothing about the contents. We do red team work and "prove you destroyed our comms" has always been an unfalsifiable promise in the closeout report. Now it's a `receipt.json` the client runs `verify` on. The liability (the record) gets replaced by an asset (proof there's no record). Genuinely hadn't seen anyone do this.

**§1.6 Two-Way Bridge**
> The honest engineering here is what got me. The relay is blind, so it physically *can't* fire outbound webhooks on a decision — so the bridge is a decrypting *member* instead, and the outbound resolve callback carries the original in-room signature so PagerDuty can verify the ack came from a real room member and not a forged curl. Ack the page in the encrypted war room, the page actually resolves, and the resolve is attributable. It's `tail --json | curl` if `tail --json | curl` had provenance and a type system.

---

## 7. RUTHLESS HONESTY — current features to redesign or quarantine

You asked for this, so here it is straight.

**`agent --allow runbook.toml` (edge-exec signed runbooks) is your highest-risk feature and your least "war room" feature.** Executing runbooks from a comms tool is a powerful capability and also the single most attractive foothold for an attacker who gets into a room, and it strains the product's identity ("are we comms, or are we an exec platform?"). *Recommendation:* keep it, but quarantine it — default-off, **gate it behind the Two-Person Rule (§1.3)**, and make it structurally impossible to auto-execute from inbound-webhook content (webhook payloads are data, never commands). This turns your scariest feature into a showcase for your strongest new one.

**`/export [--json]` of full history slightly undercuts the "you choose precisely what becomes a record" thesis.** The sealed-record model is elegant *because* persistence is a deliberate, scoped act. A blanket full-history export is a quiet escape hatch around that discipline. *Recommendation:* default `/export` to sealed items only; require an explicit `--all` with a visible warning for full history. Keep the capability, but make the safe path the default path.

**The thin web client is your weakest "architecturally honest" surface.** Browser JS crypto means the joiner is trusting that the bundle they were served wasn't tampered with — a supply-chain gap that doesn't exist for the static Go binary. *Recommendation:* pin the expected bundle hash inside the one-time join link (or serve with strict SRI) so a technical joiner can verify they received the un-tampered client. This closes the one place where "blind relay" doesn't fully extend to "verifiable client."

**Opt-in SQLite persistence should be encrypted at rest with the room key.** It's local-only and opt-in, which is fine — but a stolen disk currently yields plaintext, which contradicts the rest of the threat model. *Recommendation:* encrypt the SQLite store under a key derived from the room secret so persistence-at-rest inherits the same blindness guarantee as persistence-in-transit.

**Theming is done — stop here.** Eight themes is plenty and on the right side of delight/bloat. New theme requests are the kind of low-value engagement work that quietly pulls focus from the moat. This isn't a redesign rec; it's a "resist the temptation" rec. The next theme is not where your leverage is — §1.1 through §1.6 are.

---

*End of FEATURE_ROADMAP_V2.md*