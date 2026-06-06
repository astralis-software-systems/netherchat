# FEATURE_ROADMAP_FREE.md

**Product:** Netherchat (free, self-hosted, open-source)
**Question this document answers:** What features should the free self-hosted version add to dominate the identified gap so thoroughly that engineers recommend it to each other without being asked?

**The gap (restated, so every feature can be checked against it):**
> Netherchat is the out-of-band, self-hosted, server-blind communication layer for high-stakes operational moments — incidents, investigations, sensitive deployments — where the persistence of the record is itself the liability and where the normal channel cannot be trusted.

**The four-filter moat every feature must deepen:**
1. Ephemeral
2. AND infra-native / machine-readable
3. AND self-hostable in one line
4. AND machine-readable / pipe-friendly CLI

**The one test every feature must pass:** *Does this make the war room better, or does it make us more like Slack?*

---

## 0. ARCHITECTURAL CORRECTIONS (read this first)

The operator asked for honesty over validation. Two existing features fight the gap and should be changed *before* new features are layered on top of them. Both corrections also unlock new features later in this document.

### 0.1 Redesign `/exec` (server-side allowlisted command execution) → edge execution

**A server-blind relay that can execute commands is a contradiction.** The whole pitch is "the server can't read your messages." But if the server can `exec`, then:

- The relay becomes a high-value RCE target — the one box everyone in an incident connects to is now also a command runner.
- The allowlist lives on the relay, so the security boundary lives on the dumbest, most-exposed component.
- It quietly breaks filter #1's promise to a security-minded engineer the moment they read the code.

**Fix:** execution moves to the edge. Keep the UX (`/exec rollback-canary`), change the mechanics:

- A `/exec` produces a signed `EXEC_REQUEST` *message* in the room (Ed25519, see §3.3).
- A `netherchat agent` process running on the operator's **own** host watches the room, matches the request against **its own** local allowlist, runs it, and posts stdout/stderr back as a normal E2E message signed by that host's identity.
- The relay never executes anything. It relays a signed request like any other ciphertext.

This distributes trust to where the blast radius already is (the host that was going to run the command anyway), keeps the relay dumb and blind, and gives you a free audit property: every command and its output is a signed message attributable to a host identity. Same five keystrokes, strictly better threat model. The edge agent becomes Tier 2 feature §2.1.

### 0.2 Reframe optional SQLite persistence as a loud, encrypted, opt-in liability

Persistence is fine to offer, but the current framing ("optional, local only") undersells the danger to the exact audience that cares. Two changes:

- Persisted data must be **encrypted at rest** with a key that is **never sent to the relay** (derive from the operator's identity key; store nonce + ciphertext only).
- `--persist` should print a one-line banner on every session it's active: `persistence ON — you are choosing to create a discoverable record`. Make the liability visible at the moment of the decision.

Everything below assumes these two corrections are in place.

---

## 1. TIER 1 — MUST-HAVE GAP DOMINATORS

If any of these is missing, the gap is partially open and a competitor can occupy it. These make "incident war room" real and undeniable. Seven features.

### 1.1 Bring-Your-Own-Key Identity (SSH / age keys, no accounts)

*One-liner:* Your identity is the Ed25519 key you already have — `~/.ssh/id_ed25519`, ssh-agent, or an age key — verifiable against the public keys you've already published.

**The engineer story.** 3:14 a.m. A breach is suspected. You spin up a break-glass room and someone named `oncall-2` joins. In Slack you'd trust that the account is who it says because the IdP says so — but the IdP is exactly what you don't trust tonight. In Netherchat you run `/whois oncall-2`, see `SHA256:Hk3...`, and curl `https://github.com/oncall-2.keys` from your phone on cellular. The fingerprint matches a key they published months ago. You didn't trust the server, the network, or an account directory — you trusted a key they committed to a public surface long before tonight.

**Why competitors cannot copy it.** Slack/Teams/Mattermost identity is *server-anchored*: the account exists because the server says so, which is worthless precisely when the server is the thing under suspicion. Signal/WhatsApp identity is *phone-number-anchored* and tied to a central key directory. None of them can say "the relay literally never holds a private key and cannot impersonate anyone," because their business model requires a central account system. Netherchat can, because it has no accounts to begin with.

**Implementation sketch.**
- `Identity{ Pub ed25519.PublicKey; Handle string; Proof []byte }`. Default load order: `--identity <path>` → `SSH_AUTH_SOCK` (ssh-agent) → `~/.ssh/id_ed25519` → generate ephemeral.
- On join, client sends an `IDENTITY_ASSERT` frame: `sig = Sign(priv, room_id ‖ nonce ‖ unix_ts)`. Relay forwards verbatim; it's inside the E2E envelope so the relay can neither read nor forge it.
- Trust pinning in `netherchat.toml`:
  ```toml
  [[trust]]
  handle = "alice"
  fpr    = "SHA256:Hk3...."        # pin a known fingerprint
  keys   = "https://github.com/alice.keys"   # or a fetch source the CLIENT resolves
  ```
- `/whois @alice` → prints fingerprint, pin status (`pinned ✓` / `unpinned ✗`), and (if `keys` set) whether it matches a published key. The fetch happens client-side. Astralis runs nothing.

**Viral mechanic.** "Wait, my identity is just my SSH key, and I verified my coworker against his github.com/<user>.keys?" is a 20-second demo that lands instantly with any engineer who has ever fought an SSO console. It is the kind of thing people screenshot.

**Priority:** must-have. Every other trust feature (verification, signed records, signed exec) anchors to identity. Build it first.

---

### 1.2 Out-of-Band Verification (Short Authentication String)

*One-liner:* `/verify @alice` derives a 5-word string from the session transcript; you read it to each other over a side channel, and a MITM relay can't make the words match.

**The engineer story.** Same breach. You have alice's key, but how do you know the relay didn't hand you a key it controls and quietly sit in the middle? You're already on a phone bridge with her. You both type `/verify` and read five words. They match. You now *know* the channel is end-to-end clean, confirmed over a channel the attacker doesn't control. This is the literal meaning of "the normal channel cannot be trusted, so verify out of band."

**Why competitors cannot copy it.** This is the Signal safety-number model, and it's incompatible with the team-chat business model: Slack/Teams *can't* offer real out-of-band verification because there's nothing to verify against — the server is the root of trust by design. Signal has it but isn't infra-native, isn't self-hosted, and isn't pipeable. Netherchat is the only tool that is both server-blind *and* lives in the ops workflow where a phone bridge is already open.

**Implementation sketch.**
- After key exchange, both sides hold a transcript hash `th`. Derive `SAS = HKDF(th, "netherchat-sas-v1")`, take 5 bytes, map each to the PGP word list (or 6 emoji). Symmetric, so both compute the same string iff there's no MITM.
- `VerificationState{ Peer Handle; SAS string; Verified bool; Method enum(sas|smp) }`, kept in memory (optionally cached in a local `~/.netherchat/trust.db` so re-verification isn't needed next time).
- `/verify @alice` prints SAS; `/verify @alice ok` marks verified and shows a `✓ verified` badge next to that handle in the roster.
- Stretch: full Socialist-Millionaire (SMP) for shared-secret verification without revealing the secret. Ship SAS first; SMP is additive.

**Viral mechanic.** "I verified the channel during an actual page by reading five words over the phone bridge that was already open." Engineers who know Signal recognize it immediately; engineers who don't get taught the concept *by the tool*, which makes them feel smart, which makes them tell people.

**Priority:** must-have. Without it, "can't trust the channel" is a slogan, not a capability.

---

### 1.3 Auto-War-Room (alert → ephemeral room, automatically)

*One-liner:* A CRITICAL inbound webhook spawns a break-glass room and hands one-time invite links to your on-call — the incident channel exists because the incident exists.

**The engineer story.** PagerDuty fires. Before you've finished reading the alert text, your phone has a Netherchat one-time link and a war room is already live, named for the alert, scoped to a 2-hour TTL. Nobody created a channel, nobody invited anybody, nobody pasted a Zoom link into three places. The monitoring stack that detected the incident also opened the room for it.

**Why competitors cannot copy it.** Slack can do this *only* by writing a bot, hosting the bot, and persisting the resulting channel forever (the channel is the liability you were trying to avoid). The ephemerality + zero-infra combination is the differentiator: the room auto-vanishes when the incident is over, leaving nothing behind. A general team-chat tool structurally cannot ship "the channel deletes itself" as a default — it's antithetical to their retention/search business.

**Implementation sketch.**
- Routing rules in `netherchat.toml`:
  ```toml
  [[route]]
  match  = { severity = "critical" }     # field-equality + optional regex
  action = "break-glass"
  invite = ["@alice", "@oncall"]         # group expands from a [[group]] block
  ttl    = "2h"
  reply  = "https://pagerduty.example/api/incidents/{{.id}}/notes"  # operator's OWN system
  ```
- Inbound webhook payload (JSON) is matched against `[[route]]` rules (field equality + regex; avoid a heavy expression engine). On match: create ephemeral room, mint one-time invite links (reuse existing break-glass machinery), and (a) return links in the webhook HTTP response body and (b) optionally POST them to the operator's `reply` URL.
- `Route{ Match map[string]string; Action string; Invitees []string; TTL time.Duration; ReplyURL string }`.
- All outbound calls hit the operator's own systems. Zero Astralis infrastructure, zero ongoing cost.

**Viral mechanic.** "I deleted 40 lines of Slack-bot glue and now a P1 spawns its own war room." Concrete, measurable, and the kind of thing that gets posted in an SRE Slack — ironically.

**Priority:** must-have. This is what makes "infra-native incident response" literal rather than aspirational.

---

### 1.4 Sealed Record (`/seal`) — tamper-evident minutes without a transcript

*One-liner:* Promote only the decisions and action items to a hash-chained, signed artifact; everything else still vanishes — so you get defensible minutes with zero transcript liability.

**The engineer story.** The incident is resolving. Someone asks the question every ephemeral tool dies on: "How do we do the retro if nothing was saved?" In Netherchat you've been marking the four decisions that mattered with `/decide`. You run `netherchat seal #inc-481`, it collects a signature from everyone present, and out comes `record.json` plus rendered markdown minutes: four decisions, who made them, when, hash-chained and signed. The 600 lines of "is it the LB?" / "rolling back" / "who has prod access" evaporate on schedule. You have exactly the record you can defend and nothing you'd regret keeping.

**Why competitors cannot copy it.** This resolves the *central tension* of the entire category, and it's the feature that makes "ephemeral" survivable in a real org. Slack's answer to retro is "keep everything" — the opposite of the gap. Signal's answer is "keep everything or nothing, manually." Only a tool designed around *selective, signed promotion of specific messages* can offer ephemeral-by-default + defensible-on-demand. It's a design stance their business models can't take.

**Implementation sketch.**
- Marking: `/decide <text>`, `/action @owner <text>`, or `/mark` (promotes the previous message). Marked entries go into an in-memory append-only chain:
  ```go
  type RecordEntry struct {
      Seq      uint64
      TS       int64
      Author   [32]byte            // identity pubkey
      Kind     uint8               // decision | action | note
      Body     string
      PrevHash [32]byte            // H(prev entry)  → tamper-evident chain
      Sig      [64]byte            // Ed25519 over (Seq‖TS‖Author‖Kind‖Body‖PrevHash)
  }
  ```
- `netherchat seal #room` (owner): broadcasts a `SEAL_REQUEST` carrying the chain head hash; each present participant signs the head and returns the signature. Output: `record.json` = `{entries, head_hash, signatures[]}` + a rendered `minutes.md`.
- `netherchat verify record.json`: recomputes the chain, validates `PrevHash` links and every signature against pinned/published identities. Any tamper breaks the chain.
- Unmarked messages are untouched by all of this and vanish per the room's normal TTL / zero-persistence behavior. The sealed record is the *only* artifact and it is explicit, minimal, and signed.

**Viral mechanic.** "It's the first ephemeral tool I can actually use for an incident I might get subpoenaed over — `/seal` gives me signed minutes and `verify` recomputes the hash chain." This is the line that converts the skeptical staff engineer who otherwise says "cute, but legal will never allow it."

**Priority:** must-have. This is the feature that makes the whole product adoptable by a real company. Without it, Netherchat is a toy that legal vetoes.

---

### 1.5 Onion-Service Relay (`netherchat serve --tor`)

*One-liner:* One flag turns the relay into a v3 onion service — reachable anywhere with no port-forward, no public IP, no DNS, no TLS cert, and the address itself authenticates the relay.

**The engineer story.** The incident *is* the network — your VPN concentrator is down and you can't expose a port on anything. You run `netherchat serve --tor` on the laptop in front of you, behind CGNAT, and get `vault7x...onion`. Everyone joins over Tor. There's nothing to port-forward, no cert to provision, no cloud account to log into, and because the .onion address is derived from the relay's key, connecting to the right address *proves* you reached the right relay — no CA, no trust-on-first-use. The out-of-band channel you always wished you had, stood up from a coffee shop.

**Why competitors cannot copy it.** This makes "self-hostable in one line" true even when you have no infrastructure to host *on*. Managed tools (Slack, Teams) are the literal opposite — they require their cloud. Self-hosted-but-heavy tools (Mattermost, Matrix) require a reachable, certificate-bearing, DNS-pointed server, which fails filter #3 the moment your infra is the thing on fire. Netherchat's static-binary + onion combination means the reachability problem is solved with a free, operator-run dependency and zero Astralis cost.

**Implementation sketch.**
- Use `github.com/cretz/bine` to launch/control a `tor` process and publish a v3 onion service mapping `:443 → localhost:<relay port>`. Require `tor` in PATH (or bundle it); document both.
- Client: `netherchat join <addr>.onion/...` dials through a local Tor SOCKS5 (also via bine, or a `--tor` flag that starts an embedded client).
- Free authentication bonus: the v3 onion address *is* the relay's public key fingerprint. Treat connecting to the expected `.onion` as relay authentication — no extra TLS/CA layer needed. Document this clearly in the threat model (§3.6).
- Keep the existing TCP/TLS path as default; `--tor` is additive.

**Viral mechanic.** "`serve --tor` and the war room runs off my laptop behind CGNAT, addressed by the relay's own key." This is catnip for the security-minded subset of engineers who are the loudest evangelists. It will be the headline of the Show HN.

**Priority:** must-have. "Self-hostable" without "reachable without infra" is a half-promise to the exact people who need it most.

---

### 1.6 Dead-Man's Switch / Auto-Scuttle

*One-liner:* `scuttle_after = "30m"` — the room burns its keys and disappears if everyone walks away, because the default failure mode should be that the evidence destroys itself.

**The engineer story.** The incident ends at 4 a.m. and everyone closes their laptops. In every other tool, the channel is now a quiet, permanent liability waiting for a discovery request because someone forgot the cleanup step. In Netherchat the room had `scuttle_after = "30m"`, so 30 minutes after the last activity it ran the `/vanish` ratchet, dropped its keys, and ceased to exist — and emitted one signed line attesting that it scuttled. The thing you'd forget to do is the default.

**Why competitors cannot copy it.** "The channel deletes itself by default" is a direct contradiction of the retention/search business model behind every team-chat incumbent. They sell the persistence you're treating as a hazard. Netherchat can make self-destruction the default because the gap *is* "persistence is the liability."

**Implementation sketch.**
- Per-room policy:
  ```toml
  [room.scuttle]
  idle_after          = "30m"   # no activity → burn
  owner_loss_burn     = true    # owner heartbeat lost → burn
  heartbeat           = "60s"
  ```
- `Room{ Scuttle ScuttlePolicy; lastActivity time.Time; ownerLastSeen time.Time }`. A ticker checks policies; on trigger, run the existing `/vanish` HKDF ratchet to destroy key material, drop the room, and (optionally) emit a signed `SCUTTLED` attestation (the one thing worth keeping is *that* it happened, never the content — see §3.5).
- Manual controls: `/scuttle now`, `/scuttle arm 10m` (visible countdown to all participants).

**Viral mechanic.** "Set `scuttle_after=30m` and the room takes itself out — runs the forward-secrecy ratchet and drops the keys. The default is the evidence destroying itself, as it should be." Quotable, opinionated, and it signals that the tool *agrees with* the security-conscious engineer's worldview.

**Priority:** must-have. Without it, human error reopens the exact liability the product exists to eliminate.

---

### 1.7 Structured Event Stream — `tail --json`, metadata-only by default

*One-liner:* A stable, versioned JSON event schema for the incident timeline that emits *metadata only* by default — joins, acks, seals, fingerprints, timestamps, no message bodies — so you can ship an auditable timeline to your SIEM without leaking a byte of content.

**The engineer story.** Post-incident, your manager wants "a timeline." You don't want to hand over what people actually said. You've been running `netherchat tail #inc-481 --json | vector` into Loki the whole time, and it captured exactly the auditable skeleton — who joined when, who acked the drain, when it was sealed, which host ran the rollback — and *zero* message contents. You produce a defensible operational timeline that contains no transcript. The metadata is the record; the content was never persisted.

**Why competitors cannot copy it.** This is filter #4 ("machine-readable / pipe-friendly") taken to its logical end *and* fused with filter #1 (ephemeral). Consumer tools have no machine-readable event stream at all. Team-chat tools have audit logs, but they're coupled to retained content and locked behind enterprise tiers and APIs. A free, local, stable, content-free event stream you can pipe to `jq` is something only a CLI-native ephemeral tool can offer.

**Implementation sketch.**
- `netherchat tail #room --json` emits newline-delimited JSON:
  ```json
  {"v":1,"ts":"2026-06-06T03:14:22Z","type":"join","room":"inc-481","actor_fpr":"SHA256:Hk3...","verified":true}
  {"v":1,"ts":"...","type":"ack","room":"inc-481","actor_fpr":"...","tag":"drain-complete"}
  {"v":1,"ts":"...","type":"seal","room":"inc-481","head_hash":"...","signers":4}
  ```
- Event types: `message` (metadata: author fpr, length, hash — never body unless `--include-bodies`), `join`, `leave`, `ack`, `handoff`, `exec_request`, `exec_result`, `seal`, `scuttle`, `verify`.
- `netherchat schema` prints the JSON Schema; the `v` field is the schema version and is a stability contract.
- Default redaction is the point: bodies require an explicit local `--include-bodies` flag and never leave the box without one.

**Viral mechanic.** "`tail --json` is a versioned schema that emits metadata only — I pipe it into Loki and get an auditable incident timeline with no message contents. `netherchat schema` prints the JSON Schema." Engineers who have screenshotted Slack to build a timeline will feel this in their bones.

**Priority:** must-have. It's the half of filter #4 that turns "machine-readable" from a CLI convenience into a compliance-grade capability.

---

## 2. TIER 2 — ENGINEER DELIGHT FEATURES

These don't change the core use case; they make engineers fall in love and recommend the tool. The "I didn't know I needed that" category. Eight features plus quick wins.

### 2.1 Edge-Exec Signed Runbooks (`netherchat agent`)

*One-liner:* `/exec rollback-canary` becomes a signed request that the *operator's own host* picks up, allowlist-checks, runs, and reports back — the relay never executes anything.

**Engineer story.** During the incident you type `/exec drain node-7`. The `netherchat agent` running on the bastion (not the relay) sees a request signed by your verified identity, matches `drain` against its local allowlist, runs it, and posts the output back into the room as a signed message. Everyone sees the result; the relay saw only ciphertext; the action is attributable forever in the sealed record.

**Why competitors cannot copy it.** It only makes sense in a server-blind, identity-signed, infra-native model. Slack bots run on a server you must trust; Netherchat's execution is signed at the edge and verifiable end to end. (Also: this is the §0.1 redesign realized as a feature.)

**Implementation sketch.** `netherchat agent --room #ops --allow ./runbook.toml`; watches for `EXEC_REQUEST{ cmd, args, requester_fpr, sig }`; verifies `sig` against pinned identities and `cmd` against the local allowlist; runs with a timeout; posts `EXEC_RESULT{ cmd, exit, stdout_hash, stdout }` signed by the host identity. Allowlist is per-host, declarative TOML — never on the relay.

**Viral mechanic.** "The remote-exec runs on *my* host against *my* allowlist and the relay can't even see the command — it's signed end to end." Removes the obvious security objection to chatops and makes it defensible.

**Priority:** high. It pays off the architectural debt from §0.1 and turns a footgun into a differentiator.

### 2.2 Incident Coordination Primitives (`/ack`, `/handoff`) — not reactions

*One-liner:* `/ack drain-complete` produces a machine-countable quorum (`4/6 acked`), and `/handoff @bob` passes an explicit incident-commander token — coordination primitives, deliberately *not* social emoji.

**Engineer story.** "Everyone ack when your node is drained." Six people type `/ack drain-complete`. The roster shows `4/6` then `6/6`, and the event stream records each ack with a fingerprint and timestamp. Later, `/handoff @bob` transfers the IC role with a visible, recorded token so there's never ambiguity about who's running the incident.

**Why competitors cannot copy it (and why this isn't reactions).** This is the disciplined line the product must hold: a 👍 reaction is social signaling; `/ack <tag>` is a typed, countable, audited coordination state that emits a structured event. Reactions are rejected in §4. Coordination primitives are kept because they make the war room *function*. Team-chat tools conflate the two; Netherchat separates them on purpose.

**Implementation sketch.** `ACK{ tag, actor_fpr, sig }` aggregated into per-tag quorum state; `HANDOFF{ from_fpr, to_fpr, sig }` updates a single `ic` field. Both surface in the roster and in `tail --json`. No free-form emoji, ever.

**Viral mechanic.** "It has `/ack` with a quorum count and an explicit IC handoff token — coordination primitives, not reaction emoji. Whoever designed this has run incidents."

**Priority:** high. Makes multi-person incident coordination legible without becoming chat.

### 2.3 Ephemeral File Relay (`send --file`)

*One-liner:* Stream a file E2E through the relay to the room without it ever being stored anywhere.

**Engineer story.** You need to share a 4 MB heap dump with two responders right now. `netherchat send #inc --file heap.prof` chunks and encrypts it, the relay forwards ciphertext chunks it can't read and doesn't retain, and recipients reassemble it locally. When the room scuttles, the dump is gone everywhere.

**Why competitors cannot copy it.** Every other tool's file sharing *is storage* — that's the liability. A relay that forwards encrypted chunks with zero retention is only possible in the server-blind, zero-persistence model.

**Implementation sketch.** `FILE_OFFER{ name, size, sha256, chunks }` then `FILE_CHUNK{ idx, ciphertext }` over the existing XChaCha20-Poly1305 channel; recipients verify `sha256` on reassembly. Relay buffers in memory with a hard cap and a short TTL; nothing hits disk.

**Viral mechanic.** "File transfer with literally no storage — the relay forwards chunks it can't read and keeps none of them." Surprising to engineers conditioned to think file sharing = a bucket somewhere.

**Priority:** high. Closes the "I had to share an artifact, so I dropped back to a tool that persists" gap.

### 2.4 Split-Key Rooms (Shamir k-of-n) for investigations

*One-liner:* The room key is Shamir-split among trustees so it takes *k of n* people to open the room — no single admin can read it alone.

**Engineer story.** A sensitive investigation (HR, security, whistleblower). You don't want any one administrator able to unilaterally read the room. The room key is split 2-of-3 across three trustees; the room only opens when two of them present their shares. Power is distributed by cryptography, not policy.

**Why competitors cannot copy it.** Centralized tools have a server admin who can always read everything — that's the architecture. Threshold access requires client-held key shares and a server that holds no key, which is exactly Netherchat's model and exactly not theirs.

**Implementation sketch.** Pure-Go Shamir over GF(256) (small, no infra, no paid deps). Split the room symmetric key into `n` shares; age-encrypt each share to a trustee's pubkey; reconstruct from any `k`. `netherchat.toml`: `[room.split] k = 2; trustees = ["@a","@b","@c"]`.

**Viral mechanic.** "Investigation rooms are 2-of-3 Shamir — no single admin can open them." A genuinely novel capability in a chat-shaped tool; the kind of thing people share specifically because they've never seen it.

**Priority:** medium-high. Directly serves the "investigations" use case named in the gap.

### 2.5 Burn-After-Read Per-Message TTL (`/ttl`)

*One-liner:* `/ttl 5m` on a message removes it from every client and the relay's in-flight buffer after the window.

**Engineer story.** You paste a temporary credential to unblock a responder. `/ttl 2m`. It's gone from every screen and the relay buffer in two minutes — no "delete the message" cleanup ritual, no lingering secret in scrollback.

**Why competitors cannot copy it.** Compatible with their UI, antithetical to their retention model — disappearing messages undercut the searchable-archive value prop they sell.

**Implementation sketch.** `Message{ TTL time.Duration }`; clients schedule local removal; relay drops from its in-flight buffer at expiry. Note honestly in docs: this is client-cooperative (a malicious client can screenshot), so it's hygiene, not a guarantee — `/vanish` remains the cryptographic story.

**Viral mechanic.** "Per-message burn timers without a single byte saved anywhere." Small, but the kind of polish that signals the whole product was built by someone who gets it.

**Priority:** medium.

### 2.6 TUI Paste Rendering (stack traces, diffs, code)

*One-liner:* Paste a stack trace, log block, or diff and the TUI syntax-highlights and structurally folds it instead of vomiting 200 unreadable lines into the room.

**Engineer story.** Someone pastes a Go panic with a 60-frame goroutine dump. Instead of scrollback hell, the TUI renders it as a collapsible, highlighted block you can expand. Diffs render with `+/-` coloring. The war room stays readable when it matters most.

**Why competitors cannot copy it.** They can and partly do — but in a *terminal-native* tool this is a different, sharper experience, and it reinforces "this was built for engineers in a terminal, not for everyone in a browser." It's a positioning win more than a moat, which is why it's Tier 2.

**Implementation sketch.** Detect fenced code / common stack-trace and `diff` shapes; render with an existing Go syntax-highlight lib (e.g. `chroma`, BSD-licensed); collapse blocks over N lines with an expand affordance.

**Viral mechanic.** Shows up beautifully in screenshots and live demos — which is itself a viral surface for a terminal tool.

**Priority:** medium.

### 2.7 `netherchat replay`

*One-liner:* Replay a sealed record into a fresh ephemeral room for the retro, so you can walk the timeline together and then let *that* room vanish too.

**Engineer story.** Retro time. `netherchat replay record.json --into #retro-481` reconstructs the decision timeline into a temporary room the team walks through, annotates with fresh `/decide`s, then re-seals. The retro itself leaves nothing behind beyond the new signed record.

**Why competitors cannot copy it.** It's only coherent on top of §1.4's sealed records and §1.6's auto-scuttle — a closed ephemeral loop (seal → replay → re-seal → vanish) that a persistence-based tool has no reason to build.

**Implementation sketch.** Parse `record.json`, verify the chain, stream entries into a new room with original timestamps preserved as metadata. Reuses the §1.4 verifier.

**Viral mechanic.** "The retro reads the signed record back into a throwaway room, and *that* one vanishes too." Completes the story; makes the workflow feel finished rather than clever-but-incomplete.

**Priority:** medium.

### 2.8 Universal `--json` / Scriptable stdio

*One-liner:* Every command accepts `--json` and speaks newline-delimited JSON on stdio, so Netherchat is a composable Unix citizen, not just a chat client.

**Engineer story.** You want a one-line health check in your CI: `netherchat rooms --json | jq '.[] | select(.scuttle_armed)'`. Or drive the whole client from a script with no scraping of human-formatted output. The tool behaves like `kubectl` or `gh`, which is exactly the muscle memory your audience already has.

**Why competitors cannot copy it.** This is filter #4 generalized. GUI-first tools bolt on an API as an afterthought behind enterprise tiers; a CLI-native tool can make machine-readability the default for *every* command for free.

**Implementation sketch.** A shared output layer: every command renders through `Render(human|json)`; `--json` selects ndjson; document a stable shape per command. Pairs with §1.7's event schema.

**Viral mechanic.** "Every subcommand has `--json` and pipes cleanly — it composes like `gh`." The thing engineers notice in the first five minutes and quietly respect.

**Priority:** high. Cheap to maintain if built in from the start; defines the product's character.

### 2.9 Quick wins (lightweight, high charm-per-line-of-code)

- **age-encrypted secrets in config:** `netherchat.toml` may reference `age`-encrypted values (webhook tokens, etc.) so the config can live in a repo without plaintext secrets. (`filippo.io/age`, BSD-licensed.)
- **Local-only Unix-socket rooms:** `netherchat serve --socket /run/nc.sock` for same-host process/agent coordination (CI steps, sidecars) that never touches the network at all — the most extreme expression of "out-of-band."
- **tmux/status-line integration:** `netherchat status --json` feeds a status-line segment showing unread war-room count and IC handle. Visible in every screenshot and stream — a passive viral surface.

---

## 3. TIER 3 — TRUST AND TRANSPARENCY FEATURES

For a security product, verifiability *is* a feature. These let engineers confirm the claims themselves instead of taking them on faith. Six features.

### 3.1 `netherchat doctor --paranoid` — prove relay blindness

*One-liner:* A built-in self-test that round-trips a canary and asserts the relay-visible bytes never contain the plaintext and are statistically indistinguishable from random.

**Engineer story.** Before you trust it for a real incident, you want to *see* that the relay can't read you. `netherchat doctor --paranoid` stands up a local relay with a debug tap, sends a known canary, and prints: relay-visible bytes contain the canary? `NO`. Entropy of relay buffer: `7.99 bits/byte`. You believed the README less than you believe the test you just ran.

**Why competitors cannot copy it.** They can't run a test whose passing condition is "the server learned nothing," because their servers are designed to learn everything.

**Implementation sketch.** Test-mode relay exposes an in-memory frame tap on localhost only; client sends canary plaintext `NETHERCHAT-CANARY-<uuid>`; assert the tap's buffers never contain the canary substring and report Shannon entropy. Ships as a subcommand and as part of CI.

**Priority:** high. It's the demo that converts skeptics.

### 3.2 Reproducible builds + `netherchat verify-binary`

*One-liner:* Builds are reproducible and signed in a public transparency log; one command confirms the binary you're running matches the published source.

**Engineer story.** "How do I know this binary is the audited source and not something with a backdoor?" `netherchat verify-binary` checks the running binary's hash against a cosign signature recorded in Rekor. Match. You can rebuild from source with `-trimpath` and get the same hash yourself.

**Why competitors cannot copy it.** Closed-source SaaS can't offer source-to-binary verification at all; it's structurally unavailable to them.

**Implementation sketch.** `go build -trimpath -buildvcs=true` with a pinned toolchain; publish `SHA256SUMS`; sign releases with `cosign` (sigstore, free OSS) and log to Rekor. `verify-binary` fetches the signature/log entry and compares. Document the reproducible-build recipe.

**Priority:** high.

### 3.3 Per-Message Ed25519 Signatures (optional non-repudiation)

*One-liner:* Each message can be signed by the sender's identity key, so authenticity holds even though the relay is blind to content.

**Engineer story.** In a breach room, confidentiality isn't enough — you need to know *who said "roll back prod."* With message signing on, every message carries an Ed25519 signature checkable against the sender's verified identity. The sealed record (§1.4) inherits this for free.

**Why competitors cannot copy it.** Server-anchored identity means the server vouches for authorship — worthless when the server is suspect. Client-signed messages put authorship beyond the relay's reach.

**Implementation sketch.** Optional `sign = true` per room; `Message.Sig = Sign(identity_priv, body_hash ‖ ts ‖ room_id)`; clients verify on receipt and badge unsigned/invalid messages. Folds directly into §1.4 entries.

**Priority:** high (and a prerequisite for §1.4 and §2.1).

### 3.4 `--dump-wire` and a published wire spec

*One-liner:* Dump the raw frames going over the wire so anyone can confirm only ciphertext leaves the machine.

**Engineer story.** A security engineer wants to *watch* the bytes. `netherchat --dump-wire` prints outgoing/incoming frames; alongside the published wire-protocol spec, they confirm with their own eyes that bodies are ciphertext and metadata is minimal.

**Why competitors cannot copy it.** Proprietary protocols and closed clients can't expose a frame dump against a public spec without exposing the business.

**Implementation sketch.** A debug writer that hex-dumps frames with type annotations; a `PROTOCOL.md` documenting frame layout. Costs almost nothing once frames are well-defined.

**Priority:** medium.

### 3.5 Break-Glass Usage Attestation

*One-liner:* The *only* thing optionally kept is a signed line that break-glass was used — never its content — so you get a compliance signal without a transcript.

**Engineer story.** Security wants to know whenever break-glass is invoked. Netherchat can emit a signed `BREAK_GLASS_USED{ who, when, room_id }` attestation to an operator-configured sink. The fact is auditable; the content never existed in persistent form.

**Why competitors cannot copy it.** The discipline of keeping *only* the metadata is unnatural to tools that monetize the content. It's a stance, not a feature toggle.

**Implementation sketch.** Reuse §1.7 events; an opt-in `[audit] sink = "https://operator-own-system/..."` posts signed attestation events (never bodies) to the operator's own endpoint.

**Priority:** medium.

### 3.6 `netherchat threat-model`

*One-liner:* The threat model ships *in the binary* and prints on demand — what Netherchat protects against, what it explicitly does not, and where the trust boundaries are.

**Engineer story.** Instead of hunting through a wiki, an engineer runs `netherchat threat-model` and gets a crisp statement: relay sees only ciphertext + minimal routing metadata; identity is BYO-key and must be verified out of band; `/ttl` is hygiene not a guarantee; a malicious *client* can always screenshot. Honesty about limits is what earns trust.

**Why competitors cannot copy it.** Publishing a frank threat model that names your own limitations is a posture closed products rarely take; it reads as confidence and respect.

**Implementation sketch.** Embed `THREAT_MODEL.md` via `go:embed`; print it. Keep it brutally honest — the honesty *is* the feature.

**Priority:** medium.

---

## 4. FEATURES TO EXPLICITLY REJECT

Each will be requested. Each refusal is a product decision, not a missing capability. The test throughout: *does this make the war room better, or does it make us Slack?*

1. **Message history sync / multi-device backfill.** Backfill *is* persistence; persistence is the liability the product exists to eliminate. Shipping this would delete the gap. *Refusal = the product's reason to exist.*
2. **Full-text search.** You cannot search what does not persist; building search creates pressure to retain, which inverts filter #1. The sealed record (§1.4) is the answer to "but I need to find things later." *Refusal protects ephemerality.*
3. **Threads, reactions, emoji, GIFs, rich social UI.** These are engagement features for a place people *live*. The war room is a place people *leave*. (Note the deliberate line: `/ack` in §2.2 is a coordination primitive, not a reaction.) *Refusal keeps us out of the engagement business.*
4. **Voice / video calls.** Infra-heavy, fails filter #3, and duplicates the phone bridge that's already open during incidents (and which §1.2 deliberately uses as the out-of-band channel). *Refusal keeps the binary static and the scope tight.*
5. **Persistent user accounts / org directory / SSO admin console.** A central account system contradicts server-blindness; identity is BYO-key (§1.1) precisely so there's no directory to compromise. *Refusal preserves the core trust property.*
6. **Mobile push notifications.** Requires push infrastructure (APNs/FCM relays) = ongoing cost to Astralis, violating constraint #1, and pulls toward a consumer product. The one-time link + onion (§1.5) is the mobile-incident path. *Refusal preserves zero-infra economics.*
7. **Bot framework / app marketplace / integrations directory.** That's Slack's moat and Slack's maintenance burden. Webhooks (in) + pipes/`--json` (out) + edge agents (§2.1) cover the real need with no platform to police. *Refusal avoids becoming a platform we'd have to run.*
8. **Social read receipts.** Distinct from `/ack`: a read receipt is passive social surveillance; `/ack <tag>` is an explicit coordination act. Passive receipts add anxiety and metadata without operational value. *Refusal holds the coordination-vs-social line.*
9. **Federation / cross-server identity protocol (Matrix-style).** Operationally heavy, fails "self-hostable in one line," and reintroduces a trust-and-routing surface the onion model (§1.5) avoids. *Refusal keeps deployment a single static binary.*
10. **A hosted/managed convenience mode baked into the free tier.** Any "we'll host the relay for you" path quietly violates constraint #1 and muddies the server-blind story. Keep the free tier truly self-hosted; if Astralis ever runs infrastructure, that's a separate commercial decision, not a free-tier feature. *Refusal keeps the free tier honest.*

---

## 5. THE HACKER NEWS MOMENT

The exact `Show HN` comment a delighted engineer would post for each Tier 1 feature. If a feature couldn't earn one, it wouldn't be in Tier 1.

**§1.1 BYO-Key Identity**
> The identity model finally makes sense — it's just your SSH key. I verified a coworker by diffing his fingerprint against github.com/<him>.keys, on my phone, on cellular. No accounts, no server-side directory, and the relay never holds a private key so it can't impersonate anyone. How has nobody shipped this before?

**§1.2 Out-of-Band Verification**
> `/verify` derives a 5-word string from the session transcript and you read it over the phone bridge that's already open. It's the Signal safety-number idea dropped into an ops tool, and it took ten seconds during an actual page. If the relay is in the middle, the words don't match. Correct and boring, which is what I want from crypto.

**§1.3 Auto-War-Room**
> Wired `severity=critical` in netherchat.toml and now a P1 spawns the war room and DMs the on-call a one-time link before I've finished reading the alert. The channel exists because the incident exists, and it deletes itself afterward. I threw away 40 lines of Slack-bot glue.

**§1.4 Sealed Record**
> This fixes the thing I hate about ephemeral chat. `/seal` promotes just the decisions into a hash-chained, signed artifact and everything else evaporates. `netherchat verify record.json` recomputes the chain. It's the first disappearing-message tool I'd actually use for an incident I might get subpoenaed over.

**§1.5 Onion-Service Relay**
> `netherchat serve --tor` and it's a v3 onion service. No port-forward, no public IP, no DNS, no cert. The .onion address is the relay's key, so reaching the right address authenticates the relay for free. I ran a war room off a laptop behind CGNAT during a network incident. This is the out-of-band channel I always wanted and never had.

**§1.6 Dead-Man's Switch**
> `scuttle_after=30m` and the room burns itself when everyone walks away — runs the forward-secrecy ratchet and drops the keys. Every other tool's failure mode is "someone forgot to delete the channel." Here the default is the evidence destroying itself. Finally a tool whose defaults match my paranoia.

**§1.7 Structured Event Stream**
> `tail --json` is a versioned event schema that emits metadata only — joins, acks, seals, fingerprints — no message bodies. I pipe it into Loki and get an auditable incident timeline I can hand to compliance without leaking a single thing anyone said. `netherchat schema` prints the JSON Schema. Chef's kiss.

---

## 6. THE 90-DAY BUILD ORDER

Solo developer, six two-week sprints. Sequenced so each sprint depends on the last, ships something demoable, and makes the product visibly better every two weeks. Identity and signing come first because nearly everything downstream verifies against them.

**Sprint 1 (wk 1–2) — Identity foundation.** §1.1 BYO-key identity (ssh-agent / keyfile / age) + `/whois` + trust pinning + github.com/<user>.keys client-side resolution. *Demo:* join a room as your SSH key, verify a peer against their published keys. *Why first:* every trust feature anchors here.

**Sprint 2 (wk 3–4) — Trust layer.** §1.2 SAS verification + §3.3 per-message Ed25519 signatures. Both consume Sprint 1's identities. *Demo:* `/verify` over the phone; signed messages with badged authorship. *Why here:* signatures are a prerequisite for the sealed record in Sprint 5.

**Sprint 3 (wk 5–6) — Machine-readability.** §1.7 structured event stream (metadata-only `tail --json`, `netherchat schema`) + §2.8 universal `--json`. *Demo:* pipe a live incident timeline into `jq`/Loki with zero bodies. *Why here:* Sprint 4's auto-war-room and coordination primitives emit into this stream, so the schema must exist first.

**Sprint 4 (wk 7–8) — The incident loop.** §1.3 auto-war-room (routing rules → break-glass) + §2.2 coordination primitives (`/ack`, `/handoff`). *Demo:* a CRITICAL webhook spawns a room, pages on-call, and the team acks to quorum. *Why here:* turns the trust + machine-readable foundation into the actual end-to-end incident workflow.

**Sprint 5 (wk 9–10) — The central tension, resolved.** §1.4 sealed record (`/decide`/`/mark`, hash chain, multi-party signing, `verify`) + §2.7 `replay`. Depends on Sprint 2 signatures. *Demo:* run an incident, `/seal` it, `verify` the chain, `replay` into a retro room. *Why here:* this is the feature that makes the product adoptable by a real org — ship it once the workflow around it is solid.

**Sprint 6 (wk 11–12) — Reachability + safety + trust capstone.** §1.5 onion-service relay (`serve --tor`) + §1.6 dead-man's switch / auto-scuttle + §3.1 `doctor --paranoid`. *Demo:* stand up a war room behind CGNAT over Tor, watch it self-scuttle, run the blindness self-test live. *Why last:* the Tor integration is the highest-variance external dependency (don't let it block the core), and `doctor --paranoid` is the perfect note to end the Show HN on.

**Deferred to a second quarter (clearly valuable, not on the critical path):** §2.1 edge-exec agent (after §0.1 redesign lands), §2.3 ephemeral file relay, §2.4 split-key rooms, §2.5 per-message TTL, §2.6 TUI paste rendering, §3.2 reproducible builds + `verify-binary`, §3.4 `--dump-wire`, §3.5 break-glass attestation, §3.6 `threat-model`, and the §2.9 quick wins. Reproducible builds (§3.2) should be slotted opportunistically the first time a tagged release goes out — it's cheap to add early and expensive to retrofit trust into later.

---

### One closing note for the operator

The whole roadmap rests on one bet: that **§1.4 (Sealed Record)** is the feature that turns Netherchat from "clever toy security engineers like" into "tool a company can actually adopt for incidents." Ephemerality is the easy half; *defensible ephemerality* — signed minutes with no transcript — is the half nobody else can ship without contradicting their business model. If you cut anything from this list, do not cut that.