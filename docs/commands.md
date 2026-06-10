# Commands & keys

## Slash commands (TUI)

Type these in the message box. Tab completes command names and arguments.

| Command | Description |
|---|---|
| `/help` | List all commands. |
| `/theme <name>` | Switch theme instantly. Names: `nether`, `abyss`, `ember`, `ghost`, `sprinkles`, `dracula`, `gruvbox`, `solarized`. |
| `/font` | Show the recommended terminal font for the current theme (advisory — a TUI cannot change the terminal font; the web client honors fonts directly). |
| `/whoami` | Show your identity: ssh-keygen-format fingerprint, where the key came from (ssh-agent / key file / generated), room, and encryption status. |
| `/whois [@handle]` | Show an identity's fingerprint, pin status (`pinned ✓` / `unpinned ✗`), and — if a `keys_url` is configured — whether it matches a published key. No argument shows your own identity. See below. |
| `/verify [@handle [ok]]` | Out-of-band verify a peer via a 5-word SAS read over a trusted side channel. See below. |
| `/invite` | Mint a one-time invite token for the current room and display it as a QR code. |
| `/break-glass --invite a,b --ttl 4h` | Stand up an ephemeral, invite-only **war room** with a hard TTL and a one-time browser join link for each named person. See below. |
| `/vanish` | Rotate the room key forward (HKDF ratchet) and clear history for everyone — messages from before are no longer decryptable. |
| `/ttl <dur\|off>` | Set a client-side message display TTL (e.g. `/ttl 1h`, `/ttl off`). |
| `/beacon set "<text>"` · `clear` · `status` · `link [--ttl 2h]` | Out-of-band, read-only **status beacon** (§1.2). `set` publishes a status line encrypted to a separate key; `status` reads it; `clear` removes it; `link` mints a read-only browser URL to share with stakeholders who never join the room. See below. |
| `/exec <action>` | Send a signed, E2E-encrypted request for a `netherchat agent` to run a runbook action on its own host. The relay never runs anything. See below. |
| `/approve <id> [confirm]` | Approve a pending privileged action (the **Two-Person Rule**). Without `confirm` it shows exactly what you'd endorse; `confirm` signs and sends. You cannot approve your own request. See below. |
| `/veto <id> [reason]` | Cancel a pending privileged action immediately. Any member may veto. See below. |
| `/pending` | List pending privileged-action requests with their endorsement counts and time remaining. See below. |
| `/ack [tag]` | Ack a coordination tag (e.g. `/ack drain-complete`). The member list shows a running quorum (`drain-complete 3/6`). No argument lists active tags. A typed coordination primitive — **not** a reaction. See below. |
| `/handoff @handle` | Transfer the incident-commander (IC) token to another member. The IC holder is shown with a `⚡` in the member list. See below. |
| `/ic` | Show who currently holds incident command in this room. |
| `/join <room>` | Join another room (opens a new tab in the sidebar). |
| `/leave` | Leave the current room. |
| `/clear` | Clear the current room view locally. |
| `/quit` | Quit. |

## `/break-glass` — the incident war room

Stand up an encrypted war room in one command, pull in anyone with a link, and
let it vanish on a timer:

```
/break-glass --invite alice,bob --ttl 4h
```

This asks the server to:

1. create a fresh, invite-only, **ephemeral** room with a server-generated name
   (e.g. `war-3f9a2b71`) and a **hard deadline** of now + TTL — the room closes at
   the deadline whether or not it is still in use;
2. mint a one-time invite token for each named person (plus a host token for you);
3. print a browser **join link** per person, ready to paste into a call or email;
4. drop you into the new room (in the background — switch with `Ctrl+N`).

Each link looks like `https://chat.example.com/join?room=war-3f9a2b71&token=…` and
opens the thin [web join client](#the-web-join-client): the recipient types a
display name and is in the room — no account, no install, same end-to-end
encryption as the TUI. Tokens are single-use and expire with the room.

Flags: `--invite <comma,separated,names>` (one link each), `--ttl <dur>` (default
`4h`; the server clamps to `[1m, 168h]`). The link host defaults to the relay's
origin; override it with `netherchat connect … --web-url https://chat.example.com`
when the web client is served from a different host than the relay.

### The web join client

The browser join client (served at `/join`) exists only to let someone join an
ephemeral room from a one-time link with zero friction: one screen to enter a
display name, then a message list, member count, and connection status. It holds
an **ephemeral session key generated fresh on every visit** — nothing is written
to `localStorage`; close the tab and the identity is gone. Its crypto is
byte-for-byte identical to the TUI (X25519 + XChaCha20-Poly1305 + Ed25519), so a
browser guest and terminal users share the same room transparently.

To serve it on the same origin as the relay, build `web/` (`npm run build`) and
have your reverse proxy serve the static `dist/` and map the clean path
`/join → /join.html` (one rewrite rule), while proxying `/ws` to the relay.

## `/verify` — out-of-band verification (SAS)

`/whois` checks an identity against a key published *somewhere*. `/verify` checks
that **the live channel itself** has no MITM — even if you don't trust the relay
or the network. After key exchange, both sides derive a 5-word **Short
Authentication String** from the session transcript (the room key + both parties'
public keys). You read the words to each other over a side channel already open
(a phone bridge during an incident). If they match, the channel is clean; a relay
that substituted a key produces different words.

```
/verify @bob        # prints the 5 words + read-aloud instructions
/verify @bob ok     # after they match, mark bob verified (✓ in the member list)
/verify             # show everyone's verification status
```

Both parties run `/verify @<other>` and compare; the 5 words are identical iff
there's no MITM. Verification is in-memory only (it does not persist).

Once verified, that peer's signed messages show a `✓✓` badge; a trust-pinned
(`[[trust]]`) sender shows `✓`; an unsigned (legacy) sender shows `?`. A message
whose signature fails verification is rejected with a warning and its body is not
shown.

## Identity — bring your own key

Your identity is an Ed25519 key you already have. On connect, Netherchat resolves
one in this order:

1. `--identity <path>` — an OpenSSH private key file *or* an age identity file.
2. `SSH_AUTH_SOCK` — your **ssh-agent**'s first Ed25519 key (signing is delegated
   to the agent; the private key never enters the Netherchat process).
3. `~/.ssh/id_ed25519`
4. `~/.ssh/id_ed25519_sk` (hardware-backed)
5. `~/.config/netherchat/identity.json` (a previously generated key)
6. otherwise, generate a fresh ephemeral key (last resort).

`/whoami` prints the fingerprint in the **exact `ssh-keygen -lf` format**, so you
can compare it directly:

```
$ ssh-keygen -lf ~/.ssh/id_ed25519
256 SHA256:Hk3xyzABCDEF... you@host (ED25519)
$ netherchat connect …   # then type /whoami → fingerprint: SHA256:Hk3xyzABCDEF...
```

The X25519 key that wraps room keys is **derived from the same Ed25519 key**
(RFC 8032 → RFC 7748), so one key is your whole identity. The relay never holds a
private key and cannot impersonate anyone.

## `/whois` — verify a peer against their published keys

`/whois @alice` looks up the connected member named `alice`, prints their
fingerprint and pin status, and (if configured) fetches their published keys
**client-side** — Astralis runs nothing. Pin in `netherchat.toml` (read only by
clients; the relay never sees it):

```toml
[[trust]]
handle   = "alice"
fpr      = "SHA256:Hk3..."                  # optional: pin a fingerprint
keys_url = "https://github.com/alice.keys"  # optional: a published-key source
```

- `fpr` only → warn if a key doesn't match; never fetch.
- `keys_url` only → fetch on `/whois`; never auto-pin.
- both → fetch *and* verify against the pin.
- neither → just a display-name alias.

The 3 a.m. move: someone joins as `oncall-2`, you `/whois @oncall-2`, and confirm
their fingerprint against `github.com/oncall-2.keys` they published months ago —
trusting a key, not the server, the network, or an account directory.

Point at a specific config with `--config <toml>` (default: `./netherchat.toml`).

## `/exec` and `netherchat agent` — edge execution

The relay **never** runs commands (a blind relay that can `exec` is a
contradiction). Instead, `/exec drain` produces a signed, end-to-end-encrypted
`EXEC_REQUEST` in the room. A `netherchat agent` running on **your own** host
matches it against **its own** local allowlist, runs it, and posts a signed result
back. The relay only ever routes ciphertext.

```bash
netherchat agent --room ops --allow runbook.toml --server ws://chat.example.com
```

```toml
# runbook.toml — the allowlist lives on the agent host, never on the relay.
[[allow]]
cmd     = "drain"
command = "/usr/local/bin/drain.sh"   # fixed command line; no shell, no caller args
timeout = "60s"
```

Then from the TUI: `/exec drain`. Every attempt (allowed or denied) is logged
locally on the agent host, attributed to the requester's key fingerprint, and the
result is a signed E2E message everyone in the room can verify.

## The Two-Person Rule — `/approve`, `/veto`, `/pending`

Some actions are too dangerous for one person. The two-person rule turns "we always
get a second set of eyes" from a sticky note into a **cryptographic gate**: a
privileged action does not fire until *N* distinct authorized members have signed
the same request hash. It is enforced client-side over Ed25519 signatures — the
relay routes the request/approval/veto frames as opaque ciphertext and cannot
bypass or be coerced to bypass it.

Declare the policy in `netherchat.toml` (a client-side policy, like `[[trust]]`):

```toml
[action.scuttle]
quorum = 2          # /scuttle now and /scuttle arm need a second approver
[action.break_glass]
quorum = 2          # opening a war room needs a second approver
[action.runbook]
quorum = 2          # a netherchat agent runs a runbook action only after a second approver
```

`quorum = 1` (the default) is single-actor — today's behavior, unchanged.
`quorum = 0` disables the action entirely. The requester's signed request counts as
endorser #1, so `quorum = 2` is the classic two-person rule: the requester **plus
one independent approver**. A single actor can never reach quorum alone.

When a gated `/scuttle` or `/break-glass` is run (or an agent receives a runbook
`/exec`), the room sees:

```
⚡ @alice requests: scuttle  (needs 2 endorsers — the requester plus 1 more)
   params: room=ops, reason=manual
   approve: /approve a3f9 confirm    ·    veto: /veto a3f9 [reason]
   expires in 60s
```

A live **pending-approvals panel** above the input bar tracks every open request
with its endorsement count and countdown. Each approver runs `/approve <id>` to see
exactly what they would endorse, then `/approve <id> confirm` to sign — the
double-confirm prevents an accidental approval. When quorum is reached the action
executes (`✓ Quorum reached (2/2). Executing: scuttle`); any member can `/veto <id>`
to cancel it immediately, and a request that sits for 60s without quorum expires.

Security properties: the initiator cannot approve their own request; each member
counts once (duplicates don't increment); the `params_hash` binds an approval to the
exact action, so an approval of `scuttle room=ops` can't be replayed to approve
`scuttle room=prod`; approvals arriving after execution or veto are discarded; and
quorum state is in memory only (a client restart clears pending requests). For the
agent runbook gate, run `netherchat agent --config netherchat.toml` so it reads
`[action.runbook]`.

## Status Beacon — out-of-band incident status (`/beacon`)

During a SEV1, execs and support leads want status without being dropped into the
war room (where they'd see raw chatter and widen the blast radius). The beacon
publishes a single mutable status line readable through a short-TTL link, encrypted
to a **separate key** so a reader sees the status but **never the room messages**.

Enable it per room in `netherchat.toml`:

```toml
[rooms.ops]
beacon_token = "a-long-random-secret"   # authorizes /beacon set and /beacon clear
beacon_ttl   = "1h"                      # how long a beacon persists (max 24h)
```

Then, from the TUI:

```
/beacon set "Cause isolated, mitigation deploying, ETA 20m"   # publish/update
/beacon status                                                # read it back (decrypts locally)
/beacon clear                                                 # remove it
/beacon link --ttl 2h                                         # mint a read-only browser URL
```

`netherchat beacon-link <room> --ttl 2h` does the same from the shell (it joins the
room briefly to derive the beacon key, prints the URL, and exits). The URL looks
like `https://chat.example.com/beacon?room=ops&key=<base64>&ttl=7200`: paste it into
your (untrusted, persisted) corporate chat and stakeholders watch a live status
line. The `key` is the **beacon key only** — it cannot decrypt messages and confers
no membership.

How it stays honest: the status is sealed with
`beacon_key = HKDF-SHA256(room_key, "netherchat/beacon/v1")`, distinct from the
message key; the relay stores **one ciphertext blob per room** (the single,
opt-in, TTL'd exception to zero-persistence) and cannot read it; and the beacon is
auto-purged when the room scuttles. The read view is a stripped, read-only web page
— no message list, no join. See [encryption.md](encryption.md) for the full
write-up. Beacon changes appear in `tail --json` as `beacon_set` / `beacon_cleared`
events (metadata only — never the status text).

## Two-Way Bridge — closing the alert→ack→resolve loop (`netherchat bridge`)

Inbound already works: an alert fires a webhook, a `[[route]]` rule spawns a war
room, the on-call joins. The loop closes here. When someone acks in the room, the
bridge fires a templated callback to **your own** system (PagerDuty, Alertmanager,
Slack, an ITSM webhook) so one `/ack` actually resolves the page — and the callback
carries the **original in-room Ed25519 signature**, so the receiver can verify the
action came from a real room member, not a forged `curl`.

```bash
netherchat bridge --room ops \
  --on decision,ack \
  --post http://localhost:9999/callback \
  --json
```

The honesty constraint *is* the feature. The relay is **blind** — it cannot read a
decision to act on it — so the bridge can't be a server-side component. It joins as
an ordinary **decrypting member**, decrypts the events it subscribes to, and fires
callbacks **from the edge**. That is exactly why provenance works: the signature
comes from the in-room frame, not from a server's say-so.

```
--room      room to join and watch (required)
--on        event types to fire on: decision, action, ack, seal, vanish, scuttle
            (default: decision,action,ack)
--post      URL to POST callbacks to (required) — YOUR system; Astralis makes no
            outbound calls on your behalf
--template  path to a Go text/template for the POST body (default: built-in JSON)
--name      display name in the room (default: bridge)
--identity  identity file (generated if not found)
--json      emit an ndjson stream of bridge events to stdout
```

### Ephemerality guard (by design, not a limitation)

> **Callbacks are fire-and-forget with in-memory retry only** (bounded exponential
> backoff: 1s, 2s, 4s — one attempt plus three retries). **If the bridge restarts,
> pending callbacks are lost.** This is intentional: a durable on-disk queue would
> re-introduce persistence and violate Netherchat's zero-persistence constraint. For
> reliable delivery, run the bridge on stable infrastructure and make the receiver
> **idempotent**.

### Callback headers

Every POST carries:

| Header | Value |
|---|---|
| `Content-Type` | `application/json` |
| `X-Netherchat-Room` | the room name |
| `X-Netherchat-Event` | `decision` / `action` / `ack` / `seal` / `vanish` / `scuttle` |
| `X-Netherchat-Actor` | the actor's display name |
| `X-Netherchat-Fpr` | the actor's Ed25519 fingerprint (`SHA256:…`) |
| `X-Netherchat-Sig` | base64 of the **original** Ed25519 signature from the event |
| `X-Netherchat-Ts` | RFC3339 timestamp |

`X-Netherchat-Fpr` and `X-Netherchat-Sig` are present for the per-event-signed types
(`decision`, `action`, `ack`) — the default `--on` set. `vanish` and `scuttle` travel
as **unsigned relay control frames**, so they carry no per-event signature; `seal` is
multi-party co-signed and has no single forwardable signature. Those events fire the
callback (with `--on` opt-in) but omit the `Sig`/`Fpr` headers.

### POST body template

Without `--template`, the body is this built-in JSON (rendered injection-safe — a
decision or tag containing a quote still yields valid JSON):

```json
{
  "room":      "ops",
  "event":     "ack",
  "actor":     "alice",
  "actor_fpr": "SHA256:…",
  "text":      "drain-complete",
  "ts":        "2026-06-10T03:14:22Z",
  "sig":       "<base64 Ed25519 sig>"
}
```

A custom Go `text/template` (`--template pd-resolve.tmpl`) has these variables:

| Variable | Meaning |
|---|---|
| `.Room` | room name |
| `.Event` | event type |
| `.Actor` | actor display name |
| `.ActorFpr` | actor Ed25519 fingerprint |
| `.Text` | human description — ack: the tag · decision: the text · action: `@handle: text` · seal: `room sealed, N decisions recorded` · vanish: `room keys rotated by @actor` · scuttle: `room scuttled, reason: <reason>` |
| `.Ts` | RFC3339 timestamp |
| `.Sig` | base64 of the original Ed25519 signature |
| `.Raw` | the raw decrypted event JSON (for advanced templates) |

`.RoomSecret` is deliberately **not** a variable — key material can never be
exfiltrated through a template. A `{{json .Field}}` helper is available so custom
templates can embed any value as a valid JSON literal.

### Example use cases

```bash
# Resolve a PagerDuty incident when someone acks
netherchat bridge --room ops --on ack \
  --post https://events.pagerduty.com/v2/enqueue --template pd-resolve.tmpl

# Silence an Alertmanager alert on a decision
netherchat bridge --room ops --on decision \
  --post http://alertmanager:9093/api/v2/silences --template silence.tmpl

# Post status to Slack from the encrypted war room (not the other way around)
netherchat bridge --room ops --on decision,ack \
  --post https://hooks.slack.com/services/... --template slack.tmpl

# Generic webhook (CI, monitoring, ITSM)
netherchat bridge --room ops --on decision,action,ack,seal \
  --post https://your-system.example.com/netherchat-events
```

### Verifying provenance on the receiver

The `X-Netherchat-Sig` header proves the callback came from a real room member:

1. Fetch the actor's public key — `github.com/<actor>.keys`, or the `[[trust]]`
   pinning in `netherchat.toml`.
2. Verify the Ed25519 signature against the original signing bytes (the canonical
   format in `protocol/signing.go`: room id, sender id, epoch, nonce, ciphertext).
3. If valid, the callback genuinely came from a member who held the room key at the
   time of the event — cryptographically attributable, not just "netherchat says so."

The bridge is itself a decrypting member, so it verifies each event's signature
*before* firing; the header forwards that same signature so the receiver can
re-verify against the actor's key.

### `bridge --json` output

`--json` emits one ndjson line per delivered callback (the human default prints
`[03:14:22] ack:drain-complete fired → https://… (200 OK)` and per-retry progress):

```json
{"v":1,"ts":"…","type":"bridge_fired","room":"ops","event":"ack","actor":"alice","fpr":"SHA256:…","url":"https://…","status":200,"retries":0}
{"v":1,"ts":"…","type":"bridge_failed","room":"ops","event":"ack","actor":"alice","fpr":"SHA256:…","url":"https://…","error":"connection refused","retries":3}
```

## Keys

| Key | Action |
|---|---|
| `Enter` | Send the message / run the command |
| `Tab` | Accept the highlighted autocomplete suggestion |
| `↑` / `↓` | Move the suggestion selection, or scroll history when there are none |
| `PgUp` / `PgDn`, mouse wheel | Scroll history |
| `Ctrl+N` / `Ctrl+P` | Next / previous room |
| click a room | Focus it |
| `Esc` / `Ctrl+C` | Quit |

## Non-interactive CLI

For scripts and pipelines (plain text, no styling):

```bash
# Send one message (or pipe it via stdin)
echo "build failed on main" | netherchat send ops --server ws://chat.example.com
netherchat send ops "deploy complete" --server ws://chat.example.com

# Stream a room's decrypted messages to stdout
netherchat tail alerts --server ws://chat.example.com | grep CRITICAL | tee crit.log
```

Common flags: `--server <url>`, `--name <you>`, `--identity <path>`, `--invite <token>`.

> `send` and `tail` join the room as ordinary E2E members, so they can only
> exchange messages while at least one other member is present to share the room
> key. For unattended, no-key injection from external systems, use an inbound
> [webhook](self-hosting.md) instead (server-origin plaintext).

## Machine-readable output (`--json`)

Netherchat composes like `gh` or `kubectl`: most subcommands speak JSON on stdout
when `--json` is passed (errors go to stderr as `{"error":"…"}`; exit 0 on
success). Output is always valid JSON — never mixed with human text.

```bash
netherchat version --json     # {"version":"…","protocol_version":3,"go_version":"…","platform":"…"}
netherchat whoami  --json     # {"identity":{…},"server":"…","room":"…","encryption":"…",…}
netherchat rooms   --json     # [{"name":"ops","members":2,"invite_only":false,"ttl_seconds":0,"webhook":true},…]
netherchat agent   --room ops --allow runbook.toml --json   # ndjson exec_request/exec_result stream
```

### `tail --json` — the structured event stream

`netherchat tail #room --json` emits a **versioned, metadata-only** newline-delimited
JSON event stream (§1.7) — an auditable incident timeline you can pipe into `jq`,
Vector, or Loki with **zero message-body leakage**:

```bash
netherchat tail ops --json | jq -c '{ts,type,actor}'
```

Every event carries `v` (the schema version — a stability contract bumped only on
a breaking change) and an RFC3339-UTC `ts`. A `message` event reports `signed`,
`verified`, `body_len`, and `body_hash` (`sha256:<hex>` of the plaintext) — but
**never the body** unless you add `--include-bodies` (an explicit opt-in that
creates a local content record). Event types: `join`, `leave`, `message`, `ack`,
`handoff`, `route_fired`, `verify`, `vanish`, `scuttle`, `file_offer`,
`file_complete`, `exec_request`, `exec_result`, `action_request`,
`action_approval`, `action_executed`, `action_vetoed`, `action_expired`,
`key_ready`, `error`, `disconnect`. The five `action_*` events (§1.3) record the
full lifecycle of a two-person-rule request — who proposed it, each approval with
the running `quorum_current`/`quorum_needed`, and whether it executed, was vetoed,
or expired — as a metadata-only audit trail (never the action's raw command).

`netherchat schema` prints the JSON Schema (draft-07) for v1 events so downstream
tools can validate the stream.
