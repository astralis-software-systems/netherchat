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
| `/exec <action>` | Send a signed, E2E-encrypted request for a `netherchat agent` to run a runbook action on its own host. The relay never runs anything. See below. |
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
`verify`, `vanish`, `exec_request`, `exec_result`, `key_ready`, `error`,
`disconnect`.

`netherchat schema` prints the JSON Schema (draft-07) for v1 events so downstream
tools can validate the stream.
