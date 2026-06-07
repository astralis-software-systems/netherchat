# PROTOCOL.md — Netherchat wire protocol

**Protocol version: 3** · Status: M3+ (subject to change before 1.0)

The server admits clients in `[2, 3]`. v3 adds room-bound, OPTIONAL per-message
Ed25519 signatures (§6) and out-of-band SAS verification (a purely client-side
feature; see docs/commands.md). A v2 message (no `sig`) is accepted as *unsigned*,
not rejected.

This document specifies the Netherchat wire protocol so that third-party clients
can be built. It reflects what is implemented today; the `protocol` Go package is
the source of truth, and this document tracks it.

A guiding invariant: **the server is a blind relay.** It routes frames between
clients and learns membership and timing metadata, but it never possesses a room
key and never sees plaintext. Everything below is designed around that.

---

## 1. Transport

- WebSocket. Clients connect to `GET /ws` (e.g. `wss://host/ws`). `ws://` is
  acceptable only for local development.
- Every WebSocket message is a single JSON-encoded **Envelope** (UTF-8 text frame).
- The server also exposes read-only REST endpoints: `GET /health`, `GET /version`,
  `GET /rooms`. `/rooms` returns only room names and member counts — never content.
- Per-message read limit: 1 MiB.

## 2. Envelope

Every frame is:

```json
{ "type": "<opcode>", "data": { ... } }
```

`type` selects the payload schema for `data`. Binary fields (keys, nonces,
ciphertext, signatures) are **standard base64 strings** (Go's `encoding/json`
encoding of `[]byte`).

### Opcodes

| `type`          | Direction                      | Purpose |
|-----------------|--------------------------------|---------|
| `hello`         | client → server                | first frame; announces identity + room |
| `welcome`       | server → client                | assigns an ID, lists current members |
| `member_joined` | server → clients               | a member entered |
| `member_left`   | server → clients               | a member disconnected |
| `key_request`   | server → one client            | asks the designated distributor to wrap the room key for a newcomer |
| `key_deliver`   | client → server → one client   | a wrapped room key, routed to its target |
| `msg`           | client → server → room         | an end-to-end-encrypted message |
| `error`         | server → client                | error notification |
| `server_msg`    | server → clients               | **plaintext** server-origin message (webhook/system) — NOT E2E |
| `control`       | client → server → room         | room control action: `vanish`, `ttl` |
| `exec_request`  | member → server → room         | E2E-signed edge-exec request (carries a `msg` envelope) |
| `exec_result`   | agent → server → room          | E2E-signed edge-exec result (carries a `msg` envelope) |
| `invite_request`| client → server                | mint a one-time invite token for the room |
| `invite_result` | server → client                | the minted token |
| `break_glass`        | client → server           | create an ephemeral war room + mint one-time join links |
| `break_glass_result` | server → client           | the new room name, deadline, host token, and per-invitee tokens |

`hello` additionally carries an optional `invite_token` (required to join an
invite-only room), and `welcome` carries a `policy` describing the room
(`invite_only`, `webhook`, `ttl_seconds`). There is no exec capability in the
policy: command execution is an edge concern, never a server policy (§9).

## 3. Identity (bring your own key)

Each client's identity is an **Ed25519** key it already has — an OpenSSH key file,
ssh-agent, an age seed, or (last resort) a generated key. Load precedence:
`--identity` → `SSH_AUTH_SOCK` → `~/.ssh/id_ed25519` → `~/.ssh/id_ed25519_sk` →
`~/.config/netherchat/identity.json` → generate.

- **Ed25519** key — signs messages; the *fingerprint* is `ssh.FingerprintSHA256`
  over the SSH wire encoding, i.e. **byte-identical to `ssh-keygen -lf`**
  (`SHA256:<base64>`), so it can be compared against a published key.
- **X25519** key — receives wrapped room keys. It is **derived from the Ed25519
  key** (RFC 8032 → RFC 7748 conversion) for file/generated keys; for ssh-agent
  keys (which cannot perform X25519) it is derived from a deterministic agent
  signature over a fixed domain string, so the SSH private key never leaves the
  agent.

Only public keys ever leave the client. The relay never holds a private key and
cannot impersonate anyone. There is no escrow and no recovery.

Trust is pinned **client-side** in `netherchat.toml` (`[[trust]]` with `handle`,
optional `fpr`, optional `keys_url`) and resolved by `/whois` — the relay never
participates in any trust decision.

## 4. Handshake

```
client                          server
  │  hello{ver,room,name,idKey,kxKey} │
  ├──────────────────────────────────►│   (server assigns a member ID)
  │  welcome{your_id,members,first}    │
  │◄──────────────────────────────────┤
```

- `hello.protocol_version` must equal `1` or the server replies `error` and closes.
- `welcome.you_are_first` is `true` iff the room was empty. That client MUST mint
  the epoch-0 room key locally. Otherwise the client waits for a `key_deliver`.
- `welcome.members` lists the members already present (id, name, both public keys),
  so the new client can verify their signatures and identify a key distributor.

The server then broadcasts `member_joined{member}` to the existing members.

## 5. Room keys and epochs

A room has a 32-byte symmetric **room key** for the current **epoch**. Epoch 0 is
minted by the first member. (Rotation on membership change / `/vanish` — advancing
the epoch via an HKDF ratchet and deleting the old key — is specified by the crypto
layer and lands in a later milestone.)

### Distribution (server stays blind)

When a member joins a non-empty room, the server sends `key_request{for_member}` to
exactly one existing member — the **designated distributor**, defined as the oldest
current member. That member wraps the current room key for the newcomer and returns:

```json
"key_deliver": {
  "to_id":       "<newcomer id>",
  "from_id":     "<distributor id>",   // stamped authoritatively by the server
  "epoch":       0,
  "nonce":       "<base64 24 bytes>",
  "wrapped_key": "<base64 nacl/box>"
}
```

The wrap is `nacl/box` (authenticated X25519 + XSalsa20-Poly1305): sealed to the
newcomer's X25519 public key, authenticated by the distributor's X25519 private
key. The server routes by `to_id` but cannot open the box. The recipient verifies
it came from `from_id`'s X25519 key, yielding the shared room key.

## 6. Messages

```json
"msg": {
  "from_id":    "<sender id>",          // stamped authoritatively by the server
  "epoch":      0,
  "nonce":      "<base64 24 bytes>",
  "ciphertext": "<base64>",
  "sig":        "<base64 ed25519>"      // OPTIONAL (omitempty); absent = unsigned
}
```

- **Encryption:** `XChaCha20-Poly1305` under the room key. The 24-byte nonce is
  random per message (XChaCha's extended nonce makes this safe). The AEAD
  additional data is the 8-byte big-endian epoch.
- **Authentication (v3, §3.3):** the sender signs `SigningBytes` (below) with its
  Ed25519 key. Recipients look up the sender's public key by `from_id` and, **if a
  `sig` is present, verify it before decrypting** — an invalid signature rejects
  the message (its body is never shown). A message with **no `sig` is accepted as
  unsigned** (a pre-v3 sender used a different field), not rejected. Clients badge
  messages accordingly (signed / signed+verified / unsigned).
- The server fans the frame out verbatim to every other member. It stamps `from_id`
  with the connection's real ID, so a client cannot spoof another member at the
  routing layer; signature verification enforces authenticity end-to-end.
- `exec_request` / `exec_result` are the same `msg` envelope and are signed the
  same way; an agent ignores an unsigned exec request.

### `SigningBytes`

The signature covers an injective, length-prefixed encoding (each field is an
8-byte big-endian length followed by its bytes; the epoch is 8 bytes big-endian).
Binding `room_id` (added in v3) prevents a captured ciphertext from being replayed
into a different room:

```
field("netherchat/msg/v1") || field(room_id) || field(from_id) || epoch_be64 || field(nonce) || field(ciphertext)
```

Binding `from_id` and `epoch` prevents a captured ciphertext from being replayed
under a different identity or epoch.

## 7. Cryptographic primitives

| Purpose                | Primitive                              |
|------------------------|----------------------------------------|
| Identity signatures    | Ed25519                                |
| Key agreement / wrap   | X25519 + XSalsa20-Poly1305 (`nacl/box`)|
| Message encryption     | XChaCha20-Poly1305                     |
| Epoch ratchet (/vanish)| HKDF-SHA256                            |
| Fingerprint            | SHA-256 of the Ed25519 public key      |

## 8. Security properties & limits (honest)

- **Server-blind content.** Room keys are never sent to the server; messages are
  only ever ciphertext to it; default zero persistence means nothing is retained.
- **Forward secrecy** is provided at **epoch granularity**: `/vanish` ratchets the
  room key forward and deletes the old one — **not** per-message. This is weaker
  than Signal's Double Ratchet or MLS, by design for v1.
- The group **key-distribution protocol is custom** (over audited primitives). It
  is the primary risk surface and is slated for external review before any paid
  tier. The migration target is **MLS (RFC 9420)**; the epoch model here is shaped
  to make that swap an implementation change behind a stable interface, negotiated
  via `protocol_version`.
- **Metadata is not hidden.** The server sees room membership, message sizes, and
  timing. End-to-end encryption protects content, not metadata.

## 9. v2 message types

These are additive; the connection==room model is unchanged.

- **`server_msg`** `{kind, from, text, at}` — a plaintext message that originates
  at the server (`kind` is `webhook` or `system`). It is **not E2E** — the server
  composes it, so the server can read it. Clients render it with a clear
  "plaintext" marker. Inbound webhooks (`POST /webhook/<room>` with the room's
  configured token) arrive this way.
- **`control`** `{action, by, by_name, ttl_seconds}` — relayed to the room.
  `action: "vanish"` tells members to clear history and ratchet the room key
  forward (deterministic HKDF — no key exchange). `action: "ttl"` sets a
  client-side message display TTL.
- **`exec_request`** / **`exec_result`** — **edge execution** (the relay never
  runs anything). Both carry a `msg` envelope: the plaintext sealed under the room
  key is `{id, cmd}` for a request and `{id, cmd, allowed, exit_code, output}` for
  a result. A member's `/exec <cmd>` seals and signs a request; a `netherchat
  agent` on the operator's own host decrypts it, matches `cmd` against its local
  runbook allowlist (mapping it to a fixed command line — no shell, no
  caller-supplied args), runs it with a timeout, and seals + signs a result back.
  Every attempt is logged locally on the agent host. The relay sees only
  ciphertext and fans these out exactly like `msg`.
- **`invite_request`** / **`invite_result`** `{room, token, expires}` — a current
  member mints a one-time token. Joining an `invite_only` room requires a valid
  token in `hello.invite_token`; the first member into an empty invite-only room
  bootstraps it.

## 10. Versioning

`protocol_version` is exchanged in `hello`/`welcome`. The server admits any
client in `[MinVersion, Version]` (currently `[2, 3]`); additive changes widen
that window rather than hard-breaking older clients. v3 added room-bound optional
per-message signatures (§6). A future MLS-based key-agreement scheme can be
negotiated alongside the NaCl scheme during migration.

## 11. Break-glass war rooms

Additive over v2 (no version bump — older clients simply never send `break_glass`).
A connected member can stand up an **ephemeral, invite-only room** that vanishes at
a hard deadline — the incident war room.

```json
"break_glass": {
  "invitees":    ["alice", "bob"],   // one one-time link is minted per name (server caps the count)
  "ttl_seconds": 14400               // hard room lifetime; server clamps to [60, 604800]
}
```

The server creates a room with a generated, unguessable name (`war-<hex>`), marks
it invite-only with an absolute deadline of now + TTL, and replies to the
requester only:

```json
"break_glass_result": {
  "room":        "war-3f9a2b71",
  "ttl_seconds": 14400,
  "expires":     1749230400,          // unix seconds (hard deadline)
  "host_token":  "<one-time token>",  // for the creator to join without racing invitees for the bootstrap slot
  "invites": [
    { "name": "alice", "token": "<one-time token>" },
    { "name": "bob",   "token": "<one-time token>" }
  ]
}
```

Each token is a normal one-time invite (§9) scoped to the new room and expiring
with it. Clients embed them in `/join?room=<room>&token=<token>` links for the
browser join client. Joining is the ordinary invite-only flow: the room is
admitted via `hello.invite_token`, and `welcome.policy` reports `invite_only:true`
with `ttl_seconds` carrying the **remaining** lifetime. When the deadline passes
the server closes the room — every member receives a plaintext `server_msg`
(kind `system`) and is disconnected. Nothing about the room is persisted.

Ephemeral rooms are blind-relayed exactly like any other: the server holds only
the room name, deadline, and routing metadata — never a key or any plaintext.
