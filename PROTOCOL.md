# PROTOCOL.md — Netherchat wire protocol

**Protocol version: 2** · Status: M3 (subject to change before 1.0)

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
| `server_msg`    | server → clients               | **plaintext** server-origin message (webhook/system/exec) — NOT E2E |
| `control`       | client → server → room         | room control action: `vanish`, `ttl` |
| `exec_request`  | client → server                | run an allow-listed command |
| `exec_result`   | server → client                | command output |
| `invite_request`| client → server                | mint a one-time invite token for the room |
| `invite_result` | server → client                | the minted token |

`hello` additionally carries an optional `invite_token` (required to join an
invite-only room), and `welcome` carries a `policy` describing the room
(`invite_only`, `exec_enabled`, `webhook`, `ttl_seconds`).

## 3. Identity

Each client has a long-term identity, generated once and stored locally:

- **Ed25519** keypair — signs messages; its SHA-256 is the displayed *fingerprint*.
- **X25519** keypair — receives wrapped room keys.

Only public keys ever leave the client. There is no escrow and no recovery.

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
  "signature":  "<base64 ed25519>"
}
```

- **Encryption:** `XChaCha20-Poly1305` under the room key. The 24-byte nonce is
  random per message (XChaCha's extended nonce makes this safe). The AEAD
  additional data is the 8-byte big-endian epoch.
- **Authentication:** the sender signs `SigningBytes` (below) with its Ed25519 key.
  Recipients look up the sender's public key by `from_id` (from the member list)
  and **verify the signature before decrypting**.
- The server fans the frame out verbatim to every other member. It stamps `from_id`
  with the connection's real ID, so a client cannot spoof another member at the
  routing layer; signature verification enforces authenticity end-to-end.

### `SigningBytes`

The signature covers an injective, length-prefixed encoding (each field is an
8-byte big-endian length followed by its bytes; the epoch is 8 bytes big-endian):

```
field("netherchat/msg/v1") || field(from_id) || epoch_be64 || field(nonce) || field(ciphertext)
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
  at the server (`kind` is `webhook`, `system`, or `exec`). It is **not E2E** —
  the server composes it, so the server can read it. Clients render it with a
  clear "plaintext" marker. Inbound webhooks (`POST /webhook/<room>` with the
  room's configured token) and `/exec` output arrive this way.
- **`control`** `{action, by, by_name, ttl_seconds}` — relayed to the room.
  `action: "vanish"` tells members to clear history and ratchet the room key
  forward (deterministic HKDF — no key exchange). `action: "ttl"` sets a
  client-side message display TTL.
- **`exec_request`** `{command}` / **`exec_result`** `{command, allowed, output,
  error}` — run an allow-listed command. The server runs it only if the exact
  command string is in `[exec].allow` and the room has `exec_enabled`; there is no
  shell and arguments are not interpreted. Every attempt is audit-logged.
- **`invite_request`** / **`invite_result`** `{room, token, expires}` — a current
  member mints a one-time token. Joining an `invite_only` room requires a valid
  token in `hello.invite_token`; the first member into an empty invite-only room
  bootstraps it.

## 10. Versioning

`protocol_version` is exchanged in `hello`/`welcome`. Incompatible changes bump it.
A future MLS-based key-agreement scheme can be negotiated alongside the NaCl
scheme during migration.
