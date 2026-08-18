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
  `GET /rooms`. `/rooms` returns `{"rooms":[{name, members, invite_only,
  ttl_seconds, webhook}, …]}` — room names, live member counts, and static
  policy, never content. (`netherchat rooms` consumes it.)
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
  so the new client can verify their signatures and identify a key distributor. It
  is **always an array**: `[]` when the room was empty, never `null`. The
  distinction is not cosmetic — the empty-room case is exactly the frame that also
  carries `you_are_first`, so a client that cannot iterate the field cannot mint
  epoch 0, and Go relays before this was stated marshalled the empty case as
  `null`. Clients that must interoperate with such a relay should read the field
  as "absent or null means empty".

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

## 15. Privileged-action quorum (Two-Person Rule, §1.3)

Additive over v3 (no version bump). A dangerous action — `scuttle`, `break_glass`,
or a signed `runbook` — can require *N-of-M* independent Ed25519 approvals before it
fires. The gate is enforced **client-side over a request hash**; the relay routes
the three frames as opaque `Message` envelopes (sealed under the room key,
Ed25519-signed) exactly like `ack`/`roster_*`, and never sees the action, its
parameters, or the approval count. It **cannot bypass or be coerced to bypass the
gate** — there is no server code path that runs the action.

Three opcodes, each carrying a `Message`:

- `action_request` — the initiator proposes the action.
- `action_approval` — an authorized member co-signs the request.
- `action_veto` — any member cancels the request immediately.

The end-to-end-encrypted plaintexts (inside the `Message.ciphertext`):

```json
// action_request
{ "request_id": "a3f9c1d2e4b5a6f7",   // random 16-hex; correlates everything
  "action": "scuttle",                 // scuttle | break_glass | runbook
  "params_hash": "<hex sha256 of params>",
  "params": "room=ops, reason=manual", // canonical, human-readable; NOT a raw command
  "requester_fpr": "SHA256:…",         // must equal the signed Message's sender
  "room": "ops",
  "quorum_needed": 2,                  // distinct endorsers required
  "expires_unix": 1749230460,          // discarded ~60s after issue
  "nonce": "…" }                       // random hex, bound into every approval

// action_approval
{ "request_id": "a3f9c1d2e4b5a6f7",
  "params_hash": "<same hex sha256>",  // the approver verifies it matches the request
  "approver_fpr": "SHA256:…",          // must equal the signed Message's sender
  "sig": "<base64 Ed25519>" }          // over ActionApprovalSigningBytes (below)

// action_veto
{ "request_id": "a3f9c1d2e4b5a6f7", "vetoer_fpr": "SHA256:…", "reason": "wrong room" }
```

**Counting.** The requester's signed request is **endorser #1**. An action fires
when the number of distinct endorsers — the requester plus distinct approvers —
reaches `quorum_needed`. So `quorum = 2` is the classic two-person rule (requester
+ one independent approver), and a single actor can never reach quorum alone. The
initiator cannot also approve their own request; each approver counts once
(deduplicated by fingerprint).

**Approval signature.** `sig` covers a domain-separated, length-prefixed preimage
that binds the request, the exact action, the approver, and the request nonce:

```
ActionApprovalSigningBytes =
  field("netherchat/action-approval/v1")
    || field(request_id) || field(params_hash) || field(approver_fpr) || field(nonce)
```

so an approval of `scuttle room=ops` cannot be replayed to endorse
`scuttle room=prod` (different `params_hash`), attributed to another approver
(their fingerprint is in the preimage), or replayed against a different request
(the nonce differs). Every client — the initiator collecting quorum and any passive
`tail` observer — verifies each approval independently and reaches the threshold on
its own; only the initiator additionally **performs** the action. Approvals that
arrive after execution or a veto are discarded; quorum state is in memory only.

The policy lives in `netherchat.toml` (`[action.<name>] quorum = N`) and is read by
the connecting client and the edge agent — never by the relay. `quorum = 1` is
single-actor (the default); `quorum = 0` disables the action.

## 16. Sealed-record v2 (signature meanings, typed kinds, traceability links)

Additive over the v1 sealed record (no relay change; the relay never sees record
content). Every artifact produced before v2 keeps verifying byte-for-byte: a
record, entry, or seal signature uses its v1 layout **unless** it carries a v2
field, in which case it uses a distinct, domain-separated v2 layout. The chosen
layout is a pure function of the content, so any tampering that adds or removes a
v2 field flips the layout and breaks the signature. `record.json` carries
`"netherchat_record": "v2"` when any v2 feature is used, else `"v1"`; verifiers
accept both.

**Typed kinds & traceability links (record entry v2).** An entry may carry a
consumer-defined typed kind (`kind: "typed"` + an opaque `schema` tag and optional
`schema_version`) and/or one or more `links` (`{ "hash": "<hex>", "rel": "<label>" }`)
referencing prior records to form a verifiable lineage. Both the tag and the links
are part of the signed bytes; the library assigns them **no** meaning — domain
semantics are the consumer's. A built-in kind must not carry a schema tag, and a
typed entry must carry a non-empty tag.

```
RecordSigningBytesV2 =
  field("netherchat/record/v2")
    || seq_be64 || ts_be64
    || field(author_id) || field(kind) || field(actionee) || field(body)
    || field(schema) || field(schema_version)
    || nlinks_be64 || { field(link_hash[i]) || field(link_rel[i]) }…
    || prev_hash[32]
```

**Electronic-signature meaning (seal v2 & action-approval v2).** A seal
co-signature or a two-person-rule approval may declare a machine-readable
**meaning** (`authored` | `reviewed` | `approved` | `rejected` — extensible),
the signer's printed **name**, and a UTC **timestamp**, all bound into the signed
preimage so none can be altered after the fact. The wire bodies gain optional
fields (`SealAckBody.{meaning,signer_name,signed_at}`,
`ActionApprovalBody.{meaning,name,signed_at}`); when present the v2 preimage is
signed, when absent the bare v1 preimage is. A sealed record stores each
meaning-bearing signer's declaration under `endorsements` (fingerprint →
`{meaning, name, signed_at}`); a signer without an entry there co-signed the bare
v1 head.

```
SealSigningBytesV2 =
  field("netherchat/seal/v2") || field(room)
    || field(meaning) || field(signer_name) || field(signed_at) || head_hash[32]

ActionApprovalSigningBytesV2 =
  field("netherchat/action-approval/v2")
    || field(request_id) || field(params_hash) || field(approver_fpr) || field(nonce)
    || field(meaning) || field(name) || field(signed_at)
```

The initiator-cannot-approve-their-own-request rule is unchanged (the approver
fingerprint is still bound into the approval preimage).
