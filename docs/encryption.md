# Encryption

This document states what Netherchat's encryption does and — just as
importantly — what it does not. No overclaiming. See
[`ARCHITECTURE_DECISION.md`](../ARCHITECTURE_DECISION.md) §3 for the reasoning and
[`PROTOCOL.md`](../PROTOCOL.md) for the wire format.

## The one non-negotiable

**The server cannot read message content.** It is a blind relay: it routes
ciphertext and sealed key blobs and never possesses a room key. This is enforced
at the build-graph level — the server binary does not link the client crypto
package (`tui/internal/crypto`), and CI fails if it ever does. "We cannot read
your messages" is a property of the code, not a marketing line.

## Primitives (v1)

All pure Go, no cgo, so the static binary and trivial cross-compilation survive:

| Purpose | Primitive |
|---|---|
| Identity / signatures / fingerprint | Ed25519 |
| Key agreement & room-key wrapping | X25519 + XSalsa20-Poly1305 (`nacl/box`) |
| Message encryption | XChaCha20-Poly1305 (random 24-byte nonce) |
| Forward-secret epoch ratchet | HKDF-SHA256 |

## How it works

- **Identity.** On first run each client generates an Ed25519 keypair (signing +
  fingerprint) and an X25519 keypair (key agreement), stored locally with `0600`
  permissions. Private keys never leave the device. **There is no escrow and no
  recovery — lose the key file and you lose access. By design.**
- **Room keys & epochs.** A room has a 32-byte symmetric key for the current
  epoch. The first member mints epoch 0. Messages are sealed under it with
  XChaCha20-Poly1305 and signed with the sender's Ed25519 key; recipients verify
  the signature before decrypting.
- **Key distribution.** When a member joins, one existing member (the oldest)
  wraps the current room key for the newcomer's X25519 key with `nacl/box` and
  sends it through the server. The server routes the sealed blob but cannot open
  it.
- **`/vanish`.** Advances the room key by one HKDF step and deletes the old one;
  every member applies the same deterministic ratchet, so no re-keying round-trip
  is needed. Messages from before the vanish become undecryptable.

## What you get — and the limits (honest)

- ✅ **Server-blind content**, as above.
- ✅ **Forward secrecy at epoch granularity.** Once an epoch's key is ratcheted
  away (on `/vanish`, or when a room **auto-scuttles** — §1.6) and old keys
  deleted, prior messages can't be recovered. This is **not** per-message forward
  secrecy — within one epoch all messages share a key. That is weaker than
  Signal's Double Ratchet or MLS, by design for v1.
- ⚠️ **The group key-distribution protocol is custom** (over audited primitives).
  This is the main risk surface. It should get an **independent cryptographic
  review before any paid/cloud tier**. The migration target is **MLS (RFC 9420)**;
  the epoch model is shaped to make that swap an implementation change behind a
  stable interface, negotiated via the protocol version.
- ⚠️ **Metadata is not hidden.** The server sees who is in which room, message
  sizes, and timing. End-to-end encryption protects content, not metadata.

## Relay authentication: the `.onion` address is the relay's key (`--tor`)

The end-to-end crypto above guarantees the *server* can't read you. A separate
question is: did you reach the *right* server, or a machine-in-the-middle?

When the relay runs as a **v3 onion service** (`netherchat-server --tor`, §1.5),
the `.onion` hostname is not a name an authority assigned — it is a Base32
encoding of the service's **Ed25519 public key**. The Tor rendezvous succeeds
only if the far end proves possession of the matching private key. So:

> **Connecting to the expected `.onion` address proves you reached the right
> relay.** The address authenticates the relay for free — no CA, no TLS
> certificate, and no trust-on-first-use.

This is why a war room stood up on a laptop behind CGNAT is safe to share by its
`.onion`: an attacker who cannot steal the relay's onion key cannot impersonate
the address. Treat the `.onion` string itself as the credential — distribute it
over a channel you trust (the same phone bridge you use for `/verify`, §1.2).

Two honest limits: this authenticates the **relay endpoint**, not the **people**
in the room (that is still BYO-key identity + out-of-band `/verify`); and an
*ephemeral* onion address (no `--tor-data-dir`) changes every run, so there is
nothing to pin across restarts — pin a stable address or verify it out of band.

## What is NOT end-to-end encrypted

Some messages originate **at the server** in plaintext and therefore are not E2E.
They are clearly marked in the UI ("plaintext") so no one mistakes them:

- **Inbound webhooks** (`POST /webhook/<room>`): the external system sends
  plaintext; the server composes the message. The server can read these by
  definition.
- **`/exec` output**: produced on the server.

If you need a bot/integration message to be E2E, it must come from a real client
that holds the room key — not from a webhook.

## Status Beacon — the one bounded exception to zero-persistence (§1.2)

The Status Beacon is the **single place the relay deliberately holds room state**.
It exists so out-of-band stakeholders (a VP, a support lead, a client) can watch a
live incident status without being put in the war room — where they would see the
raw chatter and widen the blast radius.

It is a deviation from "the relay stores nothing", so it is fenced in tightly:

- **One ciphertext blob per room.** `/beacon set` overwrites the previous value;
  there is no history.
- **Encrypted to a SEPARATE key.** The beacon is sealed under
  `beacon_key = HKDF-SHA256(room_key, "netherchat/beacon/v1")[:32]`, derived from
  but **distinct from** the message group key. A beacon reader who holds
  `beacon_key` can read the status and **nothing else** — it cannot decrypt room
  messages, which use `room_key` directly.
- **The relay still cannot read it.** Only ciphertext is PUT to the relay; the
  beacon key is never sent to the server. A `GET /beacon/<room>` returns opaque
  bytes — useless without the key.
- **Opt-in per room.** A room can have a beacon only if it sets `beacon_token` (or
  reuses its `webhook_token`). It is never default-on.
- **Explicitly TTL'd and auto-purged.** Each beacon has a lifetime (capped by
  `beacon_ttl`, hard max 24h) after which it auto-expires, and it is purged the
  moment the room scuttles or otherwise closes.

The reader's link, `…/beacon?room=<room>&key=<base64 beacon_key>`, carries the
beacon key (not the room key) and confers **no membership**: it is a read-only view
of one mutable line. The status and the room therefore have **different
cryptographic visibility boundaries** derived from the same session — the whole
point of the feature.

## Persistence and history (important caveat)

Persistence is **off by default**. When enabled, the server stores only
**ciphertext**. Because the server never holds a room key:

- Replaying history to someone joining a **still-active** room works — a current
  member's key decrypts it.
- History is **not recoverable** once a room fully empties, after a `/vanish`, or
  across a server restart — the key is gone, and the server cannot help. The
  stored ciphertext becomes undecryptable noise.

This is the unavoidable consequence of a zero-knowledge server. Durable,
restart-surviving history would require client-side key backup, which conflicts
with the no-escrow design and is out of scope for v1.

### Encrypted at rest (§7)

Even though stored rows are already E2E ciphertext, the surrounding envelope is
plaintext — routing metadata (sender id, epoch, room) and message *shape*. A
stolen disk should not yield even that. So when SQLite persistence is enabled,
**each row's payload is sealed at rest with AES-256-GCM** (stdlib, pure Go — no
cgo) under a key derived as:

```
key = HKDF-SHA256(secret, info = "netherchat/sqlite/v1")   // 32-byte AES-256 key
row = nonce(12) || AES-256-GCM(key, nonce, json(envelope))
```

The honest caveat is **where `secret` comes from.** The relay is a *blind* relay:
it holds no room key and no identity key, so — unlike a client-side store — the
at-rest key **cannot** be derived from a room/identity secret. It is necessarily
an **operator secret**, resolved in this order:

1. **`NETHERCHAT_PERSIST_KEY`** (environment, supplied out of band) — the only
   source that also protects against theft of the database file, because the key
   is not on the disk with it. **Recommended.**
2. **`[persistence] key`** in `netherchat.toml` — convenient but committed
   alongside config, so weaker.
3. An auto-generated **sidecar `<path>.key`** (`0600`) next to the database — zero
   config and survives restarts, but a thief who takes *both* files defeats it.
   The server logs a warning when it falls back to this.

So: at-rest encryption raises the bar for a stolen disk to "stolen disk **and**
the out-of-band key," but only if you use option 1. We state this plainly rather
than implying the sidecar fallback is as strong as it is convenient.
