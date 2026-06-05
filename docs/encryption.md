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
  away (on `/vanish`) and old keys deleted, prior messages can't be recovered.
  This is **not** per-message forward secrecy — within one epoch all messages
  share a key. That is weaker than Signal's Double Ratchet or MLS, by design for
  v1.
- ⚠️ **The group key-distribution protocol is custom** (over audited primitives).
  This is the main risk surface. It should get an **independent cryptographic
  review before any paid/cloud tier**. The migration target is **MLS (RFC 9420)**;
  the epoch model is shaped to make that swap an implementation change behind a
  stable interface, negotiated via the protocol version.
- ⚠️ **Metadata is not hidden.** The server sees who is in which room, message
  sizes, and timing. End-to-end encryption protects content, not metadata.

## What is NOT end-to-end encrypted

Some messages originate **at the server** in plaintext and therefore are not E2E.
They are clearly marked in the UI ("plaintext") so no one mistakes them:

- **Inbound webhooks** (`POST /webhook/<room>`): the external system sends
  plaintext; the server composes the message. The server can read these by
  definition.
- **`/exec` output**: produced on the server.

If you need a bot/integration message to be E2E, it must come from a real client
that holds the room key — not from a webhook.

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
