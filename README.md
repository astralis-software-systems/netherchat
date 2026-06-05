<div align="center">

# Netherchat

**Messaging that lives below the surface**

Self-hostable, end-to-end encrypted, real-time messaging — built for developers first.
A blind-relay server that *cannot read your messages*, and a terminal client that
doesn't look like it's from 1998.

*by [Astralis Software Systems](https://github.com/salehkreiner)*

</div>

---

> **Status: M1.** Two terminal clients can exchange end-to-end-encrypted messages
> through the server. Nothing is persisted; the server only ever relays
> ciphertext. UI polish, themes, slash commands, webhooks, and the web client
> come in later milestones. See [`ARCHITECTURE_DECISION.md`](ARCHITECTURE_DECISION.md)
> for the founding design and [`PROTOCOL.md`](PROTOCOL.md) for the wire format.

## What's here

- **`cmd/netherchat-server`** — a WebSocket relay. It routes opaque ciphertext and
  sealed key blobs between clients. It holds no keys, decrypts nothing, persists
  nothing by default, and makes zero outbound calls.
- **`cmd/netherchat`** — the terminal client. All encryption happens here.
- **End-to-end encryption** built from pure-Go, audited primitives (X25519,
  XChaCha20-Poly1305, Ed25519, HKDF) — no cgo, so it cross-compiles trivially.

The encryption code lives under `tui/internal/crypto`, which Go's internal-package
rule makes **unreachable from the server**. "The server cannot read your messages"
is therefore a property of the build graph, verified in CI — not a marketing line.

## Quick start

Requires Go 1.26+ (and optionally [`just`](https://just.systems) for the dev tasks).

```bash
# 1. Build
just build            # or: go build -o bin/ ./cmd/...

# 2. Start the relay server
./bin/netherchat-server --addr :3000      # just server

# 3. In two more terminals, connect two clients to the same room
./bin/netherchat connect ws://localhost:3000 --room general --name alice
./bin/netherchat connect ws://localhost:3000 --room general --name bob
```

Type in either client and the message appears, decrypted, in the other. Your
identity key is generated on first run and stored in your per-user config dir
(`%AppData%\netherchat` / `~/.config/netherchat`). **There is no recovery if you
lose it** — that's by design.

Keys (TUI): `Enter` send · `PgUp`/`PgDn` or mouse wheel scroll · `Esc`/`Ctrl+C` quit.

## Develop

```bash
just dev            # run the server with hot reload (needs air)
just test           # full suite, including the M1 end-to-end acceptance test
just check-boundary # prove the server binary does not link the crypto package
just vet
```

## License

TBD.
