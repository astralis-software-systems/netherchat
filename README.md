<div align="center">

# Netherchat

**Messaging that lives below the surface**

Self-hostable, end-to-end encrypted, real-time messaging — built for developers first.
A blind-relay server that *cannot read your messages*, and a terminal client that
doesn't look like it's from 1998.

*by [Astralis Software Systems](https://github.com/salehkreiner)*

</div>

---

> **Status: M3.** A full terminal client: a multi-room sidebar with unread
> counts, a member list, 8 instantly-switchable themes, slash commands with
> autocomplete, inline code rendering, and invite QR codes. The server adds
> config-as-code (`netherchat.toml`), inbound webhooks, one-time invite tokens,
> ephemeral room TTLs, `/vanish` key rotation, bring-your-own-key identity
> (SSH / age / ssh-agent) with `/whois` verification, edge-executed `/exec` via
> `netherchat agent`, per-connection rate limiting, and optional local
> persistence. Plus Unix-friendly
> `send`/`tail` for pipelines. The web client is the next milestone. See
> [`ARCHITECTURE_DECISION.md`](ARCHITECTURE_DECISION.md) for the founding design,
> [`PROTOCOL.md`](PROTOCOL.md) for the wire format,
> [`docs/commands.md`](docs/commands.md) for commands/keys,
> [`docs/encryption.md`](docs/encryption.md) for the honest crypto story,
> [`docs/self-hosting.md`](docs/self-hosting.md) to run a server, and
> [`docs/sealed-record-library.md`](docs/sealed-record-library.md) to create and
> verify sealed records from your own program (no relay, no network).

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

## Install

**Client — macOS / Linux:**

```bash
curl -fsSL https://netherchat.com/install | bash
# pin a version:
curl -fsSL https://netherchat.com/install | bash -s -- --version 0.2.0
```

**Client — Windows (PowerShell):**

```powershell
irm https://netherchat.com/install.ps1 | iex
```

**Server — Docker:**

```bash
docker run -p 3000:3000 salkreiner/netherchat
# or, for a team:
docker compose up -d
```

> The installers pull pre-built binaries from GitHub Releases, so they work once
> the first version is tagged. Until then (or any time), build from source below.

## From source

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
identity is the Ed25519 key you already have — ssh-agent, `~/.ssh/id_ed25519`, or
an age key (else a generated one in your per-user config dir). `/whoami` shows a
fingerprint in exact `ssh-keygen -lf` format; `/whois @peer` verifies a coworker
against their published `github.com/<user>.keys`. The relay never holds a private
key, and **there is no recovery if you lose yours** — that's by design.

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
