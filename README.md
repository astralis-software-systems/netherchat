<div align="center">

# Netherchat

**Tamper-evident records and encrypted coordination**

Two capabilities over one cryptographic core.

*by [Astralis Software Systems](https://github.com/salehkreiner)*

</div>

---

## Sealed records

Ed25519 signatures over SHA-256 hash chains — append-only, content-addressed, and
**verifiable offline**: no relay, no network, and no trust in whoever is doing the
verifying. Importable on its own:

```go
import "github.com/salehkreiner/netherchat/sealedrecord"
```

Records carry multi-party approval proofs. Each approval is an Ed25519 signature over a
preimage binding the proposal id, the artifact hash, the approver's fingerprint, and — in
v2 — the role the approver signed as. Because the fingerprint is inside the signed bytes,
one device cannot forge another person's approval.

Verification returns the set of **distinct, cryptographically verified approvers**,
excluding both the entry author and the recorded proposer — so a proposer cannot approve
their own artifact. The library surfaces that verified set as evidence and imposes no
quorum minimum; required roles, thresholds, and distinctness are the consumer's policy.

See [`docs/sealed-record-library.md`](docs/sealed-record-library.md) to produce and verify
records from your own program with no relay running.

## Encrypted messaging

A self-hostable blind relay and a terminal client. The relay routes opaque ciphertext and
sealed key blobs; it holds no keys, decrypts nothing, and makes zero outbound calls.

**The relay cannot read your messages, and that is a property of the build graph.** The
encryption lives in `tui/internal/crypto`, which Go's internal-package rule makes
unreachable from the server binary, and CI fails if that ever changes
(`TestServerBinaryDoesNotLinkClientCrypto`). It is checkable by anyone who clones this
repo — not a marketing line.

Primitives: X25519, XChaCha20-Poly1305, Ed25519, HKDF. Pure Go, no cgo.
See [`docs/encryption.md`](docs/encryption.md) for the honest crypto story, including
what it does *not* claim.

> **Messaging client — milestone M3.** A full terminal client: a multi-room sidebar with
> unread counts, a member list, 8 instantly-switchable themes, slash commands with
> autocomplete, inline code rendering, and invite QR codes. The server adds
> config-as-code (`netherchat.toml`), inbound webhooks, one-time invite tokens,
> ephemeral room TTLs, `/vanish` key rotation, bring-your-own-key identity
> (SSH / age / ssh-agent) with `/whois` verification, edge-executed `/exec` via
> `netherchat agent`, per-connection rate limiting, and optional local persistence.
> Plus Unix-friendly `send`/`tail` for pipelines. The web client is the next
> milestone. See
> [`ARCHITECTURE_DECISION.md`](ARCHITECTURE_DECISION.md) for the founding design,
> [`PROTOCOL.md`](PROTOCOL.md) for the wire format,
> [`docs/commands.md`](docs/commands.md) for commands/keys,
> [`docs/encryption.md`](docs/encryption.md) for the honest crypto story, and
> [`docs/self-hosting.md`](docs/self-hosting.md) to run a server.

## Install

Netherchat is **two artifacts, by design**: the endpoint **client** (`netherchat`)
you install everywhere, and the **relay** (`netherchat-server`) you provision only
where you self-host. The client is where all encryption happens and stays
featherweight; the relay is a blind router that holds no keys. Install the client to
talk; add the relay to host.

### The client

**macOS / Linux:**

```bash
curl -fsSL https://netherchat.com/install | bash
```

The unpinned form installs the latest release. Pass `--version <v>` to pin a specific
one, or `--with-server` to install the relay alongside the client (see below);
`--help` lists the rest.

**Windows (PowerShell):**

```powershell
irm https://netherchat.com/install.ps1 | iex
```

### The relay (self-hosting)

The relay binary (`netherchat-server`) ships in the **same release archive** as the
client. Provision it whichever way fits your deployment:

```bash
# Native, via the installer — installs netherchat-server from the archive already
# downloaded, no second fetch:
curl -fsSL https://netherchat.com/install | bash -s -- --with-server   # Linux / macOS
#   irm ... | iex   →   add -WithServer on Windows
# Container:
docker run -p 3000:3000 salkreiner/netherchat        # or, for a team: docker compose up -d
# From source:
go build -o bin/ ./cmd/netherchat-server
```

See [`docs/self-hosting.md`](docs/self-hosting.md) for the full deployment guide
(TLS, Tor, config-as-code).

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
