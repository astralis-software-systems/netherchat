# Self-hosting Netherchat

Netherchat is a single static server binary (or a ~7 MB `FROM scratch` Docker
image). It is a **blind relay**: it routes end-to-end-encrypted frames between
clients, holds no keys, decrypts nothing, and — by default — writes nothing to
disk and makes no outbound network calls.

## Run it

### Docker (recommended)

```bash
docker run -p 3000:3000 salkreiner/netherchat
```

### Docker Compose (teams)

```bash
docker compose up -d        # builds + runs, hardened (read-only rootfs, no caps)
docker compose logs -f
docker compose down
```

### From source

```bash
go build -o bin/ ./cmd/netherchat-server
./bin/netherchat-server --addr :3000
```

Flags: `--config <path>` (load `netherchat.toml`), `--addr` (override the listen
address), `--version`, `--healthcheck` (probe the local `/health` and exit 0/1 —
used by the Docker `HEALTHCHECK`).

## Configuration (`netherchat.toml`)

Everything policy-related is config-as-code. Copy `netherchat.toml.example`,
edit, and run `netherchat-server --config netherchat.toml`. It covers:

- **`[limits]`** — per-connection message rate limit (token bucket).
- **`[persistence]`** — opt-in local history (off by default). When enabled with
  a `path`, uses a local pure-Go SQLite file; without a path, in-memory.
  **Caveat:** the server stores only ciphertext and never holds a key, so history
  is replayable to someone joining an *active* room but is unrecoverable after the
  room empties, a `/vanish`, or a restart. See [`encryption.md`](encryption.md).
- **`[rooms.NAME]`** — per-room policy: `invite_only`, `webhook` + `webhook_token`,
  `ttl` (ephemeral rooms expire after inactivity).
- **`[[trust]]`** — client-side identity pins (`handle`, `fpr`, `keys_url`) read by
  clients for `/whois`. The relay never reads them. See [`commands.md`](commands.md).

There is no server-side `/exec`: command execution moved to the **edge**. A blind
relay must never run commands, so `/exec` sends a signed, end-to-end-encrypted
request that a `netherchat agent` on your own host runs against its own runbook
allowlist (see [`commands.md`](commands.md)). The relay only ever routes ciphertext.

## Inbound webhooks

Enable `webhook` + a `webhook_token` for a room, then POST to it. The message is
plaintext and server-origin (NOT end-to-end encrypted — clients mark it as such):

```bash
curl -X POST https://chat.example.com/webhook/alerts \
  -H "X-Netherchat-Token: <your webhook_token>" \
  -H "Content-Type: application/json" \
  -d '{"text": "deploy complete", "from": "ci-bot"}'
```

Rooms without a `webhook_token` reject all webhook posts (secure by default).

## Invite-only rooms

Mark a room `invite_only`. The first member into an empty such room bootstraps it
and can mint one-time tokens with `/invite`; everyone after needs a token
(`netherchat connect … --invite <token>`, or paste it in the TUI).

## Connecting clients

```bash
netherchat connect ws://your-host:3000 --room ops --name alice
```

All clients in the same `--room` share an end-to-end-encrypted room key that the
server never sees. The first client to enter an empty room mints the key; it is
then wrapped (via `nacl/box`) for each subsequent joiner and relayed as opaque
ciphertext. See [`PROTOCOL.md`](../PROTOCOL.md).

## TLS / `wss://`

The server speaks plain WebSocket. For `wss://` over the public internet,
terminate TLS at a reverse proxy (Caddy, nginx, Traefik) in front of it:

```
# Caddy example
chat.example.com {
    reverse_proxy localhost:3000
}
```

Clients then connect with `netherchat connect wss://chat.example.com`.

## REST endpoints

| Endpoint    | Returns                                            |
|-------------|----------------------------------------------------|
| `/health`   | `{"status":"ok"}`                                  |
| `/version`  | version + protocol number                          |
| `/rooms`    | room names and member counts — **never** content   |

## What the operator can and cannot see

- **Cannot** read message content — messages are ciphertext under a room key the
  server never holds. This is enforced at the build-graph level: the server
  binary does not link the client crypto package (CI verifies this).
- **Can** see metadata: who is connected to which room, message sizes, timing.
  End-to-end encryption protects content, not metadata.

## Persistence

Off by default — the server is purely in-memory and rooms evaporate when empty.
(Opt-in local SQLite persistence is a later milestone; it will never write to the
cloud.)

## Publishing your own builds

Tag a release (`git tag v0.2.0 && git push origin v0.2.0`) to trigger the release
workflow. It needs these repository secrets:

- `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` — to push `salkreiner/netherchat`
- `HOMEBREW_TAP_TOKEN` — a PAT with write access to your Homebrew tap repo

Zero telemetry, always. The server never phones home.
