# Self-hosting Netherchat

**Netherchat ships as two artifacts, by design.** The endpoint **client**
(`netherchat`) is where all encryption happens; it is what you install on every
participant's machine, and it stays featherweight — a single static binary with no
runtime dependencies. The **relay** (`netherchat-server`) is a separate artifact you
provision only where you choose to host: a *blind* router that moves ciphertext
between clients and holds no keys. Keeping them separate is deliberate. The machine
that relays traffic and the machine that reads messages are never required to be the
same, and the client never carries server code it doesn't need — a property the
build graph enforces, not a promise. You install the client to talk; you provision
the relay to host.

The relay is a single static server binary (or a ~7 MB `FROM scratch` Docker
image). As a **blind relay** it routes end-to-end-encrypted frames between clients,
holds no keys, decrypts nothing, and — by default — writes nothing to disk and makes
no outbound network calls.

## Getting the relay

Every release archive contains **both** binaries. The client installers pull
`netherchat_<os>_<arch>.{tar.gz,zip}` from the release, which already includes
`netherchat-server` next to `netherchat` (plus `README`, `PROTOCOL`, `LICENSE`). You
can obtain the relay four ways, all producing the same checksum-verified binary:

1. **Installer, native (recommended for self-hosters)** — re-run the client installer
   with `-WithServer` (Windows) / `--with-server` (Linux/macOS). It installs the
   `netherchat-server` binary that already came down in the release archive — no
   second download.
2. **Container** — `docker run -p 3000:3000 salkreiner/netherchat` (server-only image;
   on Windows this needs Docker Desktop).
3. **By hand from a release archive** — download `netherchat_<os>_<arch>.{tar.gz,zip}`
   and extract `netherchat-server[.exe]`.
4. **From source** — `go build -o bin/ ./cmd/netherchat-server` (Go 1.26+).

On macOS the Homebrew cask installs from the same archive, so the relay binary lands
alongside the client there too.

## Run it

### Docker (containers & teams)

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

## Reachability without infra: Tor onion service (`--tor`)

When you have nothing to host *on* — no public IP, behind CGNAT, VPN down, the
incident *is* the network — one flag turns the relay into a **v3 onion service**:
no port-forward, no DNS, no TLS cert, and the `.onion` address itself
authenticates the relay (§1.5).

**1. Install tor** (Netherchat does not bundle it):

```bash
brew install tor          # macOS
sudo apt install tor      # Debian/Ubuntu
apk add tor               # Alpine
sudo pacman -S tor        # Arch
```

`tor` must be in `PATH`. `netherchat-server --tor` exits with this guidance if it
is not found.

**2. Start the relay with `--tor`:**

```bash
netherchat-server --tor
# netherchat server listening   addr=:3000 version=…
# tor onion service ready       addr=abc123…onion:80
```

`--tor` is **additive**: the relay still listens on its normal TCP port; the
onion is an extra listener over the same hub, so onion and TCP clients share
rooms. If tor fails to start or publish, the relay logs a warning and continues
on TCP — `--tor` is best-effort and never takes the core relay down.

By default the address is **ephemeral** (new on each run). For a stable `.onion`,
persist tor's state with `--tor-data-dir ./tor-data` (back it up — it holds the
service key that *is* your address).

**3. Connect over Tor.** Each client needs a local tor SOCKS proxy (the `tor`
daemon on `127.0.0.1:9050`, or Tor Browser on `127.0.0.1:9150`):

```bash
netherchat connect --tor ws://abc123…onion:80 --room ops --name alice
# Tor Browser's bundled tor:
netherchat connect --tor --tor-proxy 127.0.0.1:9150 ws://abc123…onion:80 --room ops
```

Because a v3 `.onion` address is derived from the relay's public key, reaching
the *right* address proves you reached the *right* relay — see
[`encryption.md`](encryption.md). There is no CA and no trust-on-first-use.

## Sneakernet Mode — a war room with no relay (`netherchat pair`, §1.1)

The whole thesis of Netherchat is that the normal channel cannot be trusted — and
the relay is the one component that thesis never turned on. When the relay host is
compromised, suspect, or simply unreachable, **Sneakernet Mode forms a war room
with no server at all.** Same BYO-key identity, same NaCl group crypto, same epoch
forward secrecy (`/vanish`), same sealed records (`/seal`) and scuttle receipts —
the only thing that changes is the transport. This works because the relay was
already blind: it routed ciphertext and held no keys, so removing it changes
nothing above the transport layer.

Two ways to connect with no relay:

```bash
# LAN auto-discovery (same network): both run this; one /pairs the other
netherchat pair --lan --room ops --name alice
netherchat pair --lan --room ops --name bob       # discovers alice → /pair <fpr>

# Manual blob (a VPN, or any direct reachability): one offers, the other joins
netherchat pair --manual --room ops --name alice          # prints a signed offer
netherchat pair --manual --join --room ops --name bob     # paste alice's offer
```

`--lan` advertises via mDNS (`_netherchat._tcp`) and lists discovered peers with
their fingerprints. **Discovery is never trust:** mDNS tells you someone is there;
your keys tell you who they are. A discovered peer is only a *candidate* — you
`/pair <fingerprint>` after verifying it out of band (or matching a `[[trust]]`
pin), and the Ed25519 handshake then proves the peer really holds that key. The
direct TCP connection is authenticated by the identity keys **before any message
frame is exchanged**, so a rogue process on the host's address cannot impersonate
it.

> ### Honest scope: no NAT traversal
>
> Sneakernet works **on a LAN** and **via manual blob exchange**. It does **NOT**
> support general NAT traversal — if the two machines are on different networks
> without a shared LAN, you need the manual blob exchange **and** both machines
> must be reachable by the IP addresses in the offer blob (e.g. both on a VPN, both
> on the same LAN, or one machine port-forwarded).
>
> This is a deliberate design decision. General P2P NAT traversal requires a
> STUN/TURN rendezvous server, which re-introduces infrastructure cost and a
> trusted third party — exactly what Sneakernet Mode is designed to avoid.
>
> - **Teams on different networks:** use the relay (the default mode).
> - **Teams on the same LAN or in the same room:** use `--lan`.
> - **Teams with a shared VPN or direct reachability:** use `--manual`.

> ### Honest scope: relay-less scuttle is single-actor
>
> The two-person rule (`[action.scuttle]` quorum, §1.3) requires the relay to route
> a second party's approval. Relay-less mode has no such path, so a manual
> `/scuttle` with a configured `quorum ≥ 2` is **refused** (fail-closed) rather than
> destroying the room unilaterally — the client prints why. Relay-less scuttle is
> therefore **single-actor only**: leave the quorum unset (or `1`) to allow the
> instant emergency burn, or use the relay when you need a two-person-gated scuttle.
> `netherchat pair --config <toml>` loads the policy so the refusal is enforced and
> the active governance is announced at startup.

Topology note: for two peers the connection is fully direct. For more than two, the
peer that initiated (the offerer / LAN host) coordinates membership and relays
between members — still no external infrastructure, and that peer is a full room
member who holds the key anyway, not a separate server. It works well for small
groups; for larger groups use the relay.

Configure defaults in `netherchat.toml`:

```toml
[direct]
port = 7777          # listening port for direct connections (0 = a free port)
lan_discovery = true # advertise on the LAN via mDNS
```

## REST endpoints

| Endpoint    | Returns                                            |
|-------------|----------------------------------------------------|
| `/health`   | `{"status":"ok"}`                                  |
| `/version`  | version + protocol number + source URL + license   |
| `/source`   | 302 redirect to the source for this build          |
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

## License and source

Netherchat is licensed **AGPL-3.0-or-later** ([LICENSE](../LICENSE)). What that
means in practice, by what you're doing:

**Running an unmodified build — for yourself, your team, or your users.** Nothing
is required of you. AGPL-3.0 §13 conditions its source-offer obligation on your
having *modified* the Program; an unmodified relay carries no such obligation.
`/source` and the `source` field of `/version` already point at upstream.

**Running a modified build over a network.** §13 asks that users interacting with
your version remotely be offered its Corresponding Source. Publish your modified
source where those users can reach it, then stamp the build so the offer points
there — the supported way is a linker override, exactly like `Version`:

```bash
go build -ldflags "\
  -X github.com/salehkreiner/netherchat/buildinfo.Version=X.Y.Z \
  -X github.com/salehkreiner/netherchat/buildinfo.SourceURL=https://example.com/our-netherchat" \
  -o bin/ ./cmd/netherchat-server
```

One symbol feeds the redirect, the `/version` field, and the startup log, so a
correctly stamped build carries the offer wherever a user looks. A build that
still points at upstream is offering source that does not contain your changes.

```
netherchat server listening  addr=:3000 version=X.Y.Z source=https://example.com/our-netherchat
```

**Building Netherchat into something you distribute.** This is the clause most
people mean when they ask about AGPL, and it is not §13. Importing
`sealedrecord`, linking the client, or shipping a product that contains
Netherchat generally makes that product a derivative work, which AGPL requires
you to license under the same terms. If your product is proprietary, or your
contract prohibits copyleft in deliverables — common in government and defense
work — the AGPL is not the right instrument.

**Commercial licensing.** Astralis Software Systems holds the copyright in
Netherchat and offers alternative terms for exactly these cases: proprietary
embedding, closed deliverables, and hosted services that cannot publish their
modifications. Contributors grant a relicensing right
([CONTRIBUTING.md](../CONTRIBUTING.md)), so the whole tree can be licensed
cleanly — there is no fragmented-copyright problem to diligence around.
Contact [Astralis Software Systems](https://astralis-systems.com).

*This is a plain-language summary, not legal advice. The
[license text](../LICENSE) governs.*

## Publishing your own builds

Tag a release (`git tag vX.Y.Z && git push origin vX.Y.Z`) to trigger the release
workflow. It needs these repository secrets:

- `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` — to push `salkreiner/netherchat`
- `HOMEBREW_TAP_TOKEN` — a PAT with write access to your Homebrew tap repo

Zero telemetry, always. The server never phones home.
