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

The relay is a single static server binary (or a `FROM scratch` Docker image that
is nothing but that binary). As a **blind relay** it routes end-to-end-encrypted
frames between clients, holds no keys, decrypts nothing, and — by default — writes
nothing to disk and makes no outbound network calls.

---

## Two deployment modes

There are two, and the difference between them is technical rather than a matter of
scale. Pick by whether anyone needs to join from a browser.

| | **Mode A — TUI only** | **Mode B — TUI plus browser** |
|---|---|---|
| Certificate | none | **required** |
| DNS name | none — an IP is fine | one name the cert covers |
| Reverse proxy | none | required (Caddy, nginx, …) |
| Client transport | `ws://` | `wss://` |
| Web client | not served | served from the relay's own origin |
| Runs air-gapped | **yes** | yes, with an internal CA |
| Outbound calls from the relay | none | none |

Everything above the transport is identical. Same client binary, same protocol,
same room keys, same sealed records, same offline verification. Mode B adds a
browser front door; it does not change what the relay is or what it can see.

Two things that are *not* modes, and are covered at the end: **`--tor`**, which
gives Mode A reachability when there is no shared network, and **`netherchat
pair`**, which forms a room with no relay at all.

---

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

### Docker and Compose

```bash
docker run -p 3000:3000 salkreiner/netherchat
```

```bash
docker compose up -d        # builds + runs, hardened (read-only rootfs, no caps)
docker compose logs -f
docker compose down
```

The image is `FROM scratch` with one static binary in it and nothing else — no
shell, no libc, no package manager, and no CA bundle, because the relay makes no
outbound calls. The binary is the image, so the image is about as large as the
binary: roughly 11 MB for `linux/amd64` at the time of writing. It runs as UID
65534 with a read-only root filesystem and no capabilities under the supplied
Compose file, and self-probes with `netherchat-server --healthcheck`, which is how
a shell-less image can still declare a Docker `HEALTHCHECK`.

### Relay flags

`--config <path>` (load `netherchat.toml`) · `--addr` (listen address; default
`:3000`) · `--web-url <url>` · `--tor` / `--tor-data-dir` · `--version` ·
`--healthcheck`.

`--web-url` is narrower than it looks and is covered under
[Things that only show up when you run it](#things-that-only-show-up-when-you-run-it).

---

## Mode A — TUI only. No certificate, no DNS, no outbound anything.

This is the deployment with the fewest moving parts and the strongest claim: one
binary on a host your people can reach, over plain `ws://`, with **no PKI anywhere
in the system**. It runs on an air-gapped network. The relay resolves no name,
fetches no certificate and makes no outbound call, and neither does a client, with
one opt-in exception noted under [`[[trust]]`](#configuration-netherchattoml).

Two properties make it work rather than merely tolerate it:

- **The relay's WebSocket handshake enforces same-origin, and a TUI has no origin
  to check.** A terminal client sends no `Origin` header, so the default
  enforcement in `HandleWS` (`server/internal/ws/server.go`) admits it. The same
  check is what forecloses a browser client on a foreign origin — see
  [What a relay operator can see](#what-a-relay-operator-can-see).
- **Verification is offline by construction.** A sealed record carries its signers'
  public keys inside it (`signer_keys`), so `netherchat verify` checks a chain and
  its signatures with no network, no directory, and no CA.

### Start the relay

The relay listens on `:3000` — every interface — unless you say otherwise. Pin it
to one address if you would rather it not be reachable from all of them:

```bash
netherchat-server --addr 192.168.0.203:3000
# time=… level=INFO msg="netherchat server listening" addr=192.168.0.203:3000 version=dev
```

No `--config` is required. No certificate exists. Nothing was fetched.

The address that matters more is the one *clients* dial, and its default is
`ws://localhost:3000` — right on the relay host and wrong on every other machine.
Give every client the relay's real address, or you will spend an afternoon
debugging a room that two people are in and nobody else can find.

### Connect

```bash
netherchat connect ws://192.168.0.203:3000 --room ops --name alice
netherchat connect ws://192.168.0.203:3000 --room ops --name bob
```

All clients in the same `--room` share an end-to-end-encrypted room key the relay
never sees. The first client into an empty room mints the key; it is then wrapped
(via `nacl/box`) for each later joiner and relayed as opaque ciphertext. See
[`PROTOCOL.md`](../PROTOCOL.md) §4–§5.

### The evidence path, with no PKI present

The full propose → approve → seal → verify path runs in this mode. It has headless
commands as well as the TUI's `/propose`, `/approve-artifact` and `/seal`, which is
what makes it scriptable and what makes the walkthrough below reproducible.

An approver waits in the room:

```bash
netherchat approve-artifact --server ws://192.168.0.203:3000 --room airgap-artifacts \
  --name bob --identity ./bob.json --seal --out record.json
# approve-artifact ready: watching #airgap-artifacts for a proposal
```

An agent (or a human acting for one) proposes an artifact **by hash** — the content
never crosses:

```bash
sha256sum artifact.txt
# aec93d251430bb591abc3bee7ee9aca9bb40621eb58f7dab5aaf734e0975bbea  artifact.txt

netherchat propose --server ws://192.168.0.203:3000 --room airgap-artifacts \
  --source requirements-agent --ref Q3-requirements \
  --hash aec93d251430bb591abc3bee7ee9aca9bb40621eb58f7dab5aaf734e0975bbea \
  --summary "draft for review" --identity ./alice.json --name alice --quorum 1
# proposed artifact "Q3-requirements" (id 944469117797285f, source requirements-agent) — awaiting 1 human approval(s)
```

The approver's side completes and seals:

```
approving artifact "Q3-requirements" (id 944469117797285f, source requirements-agent, hash aec93d…)
artifact approved and written into the record chain
sealed record written to record.json (1 entry, 1 signer(s))
```

Copy `record.json` to a machine that was never in the room, with the relay **shut
down** and nothing to reach:

```bash
netherchat verify record.json
# VALID — chain intact, 1 entry, 1 signature(s) verified
#   room: airgap-artifacts
#   head: 0dfa42759e56e408c56a4e7a9e6bcec25d5285649a11dc8c71a463d8fa6db9e3
#   signed: SHA256:4Y0OGO49UECP2OWAQ/3s+4EVseALPumO0aF/6+pXcGs
```

No certificate was involved at any point, and the proposer can never count toward
its own quorum (`PROTOCOL.md` §17).

### What Mode A does not get

Say this part out loud before you choose it.

- **No browser client.** The relay serves no HTML at all. `GET /join`, `GET /beacon`
  and `GET /` on the relay's own port each return `404 page not found` — there is no
  static handler in the binary. Browser participation is the whole of Mode B.
- **No join links anyone can open.** `/invite`, `/break-glass` and `/beacon link`
  still mint URLs, but they point at an origin that serves nothing. The beacon case
  is the one that hurts, because the beacon key lives in the URL fragment and never
  reaches a server that could log the miss: the sender sees a plausible link and the
  recipient sees a bare 404.
- **No beacon *page*.** The beacon REST API works — it only ever stores and returns
  ciphertext — but the page that decrypts it is a browser page.
- **Transport metadata is visible to the network, not just to the relay operator.**
  Message contents stay end-to-end encrypted, but `ws://` is plaintext at the
  transport layer, and the handshake carries room names, display names, public keys
  and any identity attestation in the clear. In Mode A, everything the
  [operator-visibility section](#what-a-relay-operator-can-see) attributes to the
  relay operator is *also* available to anyone on the path. On an enclave or
  air-gapped network the network boundary is the answer to that, and that is the
  deliberate trade. If it is not the answer for you, you want Mode B (a certificate)
  or `--tor` (a transport that authenticates and encrypts itself, with no CA).

---

## Mode B — TUI plus browser

Mode B serves the browser client and the relay from **one origin**, behind a reverse
proxy that terminates TLS.

### HTTPS is mandatory. Here is the honest reason.

**The browser client's cryptography arrives over the link, on every page load.**
That is the difference from the TUI, and it is the whole argument. A terminal
client is a binary you installed once and can verify against a published checksum;
the browser client is JavaScript the server hands the browser each time someone
opens a join link, with no subresource-integrity attribute and no signature
anywhere in it. Over plain HTTP, anyone on the path replaces the bundle that does
the encrypting, and there is no layer underneath to notice. The invite token also
rides in the query string (`/join?room=ops&token=…`), where the same observer
reads it.

Two secondary points, both true and neither the main one:

- A page served over `http://` on anything but `localhost` is **not a secure
  context**. `crypto.subtle` and `crypto.randomUUID` are `undefined` there. The
  current bundle does not use either — it draws randomness from
  `crypto.getRandomValues`, which *is* available in an insecure context — so this
  is a standing fragility rather than today's blocker.
- Serving the page over HTTPS forces `wss://` automatically: the client resolves its
  relay from the page's own scheme and host and from nothing else
  (`web/src/net/protocol.ts`, `pageRelay`).

**What this section deliberately does not say is that it will not work.** It does
work: on a plain-HTTP LAN origin the browser client reaches
`data-state="encrypted"`, exchanges keys with a Go client, and its messages decrypt
correctly at the other end — measured, not assumed. That is exactly why the warning
has to rest on what an attacker can do rather than on a browser mechanism that
would stop you, because nothing stops you. The join screen names the endpoint it
is about to dial, scheme included (`relay ws://…` versus `relay wss://…`), which is
the last chance anyone gets to notice.

### TLS / `wss://`

TLS terminates at the reverse proxy, and only there. **The relay never terminates
TLS.** `[server]` accepts no `tls_cert`/`tls_key`, and setting either is a fatal
config error rather than a setting the relay silently ignores while you believe you
are serving `wss://`. It fails `netherchat-server --config`, and
`POST /api/v1/config/validate` answers `valid:false` with the reason:

```
[server]: tls_cert is not honored — the relay does not terminate TLS, it speaks
plain WebSocket, and setting tls_cert would have served plaintext ws:// with no
warning. Terminate TLS at a reverse proxy (Caddy, nginx, Traefik) in front of the
relay instead; see docs/self-hosting.md, "TLS / wss://"
```

If you are upgrading from a config that carried those keys, delete them — they were
never read, so removing them changes nothing about how your relay serves traffic.

### Serving the web client (`/join` and `/beacon`)

```bash
cd web && npm run build     # → web/dist/{index,join,beacon}.html
```

The relay serves no HTML. It answers `/ws` and the REST endpoints and nothing else,
so the browser client is static files your reverse proxy serves — **from the same
origin as the relay**. That is not a recommendation: `HandleWS` enforces same-origin
on the WebSocket handshake deliberately and permanently, and the page resolves its
relay from its own origin alone, so a browser client on a different host cannot
connect at all.

Netherchat's links are extensionless, and that is the public contract:

```
https://chat.example.internal/join?room=ops&token=…
https://chat.example.internal/beacon?room=ops&ttl=3600#key=…
```

The files behind them are `join.html` and `beacon.html`, so your proxy needs **two
rewrite rules**, and they must match **exactly** `/join` and `/beacon` and nothing
deeper. `/beacon/<room>` is a *different thing* — it is the relay's beacon REST API
(`PROTOCOL.md` §1.2) and must still be proxied to the relay untouched.

Getting that wrong is quiet in two different ways, and both were measured:

- **A prefix matcher instead of an exact one** (`path /join* /beacon*` in Caddy, or a
  `location /beacon` without the `=`) rewrites the API path too. `/beacon/ops`
  becomes `/beacon/ops.html`, which still reaches the relay — as a request about a
  room named `ops.html`, which has no beacon. The relay answers
  `404 no beacon set for this room`, an ordinary and entirely plausible reply. The
  page keeps working; only the API is broken, and it is broken in a way that looks
  like nothing is wrong.
- **No rewrites at all** gives `/join` a bare `404` from the file server, which at
  least fails loudly — *unless* your edge has an SPA fallback that turns a miss into
  `index.html` with `200 OK`, which several CDN configurations do by default. Then
  the recipient of a beacon link gets a wrong page, no error, and no server anywhere
  logged the miss, because the key was in the fragment and never left their browser.

Both configurations below get this right. Query strings survive a rewrite; the
`#key=…` fragment never reaches the proxy at all.

### Certificate origin 1 — your internal CA

**Start here if your organization runs a PKI, which it almost certainly does.** This
is the shorter path, not the longer one. You are not asking for a new capability;
you are asking for a server certificate for one internal name, from a CA whose root
is already on every managed endpoint by GPO or MDM. There is no ACME client, no
public DNS record, no port 80 exposed to the internet, no renewal that depends on
reaching a third party, and nothing about this deployment that stops working when
the site is offline.

Get a certificate and key for the name your clients will use, put them on the proxy
host, and point Caddy at them:

```
chat.example.internal {
	tls /etc/netherchat/chat.crt /etc/netherchat/chat.key

	root * /srv/netherchat/dist

	# Clean URLs. `path /join /beacon` matches those two paths EXACTLY, so
	# /beacon/<room> below is untouched. Query strings survive a rewrite; the
	# #key=… fragment never reaches the proxy at all.
	@pages path /join /beacon
	rewrite @pages {path}.html

	reverse_proxy /ws localhost:3000
	reverse_proxy /beacon/* localhost:3000

	file_server
}
```

An explicit `tls <cert> <key>` turns off Caddy's certificate management for that
site; it says so at startup, and that line is the one to look for:

```
"logger":"http.auto_https","msg":"skipping automatic certificate management because one or more matching certificates are already loaded","domain":"chat.example.internal"
```

Then, on the endpoints:

- **Browsers** trust the internal root the moment the machine does, which for a
  managed fleet is already true.
- **The `netherchat` TUI uses the operating system's trust store**, so the same root
  covers it. On Linux and macOS you can also point one process at a CA file with
  `SSL_CERT_FILE=/path/ca.crt` without touching the store — useful for a test.
  **On Windows `SSL_CERT_FILE` does nothing**; the root has to be in the Windows
  store. A client with no path to the root fails clearly rather than quietly:

  ```
  netherchat: connect to wss://chat.example.internal: dial wss://chat.example.internal/ws:
    failed to WebSocket dial: … tls: failed to verify certificate: x509: certificate signed by unknown authority
  ```

Nothing here is Caddy-specific except the syntax. Any proxy that can present a
certificate from disk, preserve `Host`, and do the two exact-match rewrites will do;
the nginx form is below.

### Certificate origin 2 — a public CA

For a small team on the public internet with no internal PKI, let the proxy get a
certificate from a public CA. In Caddy that is the default: give the site a
public DNS name that resolves to the host, drop the `tls` line, and leave the rest
of the block exactly as above.

```
chat.example.com {
	root * /srv/netherchat/dist

	@pages path /join /beacon
	rewrite @pages {path}.html

	reverse_proxy /ws localhost:3000
	reverse_proxy /beacon/* localhost:3000

	file_server
}
```

What that requires is a property of your CA, not of Netherchat: a name the CA can
validate, a reachable challenge path, and outbound access from the proxy to the CA.
Consult your CA's documentation for the specifics — this document does not restate
them, because they change and because the relay is not involved in any of it.

The relay's own posture is unchanged either way. It still makes no outbound calls;
the proxy is the only component that talks to a CA.

### The nginx form

The Caddy block above is the one that has been run end to end against a live relay;
this is its nginx equivalent, kept in step with it.

```nginx
server {
    listen 443 ssl;
    server_name chat.example.internal;

    ssl_certificate     /etc/netherchat/chat.crt;
    ssl_certificate_key /etc/netherchat/chat.key;

    root /srv/netherchat/dist;

    # Clean URLs. `location =` is an exact match and outranks the /beacon/
    # prefix below, so /beacon hits the page and /beacon/<room> hits the API.
    location = /join   { try_files /join.html   =404; }
    location = /beacon { try_files /beacon.html =404; }

    location = /ws {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade    $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host       $host;      # same-origin handshake check
    }

    location /beacon/ {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
    }

    location / { try_files $uri $uri/ =404; }
}
```

`Host` must reach the relay unmodified. The relay compares `Origin` against `Host`
to decide whether to accept the WebSocket, so a proxy that rewrites `Host` to the
upstream address refuses every browser client. Caddy preserves it by default; nginx
needs the line.

### Verify the deployment

Run these against the real origin, from a machine that trusts the CA. Every line
below is what a correct deployment answers.

```bash
# 1. the chain verifies with no -k
curl -sS -o /dev/null -w '%{http_code}\n' https://chat.example.internal/
# 200

# 2. /join is the page
curl -sS 'https://chat.example.internal/join?room=ops&token=x' | grep -i '<title>'
#     <title>Netherchat — join</title>

# 3. /beacon is the page
curl -sS 'https://chat.example.internal/beacon?room=ops&ttl=3600' | head -1
# <!doctype html>

# 4. /beacon/<room> is still the relay's API — JSON, or the relay's own 404
curl -sS -D- https://chat.example.internal/beacon/ops | head -3
# HTTP/1.1 200 OK
# Access-Control-Allow-Origin: *
# Content-Type: application/json
```

Then the handshake itself, which is the check most deployments skip and the one
that catches a `Host`-rewriting proxy:

```bash
curl -sS -m 4 -i --http1.1 \
  -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  -H 'Origin: https://chat.example.internal' \
  https://chat.example.internal/ws
# HTTP/1.1 101 Switching Protocols
# Upgrade: websocket
```

`curl` will then sit there until the timeout, which is correct — the socket is open.
Repeat it with `-H 'Origin: https://somewhere.else'` and you should get the refusal
quoted in the next section.

### Smoke-test the built bundle before you copy it anywhere

`vite preview` serves `web/dist` — the exact bytes you are about to deploy — and it
carries the same `/ws` and `/beacon/` proxy the dev server does, so it exercises the
one-origin shape without a reverse proxy in front of it:

```bash
cd web && npm run build
NETHERCHAT_RELAY=http://localhost:3000 npm run preview   # http://localhost:4173
```

That checks the bundle and your relay. It does **not** check your reverse proxy;
the `curl`s above are what check that. `vite dev` and `vite preview` apply the same
two rewrites through the `cleanRoutes` plugin in `web/vite.config.ts`, so a link that
works in dev works here.

---

## What a relay operator can see

This section is the argument for self-hosting, so it is written plainly rather than
reassuringly. `PROTOCOL.md` §4 and §17 are the precise version; this is what it
means for the person running the box.

**Message contents are opaque and the relay cannot make them otherwise.** Messages
are ciphertext under a room key the relay never holds. This is enforced at the
build-graph level, not by policy: the server binary does not link the client crypto
package, on every platform Netherchat releases, and CI fails if that changes.

**Room names, membership, display names, key fingerprints, identity credentials and
timing are not opaque.** Here is the relay's own log from a session, unedited except
for trimming:

```
level=INFO msg="member joined" room=entcheck id=125d5e3df9bc9bea name=bob-win  first=true
level=INFO msg="member joined" room=entcheck id=ebec4e1dc1817b6d name=wsl-linux first=false
level=INFO msg="member left"   room=entcheck id=ebec4e1dc1817b6d room_empty=false
level=INFO msg="beacon set"    room=ops ttl=1h0m0s bytes=16
```

Not one byte of message content, and no key material. Also: exactly who was in which
room, under what name, and when. The current snapshot is available on demand from
`GET /rooms`, which takes **no authentication** — anyone who can reach the relay can
enumerate the active rooms and their sizes, though not the names in them:

```json
{"rooms":[{"name":"incident-4432","members":1,"invite_only":false,"ttl_seconds":0,"webhook":false}]}
```

**Identity attestations are the largest disclosure, and they are broadcast.** When a
participant connects with `--attestation`, the credential travels on the `hello`
frame and the relay copies it onto the `member` it announces to everyone else. It
never parses it, and it gains no ability to verify it — but it goes past in the
clear, and it states an enterprise-shaped principal: a UPN or an email or an
employee id, the signed display name, the role list, the validity window, the
serial, and the issuing authority. The change that matters is correlation. The relay
already knew *"a key with this fingerprint was in room #incident-4432 at 03:47."*
With attestations in the room it knows *whose* key, by an identifier that resolves
in your directory. Carrying a credential is opt-in per participant and per session;
a participant who carries none produces byte-identical frames to a client built
before the field existed.

**So: the relay operator learns who was in which room and when.** That is the
sentence self-hosting exists to answer. Not "trust us with it" — *do not give it to
anyone*, because in Mode A and Mode B alike the operator is you.

**Astralis Software Systems operates no relays.** There is no hosted Netherchat
service, and none is planned. There is nowhere for us to have this data.

**And a hosted client pointed at somebody else's relay is architecturally
foreclosed, not merely discouraged.** The browser client resolves its relay from
the page's own origin and consults nothing else — the query string cannot aim it,
because a link-borne endpoint (`/join?server=…`) is the attack that removing it
closed. On the other side, the relay refuses a WebSocket handshake whose `Origin`
does not match its `Host`:

```
HTTP/1.1 403 Forbidden
request Origin "hosted-client.example.com" is not authorized for Host "chat.example.internal"
```

A TUI, which sends no `Origin` at all, is admitted — which is why Mode A works. The
consequence is that **a relay's browser client must be served from the relay's own
origin**. There is no configuration that relaxes it, and there is a comment in
`HandleWS` telling the next person not to add one.

---

## Things that only show up when you run it

Five facts that make a first deployment fail in confusing ways. None of them is a
bug; all of them are surprising exactly once.

### Each client that mints a link needs its own `--web-url`

`--web-url` on the **relay** sets the base for the one-time `/join` links the relay
itself returns in its own REST responses, when a `[[route]]` rule or an inbound
alert spawns a war room. **It does not reach connected clients.** No wire frame
carries it.

So the links printed by `/invite`, `/break-glass` and `/beacon link` in a TUI are
built from *that TUI's own* `--web-url`. Unset, they are derived from the relay URL
it dialed (`ws→http`, `wss→https`) — right in the single-origin Mode B deployment,
wrong the moment a client talks straight to the relay's listen address while the
pages are served elsewhere:

```bash
netherchat beacon-link ops --server ws://192.168.0.203:3000
# http://192.168.0.203:3000/beacon?room=ops&ttl=3600#key=…        ← the relay serves no HTML

netherchat beacon-link ops --server ws://192.168.0.203:3000 --web-url https://chat.example.internal
# https://chat.example.internal/beacon?room=ops&ttl=3600#key=…
```

A TUI prints a warning when it mints a link on a derived base; the headless
`netherchat beacon-link` command prints the link and nothing else, as above. The
warning exists because the beacon case would otherwise fail silently in all three
directions: the key sits in the URL fragment, which never reaches a server that
could log the miss.

### `beacon_token` must be in **both** the relay's config and each client's

The beacon is off unless a room turns it on, and the token is the switch. A room can
have a beacon only if it sets `beacon_token` — or, failing that, reuses its
`webhook_token`. There is no global setting and no default, so a room you never
named in `netherchat.toml` has no beacon at all.

```toml
[rooms.ops]
beacon_token = "a-long-random-secret"   # authorizes PUT/DELETE /beacon/ops
beacon_ttl   = "1h"                     # how long a beacon persists (hard max 24h)
```

The relay checks the token; the client sends it. They are different processes
reading different files — the relay via `--config`, a TUI via `--config` or a
`netherchat.toml` in its own working directory. Since each client runs from its own
directory (see below), each needs its own copy. The three outcomes:

| Configured | `PUT /beacon/<room>` answers |
|---|---|
| neither side | `404 beacon is not enabled for this room` |
| relay only | `401 invalid or missing beacon token` |
| both | `200 {"ok":true}` |

`netherchat connect` prints which config it loaded at startup —
`netherchat: config: none found …` means the token was not read.

Reads are deliberately unauthenticated, and cross-origin readable
(`Access-Control-Allow-Origin: *`): the stored blob is ciphertext the relay cannot
decrypt, so `GET /beacon/<room>` needs no token and gives away nothing.

### A room outlives its key, and `/scuttle` is the way out

The relay tracks membership and nothing else. A room exists from the first join and
is deleted the moment it empties. The **key** lives only in client memory, and the
relay cannot ask who holds one, because it holds none itself.

That leaves one bad state: a room with members present and no key among them. The
epoch-0 mint is gated on `you_are_first`, which is false for every join into a
non-empty room, so once a room is non-empty it can never be re-founded. There is no
re-key command, and `/vanish` ratchets an existing key rather than creating one. The
reachable path is a race — the oldest member disconnects between a newcomer's
`key_request` and the delivery — so it is rare, and it is real.

**The recovery is `/scuttle` from any TUI still in the room.** It works from a
keyless client: the scuttle receipt needs a key, so that round is skipped, and the
burn request goes to the relay, which expires the room server-authoritatively. The
next join founds a fresh one. The browser client has no `/scuttle`, so this is a
terminal-only exit.

**One combination has no in-room exit at all: a keyless room whose
`[action.scuttle]` quorum is ≥ 2.** The two-person gate is enforced client-side and
routes its approval request as an end-to-end-encrypted frame, which needs the room
key the room does not have, so `/scuttle` refuses with `room key not established
yet`. If you configure a scuttle quorum, know that the operator's remaining lever is
the relay itself: every room is in memory, so restarting `netherchat-server` clears
all of them.

For a demo or a rehearsal, the cheaper answer is a fresh room name per run.

### `/seal` writes fixed filenames into the working directory

`record.json` and `minutes.md`, with no flag to redirect either. Two TUIs started in
the same directory overwrite each other's evidence. **Run each client from its own
directory.** (`/roster --signed` takes an `--out <path>`, and the headless
`netherchat approve-artifact --seal` takes one too; `/seal` is the one with no
escape hatch.)

One file is *not* fixed per directory and separate directories do not fix it:
`status.json`, the prompt-segment status file, lives at a per-user config path
(`%AppData%\netherchat\status.json`, `~/.config/netherchat/status.json`). Two
clients on one machine share it, last writer wins, and the first to exit removes it
for both. It is cosmetic — nothing depends on it — but do not read it as evidence.

### Flags may go anywhere on the line

Both of these do the same thing, and either order is fine:

```bash
netherchat send ops --server ws://192.168.0.203:3000 --name alice "the message"
netherchat send ops "the message" --server ws://192.168.0.203:3000 --name alice
```

This was not always true, and the note that used to be here told you to put the
flags first. Go's `flag` package stops parsing at the first non-flag argument, so
the second line above parsed no `--server` at all: it dialled the default
`ws://localhost:3000` and joined the flags into the message body, which meant an
`--invite` token typed after the message was encrypted into the room as chat text.
Every command now parses flags wherever they appear (`internal/cliargs`).

Two consequences worth knowing:

- A **message word beginning with `-`** is parsed as a flag and rejected. Pass
  `--` first to send it verbatim: `netherchat send ops -- --not-a-flag`.
- An argument a command has no use for is **refused, not ignored** — `netherchat
  rooms bogus --server …` exits 2 instead of quietly querying `localhost`.

---

## Identity, briefly

Netherchat holds no trust anchors on any path that produces evidence. Issuer keys
are parameters to a verification, never configuration of the system.

`netherchat connect --issuer <file>` is **read-side only**: it decides what *this
screen* says about the credentials other people carry, and changes nothing this
client sends. Records, rosters and approvals are byte-identical with the flag and
without it. Two operators in the same room, one with an issuer pinned and one
without, see two different and individually correct answers about the same person.

The issuing key itself is a trust anchor and is generated by a separate tool:

```bash
netherchat-identity keygen
```

Its output already explains where the key goes and why — including why the default
location is under `%LOCALAPPDATA%` and never `%APPDATA%` (a roaming profile copies
itself to a file server at logon), and what `0600` does and does not mean on
Windows. **Read what it prints; this document deliberately does not restate the
format or the paths**, because two copies of that explanation is one copy too many
and the tool's is the one that cannot go stale. The advisory is about the path it
actually wrote: name an `--out` under `%APPDATA%` and it says so and tells you to
move the file before you log off; name anything else and it says it cannot tell
whether that location stays on this machine, because a mapped drive and a synced
folder look no different from inside the tool.

One destination it refuses outright rather than warning about: a UNC path
(`\\server\share\…`). A warning there would arrive after `os.WriteFile` had already
put the private key on that host and into its backups, and an issuing key has no
in-format recovery. Write it locally and move it deliberately, or pass
`--allow-network-path` to mean it.

`netherchat-identity` with no arguments prints the full command set.

Client-side identity pins live in `netherchat.toml` under `[[trust]]` and are read
by `netherchat`, for `/whois`. **The relay never reads them** — the only consumer in
the tree is the client. See [`commands.md`](commands.md).

---

## Configuration (`netherchat.toml`)

Everything policy-related is config-as-code. Copy `netherchat.toml.example`, edit,
and run `netherchat-server --config netherchat.toml`. It covers:

- **`[limits]`** — per-connection message rate limit (token bucket), file size and
  concurrent-transfer caps.
- **`[persistence]`** — opt-in local history (off by default). With a `path`, a local
  pure-Go SQLite file; without one, in-memory.
  **Caveat:** the server stores only ciphertext and never holds a key, so history is
  replayable to someone joining an *active* room but is unrecoverable after the room
  empties, a `/vanish`, or a restart. See [`encryption.md`](encryption.md).
- **`[rooms.NAME]`** — per-room policy: `invite_only`, `webhook` + `webhook_token`,
  `ttl` (ephemeral rooms expire after inactivity), `beacon_token` + `beacon_ttl`,
  `durable` (opt-in persisted case room), and `[rooms.NAME.scuttle]` (dead-man's
  switch).
- **`[action.*]`** — two-person-rule quorums for `scuttle`, `break-glass`, `runbook`
  and `artifact`. Read by clients, which is where the gate is enforced.
- **`[[trust]]`** — client-side identity pins (`handle`, `fpr`, `keys_url`).
  **`keys_url` is the one outbound call anywhere in a Netherchat deployment**: when
  a pin carries one, `/whois` fetches it from the *client*, and says so on screen
  before it does (`fetching <url> (client-side)…`). Omit it on an air-gapped
  network; `fpr` alone pins fine without it.
- **`[direct]`** — defaults for relay-less pair mode; read client-side only.

There is no server-side `/exec`: command execution moved to the **edge**. A blind
relay must never run commands, so `/exec` sends a signed, end-to-end-encrypted
request that a `netherchat agent` on your own host runs against its own runbook
allowlist (see [`commands.md`](commands.md)). The relay only ever routes ciphertext.

Validate a candidate config without applying it by POSTing it to
`/api/v1/config/validate`, which answers `{"valid":true}` or
`{"valid":false,"error":"…"}`.

---

## Inbound webhooks

Enable `webhook` + a `webhook_token` for a room, then POST to it. The message is
plaintext and server-origin (NOT end-to-end encrypted — clients mark it as such):

```bash
curl -X POST https://chat.example.internal/webhook/alerts \
  -H "X-Netherchat-Token: <your webhook_token>" \
  -H "Content-Type: application/json" \
  -d '{"text": "deploy complete", "from": "ci-bot"}'
# {"ok":true}
```

Secure by default, in both directions: a room with `webhook = true` and no
`webhook_token` answers `401 invalid or missing webhook token` to every post, and a
room absent from the config answers `404 webhooks are not enabled for this room`.

## Invite-only rooms

Mark a room `invite_only`. The first member into an empty such room bootstraps it
and can mint one-time tokens with `/invite`; everyone after needs a token
(`netherchat connect … --invite <token>`, or paste it in the TUI).

## REST endpoints

| Endpoint          | Returns                                                                                                                                                                          |
|-------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `/health`         | `{"status":"ok"}`                                                                                                                                                                |
| `/version`        | version + protocol number + source URL + license                                                                                                                                 |
| `/source`         | 302 redirect to the source for this build                                                                                                                                        |
| `/rooms`          | active room names, member counts and policy flags — **never** content. Unauthenticated.                                                                                          |
| `/beacon/<room>`  | `GET` returns the room's beacon ciphertext + `updated_at`, or 404. `PUT`/`DELETE` write it and require the room's beacon token. Ciphertext only — the relay cannot read a beacon. |
| `/webhook/<room>` | `POST` an alert into a room; requires the room's `webhook_token`.                                                                                                                |
| `/api/v1/…`       | config validation and the Terraform provider's surface.                                                                                                                          |

## Persistence

Off by default — the relay is purely in-memory and rooms evaporate when empty.
Opt-in local SQLite persistence is available via
[`[persistence]`](#configuration-netherchattoml) and is strictly local: it never
writes to the cloud. What it does and does not buy you — replay to an active room,
nothing recoverable after the room empties or the server restarts, and how the
at-rest key is resolved — is in [`encryption.md`](encryption.md).

---

## Reachability without infrastructure: Tor onion service (`--tor`)

Not a third mode — Mode A's answer to *"my people are not on one network."* When
you have nothing to host *on* — no public IP, behind CGNAT, VPN down, the incident
*is* the network — one flag turns the relay into a **v3 onion service**: no
port-forward, no DNS, no TLS certificate, and the `.onion` address itself
authenticates the relay (§1.5). The transport is encrypted and authenticated with
no CA anywhere, which is the one property Mode A otherwise gives up.

**1. Install tor** (Netherchat does not bundle it):

```bash
brew install tor          # macOS
sudo apt install tor      # Debian/Ubuntu
apk add tor               # Alpine
sudo pacman -S tor        # Arch
```

`tor` must be in `PATH`. Without it, `netherchat-server --tor` exits `1` with that
same list rather than starting up degraded.

**2. Start the relay with `--tor`:**

```bash
netherchat-server --tor
# netherchat server listening   addr=:3000 version=…
# tor onion service ready       addr=abc123…onion:80
```

`--tor` is **additive**: the relay still listens on its normal TCP port; the onion
is an extra listener over the same hub, so onion and TCP clients share rooms. If tor
fails to start or publish, the relay logs a warning and continues on TCP — `--tor`
is best-effort and never takes the core relay down.

By default the address is **ephemeral** (new on each run). For a stable `.onion`,
persist tor's state with `--tor-data-dir ./tor-data` (back it up — it holds the
service key that *is* your address).

**3. Connect over Tor.** Each client needs a local tor SOCKS proxy (the `tor` daemon
on `127.0.0.1:9050`, or Tor Browser on `127.0.0.1:9150`):

```bash
netherchat connect --tor ws://abc123…onion:80 --room ops --name alice
netherchat connect --tor --tor-proxy 127.0.0.1:9150 ws://abc123…onion:80 --room ops
```

Because a v3 `.onion` address is derived from the relay's public key, reaching the
*right* address proves you reached the *right* relay — see
[`encryption.md`](encryption.md). There is no CA and no trust-on-first-use.

---

## No relay at all: Sneakernet Mode (`netherchat pair`, §1.1)

The whole thesis of Netherchat is that the normal channel cannot be trusted — and
the relay is the one component that thesis never turned on. When the relay host is
compromised, suspect, or simply unreachable, **Sneakernet Mode forms a war room with
no server at all.** Same BYO-key identity, same NaCl group crypto, same epoch
forward secrecy (`/vanish`), same sealed records (`/seal`) and scuttle receipts —
the only thing that changes is the transport. This works because the relay was
already blind: it routed ciphertext and held no keys, so removing it changes nothing
above the transport layer.

```bash
# LAN auto-discovery (same network): both run this; one /pairs the other
netherchat pair --lan --room ops --name alice
netherchat pair --lan --room ops --name bob       # discovers alice → /pair <fpr>

# Manual blob (a VPN, or any direct reachability): one offers, the other joins
netherchat pair --manual --room ops --name alice          # prints a signed offer
netherchat pair --manual --join --room ops --name bob     # paste alice's offer
```

`--lan` advertises via mDNS (`_netherchat._tcp`, UDP 5353) and lists discovered peers
with their fingerprints. Windows will ask for firewall permission the first time —
grant Private, not Public. **Discovery is never trust:** mDNS tells you someone is
there; your keys tell you who they are. A discovered peer is only a *candidate* —
you `/pair <fingerprint>` after verifying it out of band (or matching a `[[trust]]`
pin), and the Ed25519 handshake then proves the peer really holds that key. The
direct TCP connection is authenticated by the identity keys **before any message
frame is exchanged**, so a rogue process on the host's address cannot impersonate it.

> ### Honest scope: no NAT traversal
>
> Sneakernet works **on a LAN** and **via manual blob exchange**. It does **NOT**
> support general NAT traversal — if the two machines are on different networks
> without a shared LAN, you need the manual blob exchange **and** both machines must
> be reachable by the IP addresses in the offer blob (e.g. both on a VPN, both on
> the same LAN, or one machine port-forwarded).
>
> This is a deliberate design decision. General P2P NAT traversal requires a
> STUN/TURN rendezvous server, which re-introduces infrastructure cost and a trusted
> third party — exactly what Sneakernet Mode is designed to avoid.
>
> - **Teams on different networks:** use the relay (Mode A or B), or `--tor`.
> - **Teams on the same LAN or in the same room:** use `--lan`.
> - **Teams with a shared VPN or direct reachability:** use `--manual`.

> ### Honest scope: relay-less scuttle is single-actor
>
> The two-person rule (`[action.scuttle]` quorum, §1.3) requires the relay to route a
> second party's approval. Relay-less mode has no such path, so a manual `/scuttle`
> with a configured `quorum ≥ 2` is **refused** (fail-closed) rather than destroying
> the room unilaterally — the client prints why. Relay-less scuttle is therefore
> **single-actor only**: leave the quorum unset (or `1`) to allow the instant
> emergency burn, or use the relay when you need a two-person-gated scuttle.
> `netherchat pair --config <toml>` loads the policy so the refusal is enforced and
> the active governance is announced at startup.

Topology note: for two peers the connection is fully direct. For more than two, the
peer that initiated (the offerer / LAN host) coordinates membership and relays
between members — still no external infrastructure, and that peer is a full room
member who holds the key anyway, not a separate server. It works well for small
groups; for larger groups use the relay.

Configure defaults in `netherchat.toml` (read client-side by `netherchat pair` — the
relay never sees this table):

```toml
[direct]
port = 7777          # listening port for direct connections (0 = a free port)
lan_discovery = true # advertise on the LAN via mDNS, even without --lan
```

Flags take precedence over both: `--port` overrides `port`, and `lan_discovery` is
OR-ed with `--lan` rather than gating it — setting it to `false` never switches off
a `--lan` you asked for. Its practical effect is on `pair --manual`, which otherwise
only prints an offer blob: with `lan_discovery = true` that host also advertises
itself on the LAN so peers can discover and `/pair` it. Advertising binds UDP 5353
and announces your fingerprint and port to the local network, so it stays opt-in; if
multicast is unavailable the command says so and the manual offer still works.

---

## License and source

Netherchat is licensed **AGPL-3.0-or-later** ([LICENSE](../LICENSE)). What that means
in practice, by what you're doing:

**Running an unmodified build — for yourself, your team, or your users.** Nothing is
required of you. AGPL-3.0 §13 conditions its source-offer obligation on your having
*modified* the Program; an unmodified relay carries no such obligation. `/source` and
the `source` field of `/version` already point at upstream.

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

One symbol feeds the `/source` redirect, the `/version` field, and the startup log,
so a correctly stamped build carries the offer wherever a user looks. A build that
still points at upstream is offering source that does not contain your changes.

```
netherchat server listening  addr=:3000 version=X.Y.Z source=https://example.com/our-netherchat
```

**Building Netherchat into something you distribute.** This is the clause most people
mean when they ask about AGPL, and it is not §13. Importing `sealedrecord`, linking
the client, or shipping a product that contains Netherchat generally makes that
product a derivative work, which AGPL requires you to license under the same terms.
If your product is proprietary, or your contract prohibits copyleft in deliverables —
common in government and defense work — the AGPL is not the right instrument.

**Commercial licensing.** Astralis Software Systems holds the copyright in Netherchat
and offers alternative terms for exactly these cases: proprietary embedding, closed
deliverables, and hosted services that cannot publish their modifications.
Contributors grant a relicensing right ([CONTRIBUTING.md](../CONTRIBUTING.md)), so
the whole tree can be licensed cleanly — there is no fragmented-copyright problem to
diligence around. Contact
[Astralis Software Systems](https://astralis-systems.com).

*This is a plain-language summary, not legal advice. The
[license text](../LICENSE) governs.*

## Publishing your own builds

Tag a release (`git tag vX.Y.Z && git push origin vX.Y.Z`) to trigger the release
workflow. It needs these repository secrets:

- `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` — to push `salkreiner/netherchat`
- `HOMEBREW_TAP_TOKEN` — a PAT with write access to your Homebrew tap repo

Zero telemetry, always. The relay never phones home. The set of outbound calls it
can make is closed structurally rather than by promise: a `[[route]]` with a
`reply_url`, `--tor`, and the loopback-only `--healthcheck` probe. A CI test parses
every first-party package the relay links and fails on any call site not on that
allowlist, so a new one cannot land without this paragraph changing with it.
