# CLAUDE.md — Netherchat

Build, test, and contribution guide for Netherchat, a self-hostable, end-to-end
encrypted, real-time messaging system. The repository is a single Go module
(`github.com/salehkreiner/netherchat`) plus a TypeScript web client under `web/`.

---

## Prerequisites

- **Go 1.26+** — the only requirement to build and test the Go code. CGO is not
  needed and must stay disabled (see [CGO_ENABLED=0](#cgo_enabled0)).
- **Node.js 20+ and npm** — only for the web client in `web/`.
- Optional: [`just`](https://github.com/casey/just) (task runner), `air` (hot
  reload), Docker, `shellcheck`.

---

## Repository layout

```
cmd/
  netherchat-server/    the blind-relay server (the only server entrypoint)
  netherchat/           the CLI + TUI client (connect, send, tail, verify, report, …)
  netherchat-*/         standalone connector binaries (adapters, bridges)
protocol/               wire protocol types — crypto-free, imported by both sides
server/                 relay logic (internal/ws, internal/hub, config, …)
tui/                    client logic
  tui/internal/crypto/  the ONLY package containing end-to-end crypto
  tui/client/ tui/ui/   client core and the Bubble Tea UI
  tui/record/ …         sealed records, event log, report, etc.
web/                    browser client (Vite + TypeScript)
installer/              install.sh / install.ps1
docs/                   documentation
```

---

## Building

```sh
go build ./...                 # compile everything
just build                     # → go build -o bin/ ./cmd/...  (binaries into ./bin)
```

All binaries are static and built with `CGO_ENABLED=0`. Cross-compile from any host:

```sh
GOOS=linux  GOARCH=arm64 CGO_ENABLED=0 go build -o bin/ ./cmd/...
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o bin/ ./cmd/...
```

---

## Testing

```sh
go test ./...                  # full suite
go test -race ./...            # with the race detector (CI uses this)
go vet ./...                   # static analysis
gofmt -l .                     # must print nothing; CI fails on unformatted files
just check-boundary            # the blind-relay import-graph guard (see below)
```

The boundary guard runs directly as:

```sh
go test ./tui/e2e/ -run TestServerBinaryDoesNotLinkClientCrypto -v
```

Web client checks (run from `web/`): `npm run typecheck`, `npm run test`.

---

## Running the server locally

```sh
go run ./cmd/netherchat-server --addr :3000           # or: just server
go run ./cmd/netherchat-server -config netherchat.toml # with config-as-code
```

Or via Docker:

```sh
docker run -p 3000:3000 salkreiner/netherchat
docker compose up                                      # uses docker-compose.yml
```

Health check: `curl http://localhost:3000/health`.

## Running a client locally

```sh
go run ./cmd/netherchat connect ws://localhost:3000 --room general --name dev  # or: just connect
echo "deploy done" | go run ./cmd/netherchat send #ops                          # pipe mode
```

---

## Running the web client locally

```sh
cd web
npm install
npm run dev        # Vite dev server with hot reload
npm run build      # tsc -b && vite build → web/dist
npm run typecheck  # type-check only
```

---

## The import boundary (blind relay)

The end-to-end crypto lives in `tui/internal/crypto`. Go's `internal/` visibility
rule means **only packages under `tui/` can import it** — the server tree
(`cmd/netherchat-server`, `server/…`) physically cannot link it. This makes "the
server cannot read message content" a property of the build graph, not a promise.

- `protocol/` is crypto-free (wire types only). The server imports `protocol`; it
  never imports the client crypto package.
- A CI guard test, `TestServerBinaryDoesNotLinkClientCrypto`, fails the build if the
  server binary's transitive imports ever include the client crypto package.
- **Do not add a crypto import to any server-side package.** If you need to share a
  type across the boundary, put a crypto-free type in `protocol/`.

## CGO_ENABLED=0

All Go builds must keep CGO disabled. The crypto is pure Go
(`golang.org/x/crypto` + the standard library), so `CGO_ENABLED=0` holds — which
yields a static single binary, a `FROM scratch` Docker image, and cross-compilation
from any host. **Do not introduce a dependency that requires CGO.**

---

## CI/CD

GitHub Actions (`.github/workflows/ci.yml`) runs on pushes to `main` and on every
pull request:

- **build-test** — `gofmt` check, `go vet ./...`, `go build ./...`,
  `go test -race ./...`, and the blind-relay boundary guard.
- **shellcheck** — lints `installer/install.sh`.
- **docker** — builds the `salkreiner/netherchat` image and runs a `/health`
  smoke test.

`.github/workflows/release.yml` builds the cross-platform binary matrix and the
Docker image on a release tag. All CI jobs must be green before a change merges.

---

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/): a type prefix,
optionally with a scope.

- Types: `feat`, `fix`, `chore`, `docs`, `crypto`, `test`, `refactor`.
- Examples: `feat(server): …`, `fix(tui): …`, `crypto: …`, `docs: …`.
- One logical change per commit; imperative, present-tense subject line.

## Branches and pull requests

- `main` is the trunk and is always buildable.
- Develop on a topic branch and open a pull request against `main`.
- CI (build, vet, gofmt, race tests, boundary guard, shellcheck, docker) must be
  green before a change is merged.
- When the wire format changes, update `PROTOCOL.md` in the same change.
