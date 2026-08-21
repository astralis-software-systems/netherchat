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

---

## The `§N.N` markers in comments

Comments across this tree carry cross-references of the form `§1.3`, `§2.2`,
`§5.6`. There are **477 of them across 146 files**, and they are load-bearing in
one specific way: `git grep "§1.3"` is the fastest way to find every site that
implements the Two-Person Rule, and there is no other cross-file grouping of
feature-related code in the repository.

**They are not all citing the same thing, and one population has no target.**

| Population | Where | Resolves? |
|---|---|---|
| Markers that **name their document** — `PROTOCOL.md §17`, `ARCHITECTURE_DECISION.md §8.1`, `RFC 3986 §3.5`, `docs/self-hosting.md`, `identity-v1-spec §5.6` | ~21 lines | **Yes.** Follow the name. Do not touch these. |
| Markers under `tui/attest/`, `tui/record/identity.go` and `protocol/identity_signing.go` | ~14 lines | **Yes** — they cite `docs/identity-v1-spec-2026-08-17.md`, which exists. `§1.1` is its field-by-field section, `§2.1` the preimage, `§5.6` the two-timestamp bracket, `§9.x` its guard rules. |
| Bare `§1.x` / `§2.x` / `§3.x` everywhere else | the remaining ~440 lines | **No document in this repository defines them.** |

The third population points at a numbered product specification that is not in
the tree and was not recovered. Grepping every `.md` here for a heading of the
form `§1.3`, `## 1.3` or `### 1.3` in that namespace returns nothing;
`PROTOCOL.md` uses a different, flat scheme (`## 1. Transport` … `## 17.`) and
itself *uses* the foreign marker at `## 15. Privileged-action quorum (Two-Person
Rule, §1.3)` without defining it.

**Disposition: they stay, and this table is what they mean.** Deleting them
would cost the cross-file grouping and buy nothing; rewriting 440 comments to
name a document that does not exist would be worse. Treat a bare `§N.N` as a
**stable internal feature tag**, defined here:

| Tag | Feature | Strongest evidence in the tree |
|---|---|---|
| `§1.1` | Sneakernet / relay-less pair mode | `netherchat pair … (§1.1 Sneakernet)` |
| `§1.2` | Status Beacon (`/beacon`, `beacon-link`, the REST API) | `beaconLinkCmd implements … (§1.2)` |
| `§1.3` | Two-Person Rule / privileged-action quorum | `Two-Person Rule (§1.3)`, and `PROTOCOL.md §15`'s own heading |
| `§1.4` | Sealed Record and the signed roster | `a sealed record (§1.4), a signed roster (§1.4)` |
| `§1.5` | `/scuttle`, the scuttle receipt, and Tor reachability | `a scuttle receipt (§1.5)` |
| `§1.6` | The Two-Way Bridge, and the dead-man's switch / auto-scuttle | `netherchat bridge (§1.6 — the Two-Way Bridge)` |
| `§1.7` | The structured event stream (`tail --json`, `eventlog`) | `the structured, versioned, metadata-only event stream (§1.7)` |
| `§2.1` | Desktop notifications | `NotifyConfig is the CLIENT-side desktop-notification policy (§2.1)` |
| `§2.2` | Live log streaming (`netherchat stream`, `/stream`) | `streamCmd implements … (§2.2)` |
| `§2.3` | **Ambiguous — two features share this tag.** Encrypted file transfer (`protocol/file.go`, `tui/client/file.go`, `server/internal/ws/transfers.go`) and the status line (`cmd/netherchat/statuscmd.go`, `tui/statusline/`). One of the two is a mis-citation and the tree cannot say which. | `relay-blind transfer (§2.3)` vs `netherchat status … (§2.3)` |
| `§2.4` | Invite links and terminal QR codes | `also render the link as a scannable terminal QR code (§2.4)` |
| `§2.5` | Slash-command macros | `Macro expansion happens BEFORE dispatch (§2.5)` |
| `§2.6` | `netherchat report` — HTML / Markdown incident timelines | `reportCmd implements … (§2.6)` |
| `§2.7` | `/replay` — streaming a prior sealed record into a retro room | `replayCmd implements … (§2.7)` |
| `§3.1` | `netherchat doctor` | `doctorReport is the result of `netherchat doctor` … (§3.1)` |
| `§3.2` | Relay-less quorum limits (a second party must be reachable) | `refuse rather than burn unilaterally (§3.2)` |
| `§3.3` | v3 per-message Ed25519 signatures | `v3 adds room-bound, OPTIONAL per-message Ed25519 signatures (§3.3)` |

Two caveats this table does not paper over. `§2.3` above is genuinely ambiguous
in the surviving evidence. And `§1.5/D5` in `cmd/netherchat/main.go` and
`config_test.go` pairs the tag with a `D`-prefixed decision id from a different
scheme again; it is about fail-closed config loading, not about `/scuttle`.

**When you add a marker:** name the document (`PROTOCOL.md §17`, `roadmap §8`,
`identity-v1-spec §5.6`). Bare tags are inherited, not a convention to extend.
