# ARCHITECTURE_DECISION.md — Netherchat

**Astralis Software Systems**
**Status:** Proposed — awaiting operator approval before M1
**Author:** Claude Code (claude-opus-4-8), extended thinking
**Date:** 2026-06-04
**Supersedes:** none — this is the permanent founding architecture record

> This document is the output of the "First Responsibility" reasoning task in
> `CLAUDE.md`. No source code has been written. Per the project rules, M1
> (two TUI clients exchanging E2E-encrypted messages through the server) does
> **not** begin until this document is approved. Conflicts I found between the
> stated requirements and physical reality are surfaced explicitly in
> §8 — I have not papered over any of them.

---

## 0. How decisions were scored

Each decision lists the candidates from `CLAUDE.md`, scores them 1–5 (5 = best)
against the criteria the operator specified, applies a weight reflecting the
requirement priorities (the TUI is the v1 priority; the one-line installer and
small images are the first-impression surface), and states **what we give up**.

The scores are judgments, not measurements — but the weighting and the
reasoning behind each cell are written down so a reviewer can disagree with a
specific number rather than the conclusion as a whole.

A single thread runs through every decision: **the server is a blind relay.**
The end-to-end crypto lives in the *client*. That fact collapses several
apparent trade-offs (most importantly, it removes the server-side crypto-library
argument that would otherwise favor Rust) and it is the architectural backbone
that lets Netherchat say "we cannot read your messages" and mean it.

---

## 1. Decision: Server Language & Framework → **Go**

### Scoring

Weights: TUI-framework fit **×3**, cross-compile ease **×3**, WebSocket maturity
**×3**, contributor accessibility **×3**, Docker image size **×2**, concurrency
model **×2**, binary size **×2**, startup time **×1**. (Max weighted score = 95.)

| Criterion (weight) | Go | Rust | Bun+TS | Node+TS | Elixir |
|---|:--:|:--:|:--:|:--:|:--:|
| TUI framework fit (×3) | **5** | 4 | 3 | 3 | 1 |
| Cross-compile ease (×3) | **5** | 3 | 3 | 2 | 2 |
| WebSocket maturity (×3) | **5** | 4 | 4 | **5** | **5** |
| Contributor accessibility (×3) | 4 | 2 | **5** | **5** | 2 |
| Docker image size (×2) | **5** | **5** | 2 | 2 | 3 |
| Concurrency model (×2) | **5** | 4 | 3 | 3 | **5** |
| Binary size (×2) | 4 | **5** | 2 | 2 | 2 |
| Startup time (×1) | **5** | **5** | 4 | 4 | 3 |
| **Weighted total / 95** | **90** | 72 | 63 | 63 | 53 |

### Why Go

- **Cross-compilation is the cleanest in the industry.** `GOOS=darwin
  GOARCH=arm64 CGO_ENABLED=0 go build` produces a static binary for any target
  from any host — no cross-toolchain, no `osxcross`, no Zig shim. R1 (one-line
  installer on mac Intel + Apple Silicon, Linux ×4 distros, Windows/WSL2) and R7
  (pre-built binaries for all targets) are satisfied by a single CI matrix, and
  even from the operator's *Windows* machine alone. **This only holds with
  `CGO_ENABLED=0`, which our pure-Go crypto choice (Decision 3) guarantees.**
- **`FROM scratch` Docker images.** A static Go binary yields a ~10–20 MB image
  with nothing else in it — no shell, no libc, minimal attack surface. For a
  security product whose M2 milestone is `docker run … salkreiner/netherchat`,
  small + minimal is both a first impression *and* a hardening win. Rust ties
  here; everyone else is 4–8× larger.
- **Goroutine-per-connection is the textbook fit** for a WebSocket fan-out hub.
  One goroutine reads each socket, one hub goroutine owns room state, messages
  fan out over channels. This scales to tens of thousands of concurrent
  connections without async coloring, and it is *simple to read* — which matters
  for R6 and for onboarding subcontractors.
- **WebSocket maturity:** `github.com/coder/websocket` (formerly
  `nhooyr.io/websocket`) — context-aware, minimal, idiomatic, `net/http`-native.
  `github.com/gorilla/websocket` is the battle-tested fallback (back under active
  maintenance). Either is production-grade.
- **The decisive coupling:** Go shares a language with **Bubble Tea / Charm**
  (Decision 2), the best modern TUI toolkit in existence and a near-perfect match
  for R2's "looks like 2025, not ncurses 1998." One language spans server + TUI +
  the shared wire protocol and client crypto packages. Elixir scores highest on
  raw real-time concurrency but has *no* first-class TUI framework — choosing it
  forces a second language for the v1-priority client, which is disqualifying.

### Framework choices within Go

- **HTTP (REST config endpoints only — R4):** the standard library `net/http`
  with the Go 1.22+ `ServeMux` (method + path patterns). Three endpoints
  (`/health`, `/rooms`, `/version`) plus the webhook receiver do **not** justify
  a web framework. A senior engineer notices when you pull a framework for four
  routes; we won't.
- **WebSocket:** `github.com/coder/websocket` (clean, modern, `wsjson` helpers),
  with `gorilla/websocket` named as the conservative alternative if we hit an
  edge case.
- **Config:** `github.com/pelletier/go-toml/v2` (Decision 4).

### What we give up

- **Raw single-core throughput and the absence of GC pauses** that Rust offers.
  Irrelevant at Netherchat's scale; the workload is I/O-bound fan-out, and Go's
  GC is sub-millisecond. We are not throughput-bound, we are correctness- and
  DX-bound.
- **The pristine Rust crypto ecosystem** (`libsignal`, OpenMLS). We accept that
  the eventual MLS migration (Decision 3) will be an interface-level swap, very
  likely a CGO/FFI binding to OpenMLS or a then-mature Go MLS library — *on the
  client only*. The server never links crypto, so this never costs us the
  static-binary property where it matters most.
- **TypeScript code-sharing with the future web client (R3).** The web client
  will be a separate TS/React codebase. We share a *documented wire protocol*
  (`PROTOCOL.md`, R6), not code. This is in fact the cleaner architecture the
  brief asks for: "the server must not care whether the connecting client is TUI
  or web" (R4).
- **Elixir's WhatsApp-grade channel scaling.** Not needed at v1; the Redis
  adapter sketched in the deployment notes covers multi-node later.

---

## 2. Decision: TUI Framework → **Bubble Tea (+ Lip Gloss, Bubbles, Glamour)**

### Scoring

Weights: theme flexibility **×3**, mouse support **×3**, rendering quality **×3**,
language match with the Go server **×3**, dependency footprint **×2**.
(Max weighted = 70.)

| Criterion (weight) | Bubble Tea | Ratatui | Textual | Ink | blessed |
|---|:--:|:--:|:--:|:--:|:--:|
| Theme flexibility (×3) | **5** | 4 | **5** | 4 | 2 |
| Mouse support (×3) | **5** | 4 | 4 | 2 | 3 |
| Rendering quality (×3) | **5** | **5** | 4 | 3 | 1 |
| Language match w/ server (×3) | **5** | 1 | 1 | 1 | 1 |
| Dependency footprint (×2) | **5** | **5** | 1 | 2 | 2 |
| **Weighted total / 70** | **70** | 52 | 44 | 34 | 25 |

### Why Bubble Tea

- **Themes that hot-swap (R2: "apply instantly without restart").** Lip Gloss
  styling is declarative — each theme is a struct of `lipgloss.Style` /
  `lipgloss.Color` values. Switching the active theme struct and re-rendering on
  the next frame *is* instant theme change, with no special machinery. TrueColor
  and adaptive (light/dark) colors are first-class, which is exactly what the
  named palettes (`nether`, `abyss`, `ember`, `ghost`, `dracula`, `gruvbox`,
  `solarized`, `sprinkles`) require.
- **Mouse (R2): click rooms, scroll history, click usernames.** Bubble Tea
  exposes mouse cell-motion / all-motion events out of the box.
- **Modern rendering.** The Charm stack (Bubble Tea for the Elm-style
  Model/Update/View loop, **Lip Gloss** for layout + color, **Bubbles** for
  ready-made viewport/list/textinput/spinner components, **Glamour** for Markdown
  + syntax-highlighted code blocks) is the toolkit behind the CLI tools developers
  already love. Glamour directly satisfies R2's "inline code rendering with
  syntax highlight." `mdp/qrterminal` (pure Go) renders the `/invite` QR code.
- **One language, compiler-enforced boundaries.** The TUI compiles into the same
  single static binary as the CLI sub-commands (`send`, `tail`), shares the
  `protocol` package with the server, and is the *only* binary that links the
  client crypto package. No runtime, no `node_modules`, no Python.
- The **Elm Architecture** (one message type, one update function) is an ideal
  fit for a client juggling many event sources — keystrokes, mouse, inbound
  socket frames, TTL timers, presence updates — and it is straightforward to
  unit-test.

### What we give up

- **Ratatui's absolute rendering ceiling and Rust's speed.** Bubble Tea is more
  than fast enough for chat; large scrollback is handled with a virtualized
  `viewport`. Ratatui would also cost us the language match (score 1) — a
  second-language client is not worth marginal rendering headroom.
- **Textual's CSS-like theming (TCSS) ergonomics**, which are genuinely lovely —
  but Textual drags in a Python runtime, which `CLAUDE.md` itself calls "ugly for
  a security tool," and which fights R1's single-binary preference.
- **Ink's React component model** for web-dev contributors — but those
  contributors will work in the *actual* React codebase (the web client), so the
  familiarity isn't lost, just relocated.

> **Conflict flagged (see §8.1):** No TUI framework — Bubble Tea included — can
> change the terminal's *font*. The `/font` slash command and the per-theme font
> names in `CLAUDE.md` (IBM Plex Mono, Fira Code, …) cannot be honored as literal
> font switching inside the terminal; font is owned by the user's terminal
> emulator. This needs an operator decision; my recommended resolution is below.

---

## 3. Decision: Encryption Architecture → **NaCl/libsodium-equivalent group scheme (pure Go), designed as MLS-shaped epochs**

This is the decision the operator asked to have justified fully, so this section
is the longest and most concrete. A senior engineer's BS detector fires hardest
here, so I state the actual scheme, name the actual primitives, and — critically
— state the **limits** plainly rather than overclaiming.

### Candidates

| Approach | Server-blind? | Forward secrecy | Group support | Solo-dev complexity | Verdict |
|---|:--:|:--:|:--:|:--:|---|
| **TLS only** | ❌ operator can read | n/a | n/a | trivial | **Rejected** — destroys the brand promise (R5, requirement 1). |
| **Signal (Double Ratchet + X3DH)** | ✅ | per-message (best) | via Sender Keys (complex) | very high; official lib is C/Rust (CGO) | Deferred — gold standard for 1:1, but group Sender-Keys + CGO is too much risk for a solo-dev MVP. |
| **MLS (RFC 9420)** | ✅ | per-epoch, + PCS | **purpose-built for groups** | high; best lib (OpenMLS) is Rust, Go libs nascent | **Migration target**, not v1. This is where the industry is going. |
| **NaCl / libsodium group scheme** | ✅ | per-epoch (with ratchet + deletion) | custom key distribution | manageable; **pure Go, no CGO** | **Selected for v1.** Audited primitives, trivial cross-compile, honest claims. |

### Why the hybrid wins for v1

The non-negotiable is **the server cannot read message content**. All four
non-TLS approaches satisfy that, because in all of them the symmetric content key
never reaches the server. The differentiators for v1 are **solo-dev complexity**
and **build/distribution impact** — and here the NaCl approach is decisively best
*because we can implement libsodium-equivalent primitives in pure Go*:

```
golang.org/x/crypto/nacl/box          // X25519 + XSalsa20-Poly1305  (authenticated key wrap)
golang.org/x/crypto/chacha20poly1305  // XChaCha20-Poly1305          (message AEAD, 24-byte nonce)
golang.org/x/crypto/curve25519        // X25519 ECDH
crypto/ed25519 (stdlib)               // identity signatures / fingerprint
golang.org/x/crypto/hkdf              // epoch key ratchet
```

All pure Go → `CGO_ENABLED=0` holds → the static binary and trivial
cross-compilation (Decisions 1 & 7) survive. We get audited, ubiquitous NaCl
crypto **without** the CGO penalty that libsignal/OpenMLS would impose.

### The v1 scheme (concrete)

**Identity (per client, generated on first run, stored locally only).**
- An **Ed25519** signing keypair (authenticity + the fingerprint shown by
  `/whoami`).
- An **X25519** key-agreement keypair (receiving wrapped room keys).
- Private keys live at `~/.config/netherchat/identity.key` (`%APPDATA%` on
  Windows), `0600`. They are **never** transmitted in private form. The public
  halves *are* the user's identity. **No key escrow, no recovery** (requirement
  5) — losing the key file means losing access, and this is documented
  prominently as a feature.

**Room keys and epochs.**
- A room has a current 32-byte symmetric **room key `RK_e`** for **epoch `e`**.
- A new epoch begins on any of: a member joining or leaving, a `/vanish`, a
  manual rotation, or a time/message-count cadence.
- On epoch advance, the new key is **ratcheted forward** and the old one is
  **destroyed**:
  `RK_{e+1} = HKDF-Expand(RK_e, "netherchat/epoch-ratchet/v1")`, then `RK_e` is
  zeroed in memory. For membership *additions* a fresh random key is generated
  instead of a pure ratchet, so a new member cannot derive prior epochs.

**Key distribution (server as blind relay — requirement 4).**
- The member who advances the epoch wraps `RK_{e+1}` **individually for each
  current member** using authenticated `nacl/box` to that member's X25519 public
  key (sender-authenticated, so recipients know which member rotated the key).
- These wrapped blobs are sent through the server, which routes them by
  recipient public key. **The server sees only ciphertext key-wraps addressed to
  public keys; it never sees `RK`.**

**Messages.**
- Encrypted client-side with **XChaCha20-Poly1305** under `RK_e`, fresh random
  24-byte nonce per message (XChaCha's extended nonce makes random nonces safe
  without a counter). The plaintext is signed with the sender's Ed25519 key.
- On the wire: `{ room, epoch, sender_pubkey, nonce, ciphertext, sig }`. The
  server routes this opaque envelope. Recipients verify the signature, then
  decrypt with `RK_e`. **A Wireshark capture shows ciphertext only — this is the
  M1 acceptance test.**

### Properties — stated honestly

- ✅ **Server-blind (the non-negotiable).** Content keys are never on the server;
  message plaintext is never on the server; default zero-persistence (R4) means
  even ciphertext isn't retained. The "we cannot read your messages" claim is
  credible at v1.
- ✅ **Forward secrecy at epoch granularity (requirement 2).** Because old `RK`s
  are deleted on epoch advance and nothing is persisted by default, compromise of
  the *current* state does not reveal messages from already-closed epochs.
  Compromise of a long-term *identity* key does not retroactively decrypt past
  messages — messages are encrypted under room keys, not under the identity key,
  and the past room keys are gone.
- ✅ **Group messaging (requirement 3).** Any number of members hold `RK_e`;
  distribution is `O(members)` wrapped blobs per epoch.
- ⚠️ **Not per-message forward secrecy.** This is weaker than Signal's Double
  Ratchet or MLS. Within a single epoch all messages share `RK_e`. We will say
  exactly this in `docs/encryption.md` and never imply otherwise.
- ⚠️ **The custom group-key-distribution layer is the risk surface.** The
  primitives are audited; the *protocol gluing them together* is ours, and DIY
  group crypto is where mistakes live. Mitigations: keep the custom layer minimal
  and fully documented, add known-answer/property tests, and **commission an
  external cryptographic review before any paid/cloud claim (M5).** Until then,
  `docs/encryption.md` describes v1 as "audited primitives, custom group protocol,
  pending formal review."
- ⚠️ **Metadata is not hidden.** E2E protects *content*, not the fact that
  account A is in room #ops or message sizes/timing. Standard, and stated plainly.

### Why this preserves the MLS path (the explicit requirement)

Our model — **epochs, a per-epoch group secret, and membership changes that
trigger a rekey** — is precisely MLS's mental model (MLS has epochs, group
secrets, and Commits that advance epochs on membership change). By putting all of
it behind a `GroupCrypto` interface (`Encrypt`, `Decrypt`, `AdvanceEpoch`,
`WrapKeyFor(member)`, `MemberAdded/Removed`), the future swap to MLS/TreeKEM is an
**implementation change behind a stable interface and a versioned wire protocol**,
not a redesign. `PROTOCOL.md` will carry an explicit protocol-version field so a
TreeKEM-based epoch advance can coexist during migration.

### What we give up

- Per-message forward secrecy and strong post-compromise security (Signal/MLS)
  at v1 — deferred deliberately, with the migration designed in.
- Formal security proofs that MLS/Signal carry — mitigated by minimizing and
  reviewing the custom layer and treating the audit as a release gate for the
  paid tier.
- Sender anonymity within a room — we deliberately authenticate senders
  (Ed25519) because Netherchat is team/ops chat where "who sent this" matters.

---

## 4. Decision: Config Format → **TOML**

| | TOML | YAML | HCL |
|---|:--:|:--:|:--:|
| Human-friendly, unambiguous types | ✅ | ⚠️ ("Norway problem", `no→false`) | ✅ |
| Whitespace-safe | ✅ | ❌ significant indentation | ✅ |
| Go support | ✅ `go-toml/v2` (fast, maintained) | ✅ | ⚠️ heavier parser |
| Fit for static room/port/TLS config | ✅ tables map to rooms | ✅ | overkill (expressions/interpolation unused) |

**TOML**, decisively — and `CLAUDE.md` already names the file `netherchat.toml`
throughout (R4 and the project structure's `netherchat.toml.example`), so this is
also the consistent choice. Tables (`[rooms.ops]`) map cleanly to per-room config.
YAML's type ambiguity and indentation footguns are exactly what a *security*
config-as-code file should avoid. HCL's dynamic expressions buy us nothing for
static configuration.

**What we give up:** HCL's interpolation/expressions (not needed) and YAML's
ops-world ubiquity (ops engineers read TOML without complaint, and we dodge the
YAML footguns).

---

## 5. Decision: Monorepo Tooling → **single Go module + `go`-native build, orchestrated by `just` (with a `make dev` shim)**

- **Module layout:** a single Go module `github.com/salehkreiner/netherchat`.
  A single module keeps cross-package refactors
  trivial for a small team; Nx/Turborepo are TS-oriented and Go-irrelevant here,
  and multi-module `go.work` adds versioning ceremony we don't need yet.
- **The blind-relay boundary is enforced by the compiler, not by good
  intentions.** Client crypto lives at `tui/internal/crypto`. Go's `internal/`
  rule means *only* packages rooted at `tui/` can import it — the server tree
  (`server/…`, `cmd/netherchat-server`) physically **cannot** link the
  decryption code. "The server cannot read your messages" becomes a property of
  the import graph, verifiable with `go list`, not a promise. A CI check asserts
  the server binary's transitive imports never include the crypto package.
- **Task runner:** a `justfile` is the canonical entrypoint (`just dev`, `just
  build`, `just docker`, `just release`). `just` is a single cross-platform
  binary — important because the dev box is **Windows without a real WSL distro**
  (see §8.2), where GNU `make` is not native.
- **Honoring R6's literal `make dev`:** a thin `Makefile` whose `dev` target
  shells out to `just dev`, so the documented muscle-memory command works for
  contributors on mac/Linux while `just` remains the real tool. (Operator: confirm
  you're fine with `just`-as-primary; see §8.3.)
- **Hot reload (R6):** `air` (`github.com/air-verse/air`) watches the server and
  rebuilds on change; wired into `just dev`.
- **Release (R7):** **GoReleaser** produces the GitHub-release binary matrix
  (darwin amd64/arm64, linux amd64/arm64, windows amd64), the Homebrew formula,
  and the `salkreiner/netherchat` Docker image in one config — a direct match for
  R7 and the reference installer benchmark.

---

## 6. Recommended monorepo structure

```
netherchat/
├── CLAUDE.md
├── ARCHITECTURE_DECISION.md        # this file
├── PROTOCOL.md                     # wire protocol for third-party clients (R6) — next deliverable
├── README.md
├── LICENSE
├── go.mod  go.sum                  # single module: github.com/salehkreiner/netherchat
├── justfile                        # canonical task runner
├── Makefile                        # thin shim: `make dev` -> `just dev` (honors R6)
├── .goreleaser.yaml                # release matrix + Homebrew + Docker (R7)
├── Dockerfile                      # multi-stage; final stage FROM scratch
├── docker-compose.yml              # team deployment variant (R1)
├── netherchat.toml.example
├── .github/workflows/              # CI: lint, test, build matrix, import-graph guard, release
│
├── cmd/
│   ├── netherchat-server/main.go   # server entrypoint (thin)
│   └── netherchat/main.go          # client entrypoint: TUI + `send`/`tail` subcommands (thin)
│
├── protocol/                       # SHARED, importable by everyone — wire types only
│   ├── envelope.go                 # message/key-wrap/control framing, opcodes
│   └── version.go                  # PROTOCOL_VERSION (enables MLS migration coexistence)
│
├── server/                         # server logic (blind relay) — links protocol, NOT crypto
│   └── internal/
│       ├── config/                 # TOML load/validate
│       ├── hub/                    # rooms, connection registry, fan-out routing
│       ├── ws/                     # websocket transport (coder/websocket)
│       ├── relay/                  # blind key-wrap routing by recipient pubkey
│       ├── webhook/                # inbound per-room webhooks (R4)
│       ├── api/                    # REST: /health /rooms /version
│       ├── invite/                 # one-time invite tokens
│       ├── ttl/                    # ephemeral room expiry
│       ├── store/                  # persistence interface (in-mem default; SQLite adapter; Postgres-ready)
│       └── ratelimit/
│
├── tui/                            # client logic — the ONLY tree that links crypto
│   ├── client/                     # ws client, reconnect, presence
│   ├── commands/                   # non-interactive: send, tail (pipe/Unix integration)
│   ├── internal/
│   │   └── crypto/                 # E2E: identity, epoch ratchet, nacl/box keywrap, XChaCha AEAD
│   └── ui/                         # Bubble Tea
│       ├── app/                    # root Model/Update/View
│       ├── theme/                  # 8 Lip Gloss themes; instant switch
│       ├── roomlist/  chat/  members/
│       └── input/                  # slash-command parser + autocomplete
│
├── web/                            # v2 browser client (R3) — scaffold only now (TS/React)
│   ├── package.json
│   └── src/
│
├── installer/
│   ├── install.sh                  # mirrors a reference installer UX (checkmarks, OS detect, no-sudo, clean uninstall)
│   └── install.ps1                 # Windows/PowerShell
│
└── docs/
    ├── self-hosting.md
    ├── encryption.md               # the honest crypto write-up from §3, incl. limitations
    └── commands.md
```

**Dependency rule (CI-enforced):** `cmd/netherchat-server → server/… → protocol`.
The crypto package is reachable **only** through `tui/`. The server is, by
construction, incapable of decrypting.

---

## 7. Bootstrap commands

> **Reality check (see §8.2):** there is no general-purpose WSL2 distro on this
> machine — only Docker Desktop's backend distros, and `bash` is not available.
> Go 1.26.3 is installed natively on Windows and cross-compiles to every release
> target with `CGO_ENABLED=0` (which our pure-Go crypto guarantees). **The
> recommended dev path is therefore native Windows + PowerShell**, with Docker
> Desktop for container builds. Installing a real Ubuntu distro
> (`wsl --install -d Ubuntu`) is optional and only needed if you want
> Linux-native development; it is not required to ship.

The repo already exists at `C:\Users\saleh\netherchat` with `CLAUDE.md` committed
and git initialized on `main`. These are the *new* steps, run in **PowerShell**
from the repo root (already the working directory):

```powershell
# 1. Initialize the Go module
go mod init github.com/salehkreiner/netherchat

# 2. Create the directory skeleton (§6)
$dirs = @(
  "cmd\netherchat-server","cmd\netherchat",
  "protocol",
  "server\internal\config","server\internal\hub","server\internal\ws",
  "server\internal\relay","server\internal\webhook","server\internal\api",
  "server\internal\invite","server\internal\ttl","server\internal\store",
  "server\internal\ratelimit",
  "tui\client","tui\commands","tui\internal\crypto",
  "tui\ui\app","tui\ui\theme","tui\ui\roomlist","tui\ui\chat",
  "tui\ui\members","tui\ui\input",
  "web\src","installer","docs",".github\workflows"
)
$dirs | ForEach-Object { New-Item -ItemType Directory -Force -Path $_ | Out-Null }

# 3. Core dependencies
go get github.com/coder/websocket
go get github.com/pelletier/go-toml/v2
go get github.com/charmbracelet/bubbletea
go get github.com/charmbracelet/lipgloss
go get github.com/charmbracelet/bubbles
go get github.com/charmbracelet/glamour
go get golang.org/x/crypto/nacl/box
go get golang.org/x/crypto/chacha20poly1305
go get golang.org/x/crypto/hkdf
go get github.com/mdp/qrterminal/v3            # /invite QR (pure Go)

# 4. Dev tooling (single binaries; install once)
go install github.com/air-verse/air@latest         # hot reload (R6)
go install github.com/goreleaser/goreleaser/v2@latest
winget install --id Casey.Just -e                  # `just` task runner (or: scoop install just)

# 5. Sanity check
go build ./...
```

`go.mod` will pin `go 1.26`. (On macOS/Linux contributor machines the same steps
apply with forward slashes; `just`/`air`/`goreleaser` install via Homebrew.)

---

## 8. Conflicts & clarifications (not papered over)

Per `CLAUDE.md` instruction #3, these are surfaced rather than silently resolved.
None block writing this document; items 8.1–8.3 want an operator decision before
or during M3, and 8.5 should be settled before M3.

### 8.1 — `/font` and per-theme fonts cannot work as literal font switching in a TUI
A terminal application cannot change the terminal emulator's font; that is owned
by the user's terminal (iTerm2, Windows Terminal, etc.). The theme font names
(IBM Plex Mono, Fira Code, …) and the `/font` command can be honored as:
**(a)** advisory — `/font` prints the recommended font + how to set it in common
terminals, and `/whoami`/theme docs name the intended font; **(b)** fully honored
later in the **web client** (R3), where we control CSS `@font-face`. My
recommended resolution: ship `/font` as advisory in the TUI, make it real in the
web client, and adjust glyph/box-drawing choices per theme for graceful
degradation. **Resolved (2026-06-04):** advisory in the TUI — print the
recommended font + terminal setup instructions; real CSS `@font-face` in the web
client.

### 8.2 — "WSL2 available and preferred" is not currently true on this machine
Only `docker-desktop` backend distros exist; no Ubuntu/Debian, and `bash` returns
"Permission denied." I have written §7 for native-Windows Go development, which is
fully sufficient (Go cross-compiles to all targets from Windows). If you want
Linux-native dev, `wsl --install -d Ubuntu` first. **Confirm which you prefer.**

### 8.3 — R6 says `make dev`; I recommend `just` as the real runner
`just` is one cross-platform binary and far nicer than GNU `make` on Windows. I
keep a `make dev` shim that calls `just dev` so the documented command still
works. **Resolved (2026-06-04):** `just` is primary, `make dev` shim accepted.

### 8.4 — Encryption honesty (informational, not a blocker)
v1 forward secrecy is **per-epoch, not per-message**, and the group key
distribution is a **custom protocol over audited primitives**. `docs/encryption.md`
will say exactly this, and I recommend an **external crypto review as the gate for
the paid/cloud tier (M5)** — not for M1/M2/M3. The "we cannot read your messages"
claim is fully sound at v1; I just won't let us imply Signal/MLS-grade forward
secrecy before MLS lands.

### 8.5 — `/exec` ("run command on server") is a serious surface for a security product
Remote command execution is the single most dangerous feature in the spec. R2/R4
already say it requires explicit server-side opt-in. I will design it **off by
default**, gated behind a `netherchat.toml` allowlist of permitted commands (not
arbitrary shell), per-room permission, full audit logging, and never enabled by
the installer. **Flagging for your awareness; recommend we confirm the exact
constraint model before building `/exec` in M3.**

### 8.6 — GitHub module path
**Resolved (2026-06-04):** module path is `github.com/salehkreiner/netherchat`.

---

## 9. Summary of decisions

| # | Decision | Choice | Headline reason | Chief trade-off accepted |
|---|---|---|---|---|
| 1 | Server language/framework | **Go** + stdlib `net/http` + `coder/websocket` | Best cross-compile + tiny images + goroutine fan-out + shares language with the TUI | Rust's raw speed & crypto ecosystem |
| 2 | TUI framework | **Bubble Tea / Charm** | Instant themes, mouse, modern look, same language, no runtime | Ratatui's rendering ceiling; Textual's TCSS |
| 3 | Encryption | **NaCl group scheme (pure Go), MLS-shaped epochs** | Server-blind with audited primitives, no CGO, MLS migration designed in | Per-message FS deferred to MLS; custom layer needs audit |
| 4 | Config format | **TOML** | Unambiguous, whitespace-safe, already the named format | HCL expressions / YAML ubiquity |
| 5 | Monorepo tooling | **Single Go module + `just` (+ `make` shim)** | Simple refactors; compiler-enforced blind-relay boundary | `go.work` multi-module isolation |

**Next step:** await operator approval and answers to §8. On approval, proceed to
**M1** — two TUI clients exchanging E2E-encrypted messages through the server,
encryption included, no UI polish — built strictly in the M1→M5 order.

*ARCHITECTURE_DECISION.md — v1 — Astralis Software Systems — 2026-06-04*
