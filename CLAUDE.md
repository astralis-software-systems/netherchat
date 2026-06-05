# CLAUDE.md — Netherchat
### Astralis Software Systems, LLC
### Operator: saleh · Environment: Windows 11 (WSL2 + PowerShell) · Claude Code target: claude-opus-4-8, extended thinking enabled

---

## Mission Statement

Netherchat is a self-hostable, end-to-end encrypted, real-time messaging system built
first for developers and DevOps engineers, and designed to scale to non-technical users
via a web client without ever compromising the developer-first experience.

It is the third product in the Astralis Software Systems portfolio alongside:
- **Scrubadubber** (scrubadubber.com) — multi-agent prompt scrubber, PII/token sanitizer
- **FireCondor** (firecondor.com) — AI-driven wildfire risk detection and alerting

Netherchat shares Scrubadubber's delivery philosophy: a one-line curl installer,
a public GitHub repo, transparent open-source architecture, and a Docker-first deployment
story. The business model is Option B (self-hosted free + cloud-hosted paid), freemium
tiers to be designed after core architecture is proven.

The product must impress a seasoned senior engineer on first contact. Every decision
should pass the test: "Would a developer who has seen everything be quietly impressed
by this, or roll their eyes?"

---

## Your First Responsibility

Before writing a single line of code, you must reason through the framework and
architecture selection problem completely. This is a `ultrathink` task. There are
real tradeoffs and the wrong choice will create compounding pain across:

- Cross-platform packaging (Windows/Mac/Linux)
- TUI client quality and theme-ability
- WebSocket server performance under concurrent connections
- E2E encryption library availability and maturity
- Docker image size (small images = faster installs = better first impression)
- Long-term federation design compatibility
- Developer experience for contributors (Astralis may onboard subcontractors)

Do not anchor on the first reasonable answer. Generate the full space of options,
score them against the requirements below, and produce a justified recommendation
with explicit acknowledgment of what you are trading away.

---

## Hard Requirements

### R1 — One-line installer
```bash
curl -fsSL netherchat.com/install | bash
```
This must work on:
- macOS (Intel + Apple Silicon)
- Linux (Ubuntu 22.04+, Debian, Alpine, Arch)
- Windows via WSL2

The installer pulls a Docker image OR a single self-contained binary.
Preference is a **single static binary** where the language allows it,
because it removes the Docker dependency for power users who want zero overhead.
Docker-compose variant must also exist for teams who want it.

### R2 — TUI Client (v1 priority)
A terminal UI that a developer opens and actually wants to use daily.
Requirements:
- Mouse support (click to focus rooms, scroll history)
- Full keyboard navigation (vi-style bindings optional but appreciated)
- Slash command system with autocomplete (`/theme`, `/font`, `/vanish`, `/exec`, `/whoami`, `/help`, `/invite`, `/ttl`)
- Named themes: `nether` (deep violet), `abyss` (cold cyan), `ember` (orange), `ghost` (monochrome), `sprinkles` (rainbow easter egg), `gruvbox`, `dracula`, `solarized`
- Theme changes apply instantly without restart
- Timestamp display, online presence indicators, unread counts per room
- Inline code rendering (backtick blocks rendered with syntax highlight if possible)
- The TUI must not look like ncurses from 1998. It must look like something built in 2025.

### R3 — Web Client (v2, but architect for it now)
A browser-based client connecting to the same server via WebSocket.
The web client uses the Netherchat brand design system already established:
- Background: `#0a0a12`, font: Space Grotesk + JetBrains Mono
- Accent: `#7c3aed` (violet), theme system mirrors TUI themes
- This is how non-technical users access Netherchat
- The server must not care whether the connecting client is TUI or web

### R4 — Server Architecture
- WebSocket-first, HTTP for REST config endpoints only
- Room management: rooms defined in `netherchat.toml` (config-as-code)
- Default: **zero persistence** — no messages written to disk
- Optional: `persistence = true` in config writes to local SQLite only (never cloud)
- Inbound webhooks: every room gets a webhook URL automatically
- Pipe-friendly CLI: `echo "deploy done" | netherchat send #ops`
- SSH fallback mode: `ssh user@host netherchat` drops you into TUI (no client install needed)
- Rate limiting, room-level permissions, invite-only rooms
- Zero telemetry by default — the server never phones home

### R5 — Encryption
See the Encryption Architecture section below. Claude must justify the chosen approach.

### R6 — Developer Experience (contributor-facing)
- Monorepo structure (server + tui-client + web-client + installer + docs)
- Single `make dev` spins up the full local stack
- Hot reload on server changes during development
- Clear separation: server knows nothing about client implementation details
- Protocol documented in `PROTOCOL.md` so third-party clients can be built

### R7 — Packaging and Distribution
- GitHub releases with pre-built binaries for all targets
- Docker Hub image: `astralis/netherchat`
- Homebrew formula (Mac)
- `install.sh` mirrors Scrubadubber's installer UX exactly
- Version pinning supported: `curl ... | bash -s -- --version 1.2.0`

---

## Architecture Reasoning Task

You must reason through and produce a justified recommendation for each of the
following decision points. For each, list at least 3 options, score them, pick one,
and state what you are giving up.

### Decision 1: Server Language & Framework

Candidates to evaluate (at minimum):
- **Go** — single binary, excellent concurrency, gorilla/websocket or nhooyr.io/websocket,
  small Docker images (FROM scratch possible), fast compile, strong stdlib
- **Bun + TypeScript** — fast runtime, native WebSocket, good ecosystem, familiar to
  web devs, but runtime dependency
- **Node.js + TypeScript** — proven, massive ecosystem, uWS for performance,
  larger image, familiar to front-end contributors
- **Rust** — best performance, Tokio + axum + tokio-tungstenite, hardest to contribute to,
  smallest binaries, most impressive to senior engineers
- **Elixir/Phoenix** — best-in-class for real-time/channels, but niche, contributor barrier

Score against: binary size, cross-compile ease, WebSocket maturity, concurrency model,
contributor accessibility, Docker image size, startup time.

### Decision 2: TUI Framework

Candidates to evaluate:
- **Bubble Tea (Go)** — if Go is chosen for server, share language, excellent modern TUI,
  used by Charm.sh tools which are universally loved by devs
- **Ink (Node/TypeScript)** — React for terminals, component model is great for themes,
  runtime dependency
- **Ratatui (Rust)** — most powerful, most complex, beautiful output
- **Textual (Python)** — surprisingly capable, good for rapid iteration, but Python
  dependency is ugly for a security tool
- **blessed-contrib / neo-blessed (Node)** — mature but dated aesthetic

The TUI must support the theme system. Evaluate how each framework handles
dynamic color scheme changes and custom fonts/glyphs.

### Decision 3: Encryption Architecture

The operator has asked Claude to justify this fully.

Context:
- Messages are ephemeral by default (no persistence)
- Multiple parties in a room (not just 1:1)
- Self-hosted — server operator could theoretically intercept if encryption is only transport-layer
- Target users include lawyers, therapists, engineers with confidential work
- Complexity must be manageable for a solo developer

Evaluate:
- **TLS only (transport encryption)** — easiest, but server operator can read messages.
  Eliminates "we can't read your messages" as a claim. Not acceptable for Netherchat's
  brand promise.
- **libsodium (NaCl)** — `crypto_box` for 1:1, need to design group key exchange manually.
  Excellent library, available in every language, audited, fast. Requires custom group
  key distribution protocol.
- **Signal Protocol (Double Ratchet + X3DH)** — gold standard, provides forward secrecy
  and break-in recovery. Libraries: libsignal (official, C/Rust), signal-protocol (JS).
  Complex to implement correctly for groups. Overkill for MVP but aspirational.
- **MLS (Messaging Layer Security, RFC 9420)** — IETF standard for group E2E encryption.
  Designed specifically for the multi-party case. Libraries are emerging. This is where
  the industry is heading. Forward-looking choice.
- **Hybrid: libsodium for MVP, MLS migration path designed in** — pragmatic. Ship fast
  with audited crypto, document the migration target.

Justify which approach serves Netherchat's v1 needs while preserving the ability to
make the "we cannot read your messages" claim credibly.

### Decision 4: Monorepo Tooling

- **Turborepo** — if TypeScript stack
- **Go workspaces** — if Go stack
- **Cargo workspaces** — if Rust
- **Nx** — language-agnostic, powerful, heavy
- **Just (justfile)** — simple task runner, language agnostic, pairs well with any choice

### Decision 5: Config Format

- **TOML** — human-friendly, Rust's native, Go has excellent support, good for
  `netherchat.toml`. Recommended default.
- **YAML** — familiar but ambiguous types, significant whitespace footgun
- **HCL** — Terraform users will feel at home, overkill here
- Evaluate and justify.

---

## Encryption Architecture (Detailed)

Whatever you recommend, the encryption design must satisfy:

1. **The server operator cannot read message content.** Keys are never transmitted
   to or stored on the server in plaintext. This is the non-negotiable claim.
2. **Forward secrecy.** Compromise of a long-term key does not expose past messages.
3. **Group messaging support.** Multiple clients in a room, all able to decrypt.
4. **Key exchange happens at connect time** via the server as a relay only —
   the server passes public keys between clients but never sees the symmetric key.
5. **No key escrow.** There is no master key, no recovery mechanism. If you lose
   your key, you lose access. This is a feature, not a bug. Document it prominently.

---

## Feature Specification (v1 scope)

### Server Features
- [ ] WebSocket server, rooms, in-memory message routing
- [ ] `netherchat.toml` config: rooms, ports, TLS cert paths, persistence toggle
- [ ] Inbound webhooks per room (POST JSON → message in room)
- [ ] REST endpoints: `/health`, `/rooms`, `/version`
- [ ] Rate limiting per connection
- [ ] Invite tokens (generate a one-time invite link)
- [ ] Ephemeral rooms with TTL (`--ttl 24h`)
- [ ] Optional SQLite persistence (opt-in, local only)
- [ ] Zero telemetry mode (default, no exceptions)

### TUI Client Features
- [ ] Connect to server by URL: `netherchat connect wss://chat.example.com`
- [ ] Room list sidebar, active room main view, member list
- [ ] Message input with slash command autocomplete
- [ ] Theme system (8 themes minimum, instantly switchable)
- [ ] `/vanish` — clear local history + signal server to rotate room key
- [ ] `/invite` — generate invite token, display as QR code in terminal
- [ ] `/exec` — run command on server (requires explicit server-side opt-in config)
- [ ] `/ttl set 1h` — set message TTL for current room
- [ ] `/whoami` — show session fingerprint, encryption status, server info
- [ ] Pipe mode: `netherchat send #ops "deploy complete"` (non-interactive)
- [ ] Tail mode: `netherchat tail #alerts | grep ERROR`
- [ ] Notification hooks (run a shell command on new message)
- [ ] Mouse support: click rooms, scroll, click usernames

### Pipe / Unix Integration
```bash
# send message
echo "build failed on main" | netherchat send #deployments

# tail a channel to stdout
netherchat tail #alerts

# pipe tail into other tools
netherchat tail #alerts | grep "CRITICAL" | tee /var/log/critical-alerts.log

# send file content
cat error.log | netherchat send #ops
```

### Webhook Integration
```bash
# Every room gets a webhook automatically
curl -X POST https://chat.example.com/webhook/secure-ops \
  -H "Content-Type: application/json" \
  -d '{"text": "Deployment complete", "from": "ci-bot"}'
```

---

## Project Structure (Recommended — finalize after framework decision)

```
netherchat/
├── CLAUDE.md                  # this file
├── PROTOCOL.md               # wire protocol spec for third-party clients
├── README.md
├── Makefile / justfile        # dev tasks
├── docker-compose.yml
├── netherchat.toml.example
├── server/                   # server process
│   ├── main.go (or main.ts)
│   ├── rooms/
│   ├── crypto/
│   ├── webhooks/
│   ├── config/
│   └── api/
├── tui/                      # terminal client
│   ├── main.go (or index.ts)
│   ├── ui/
│   │   ├── themes/
│   │   ├── rooms/
│   │   └── input/
│   └── crypto/
├── web/                      # browser client (v2)
│   ├── src/
│   └── public/
├── installer/
│   ├── install.sh
│   └── install.ps1
└── docs/
    ├── self-hosting.md
    ├── encryption.md
    └── commands.md
```

---

## Brand & Design Constraints

The Netherchat visual identity is established. Do not deviate from it.

- **Primary background:** `#0a0a12`
- **Accent violet:** `#7c3aed`
- **Soft violet:** `#a78bfa`
- **Text primary:** `#e2e0f0`
- **Text muted:** `#7c6fa0`
- **Fonts:** Space Grotesk (UI), JetBrains Mono (code/terminal/tags)
- **Logo:** Stylized N glyph, curling tips, Tim Burton-influenced, terminal node dots at ends
- **Tagline:** "Messaging that lives below the surface"
- **Tone:** Corporate professional with deliberate underground/rebel edge.
  Never edgy for its own sake. Never try-hard. Quiet confidence.

TUI themes must be named and behave as follows:
- `nether` — deep violet (default, matches brand)
- `abyss` — cold cyan on near-black, monospace font
- `ember` — orange/amber on near-black, warm
- `ghost` — full grayscale, IBM Plex Mono
- `sprinkles` — rainbow per-user colors, Fira Code (easter egg)
- `dracula` — standard Dracula palette (devs already have this on their machines)
- `gruvbox` — standard Gruvbox palette
- `solarized` — standard Solarized Dark palette

---

## Scrubadubber Compatibility Notes

Scrubadubber's install script is the UX benchmark. Before finalizing the installer,
review how scrubadubber.com/install works and mirror its structure:
- Progress output with checkmarks
- Clear error messages with remediation hints
- Detects OS and pulls the right binary
- Works without sudo where possible
- Leaves a clean uninstall path

Netherchat's installer must feel like it comes from the same company.

---

## Deployment Path (for cloud-hosted paid tier, future)

Design decisions now that preserve this future:
- Server must be stateless by default (horizontal scaling possible)
- Room state in Redis (optional, for multi-node) — design the interface even if
  the default implementation is in-memory
- Auth tokens must be JWT-compatible for future SSO integration
- SQLite persistence today must be swappable for Postgres via an interface/adapter pattern

Do not build these now. Design the interfaces so they are not painful to add.

---

## What Success Looks Like at Each Milestone

### M1 — Two terminals talking
Two instances of the TUI client can exchange encrypted messages through the server.
No themes, no commands, no webhooks. Just messages flowing, E2E encrypted, nothing
persisted. A senior engineer looking at a Wireshark capture sees ciphertext only.

### M2 — Docker one-liner
`docker run -p 3000:3000 astralis/netherchat` starts the server.
`curl -fsSL netherchat.com/install | bash` installs the TUI client.
This is the first thing that goes on GitHub.

### M3 — Full TUI polish
All slash commands working. All 8 themes. Pipe mode. Tail mode. Webhook endpoint.
`netherchat.toml` config. This is the Hacker News launch moment.

### M4 — Web client
Browser client connecting to the same server. Non-technical users can now use Netherchat.
The site gets the full landing page treatment (already designed).

### M5 — Cloud hosted
Astralis runs a managed instance. Freemium tiers introduced. Paying customers.

---

## Instructions for Claude Code Session

When you begin a new Claude Code session on this project:

1. **Read this entire file first.** Do not skip sections.
2. **Ultrathink the framework decision** before touching any code. Use extended thinking.
   Produce your reasoning in a file called `ARCHITECTURE_DECISION.md` before writing
   any source files. This document is permanent and becomes part of the repo.
3. **Ask clarifying questions** if any requirement conflicts with your recommended
   architecture. Do not silently paper over conflicts.
4. **Follow the build order strictly:**
   M1 → M2 → M3 → M4 → M5. Do not skip ahead.
5. **Never add telemetry, analytics, or any outbound network call** that is not
   explicitly initiated by the user or admin. This is a security product.
6. **The encryption layer is not optional for M1.** M1 includes E2E encryption.
   A version of Netherchat that sends plaintext, even temporarily, must never be
   committed to the public repo.
7. **Commit messages follow conventional commits:** `feat:`, `fix:`, `chore:`, `docs:`, `crypto:`
8. **Every crypto decision gets a comment** explaining what it does and why,
   linking to the relevant RFC or libsodium docs section.
9. **Test the installer on a clean environment** before tagging any release.
   The install experience is a product in itself.
10. **When in doubt, do less and do it better.** A focused, excellent tool beats
    a bloated one. Senior engineers will notice both.

---

## Prompt for Initial Session

Use this prompt verbatim when starting the first Claude Code session:

```
You are beginning development of Netherchat, a self-hostable end-to-end encrypted
messaging system built by Astralis Software Systems. Read CLAUDE.md completely before
doing anything else.

Your first task is NOT to write code. Your first task is to produce ARCHITECTURE_DECISION.md.

In that document, using extended thinking and full deliberation, you will:

1. Evaluate and select the server language and framework from the candidates in CLAUDE.md.
   Score each against: binary size, cross-compile ease, WebSocket maturity, concurrency
   model, contributor accessibility, Docker image size, startup time, TUI framework
   compatibility. Pick one. State what you are giving up.

2. Evaluate and select the TUI framework. Score each against: theme system flexibility,
   mouse support, rendering quality, language match with server choice, dependency footprint.
   Pick one. State what you are giving up.

3. Evaluate and select the encryption approach. The non-negotiable: the server operator
   cannot read message content. Evaluate TLS-only, libsodium, Signal Protocol, and MLS.
   Pick the approach that lets Netherchat credibly say "we cannot read your messages"
   at v1, while preserving a migration path to MLS. Justify fully.

4. Evaluate TOML vs YAML vs HCL for config. Pick one and justify.

5. Produce the final recommended monorepo directory structure based on your choices.

6. Produce the exact commands to bootstrap the project from scratch, starting from
   C:\Users\saleh\ on Windows 11 with WSL2 available.

After ARCHITECTURE_DECISION.md is approved by the operator, proceed to M1:
two TUI clients exchanging E2E encrypted messages through the server.
No UI polish required at M1. Encryption is required at M1.

The product must impress a senior engineer who has seen everything.
Make every decision as if that engineer is watching.
```

---

## Environment Notes

- OS: Windows 11
- WSL2 available and preferred for development
- Existing projects at `C:\Users\saleh\` — new project goes at `C:\Users\saleh\netherchat`
- AWS credentials configured (`.aws` present) — future deployment target
- Docker Desktop installed (`.docker` present)
- Go installed (`go/` folder present at `C:\Users\saleh\go`)
- Python/Anaconda available if needed
- VS Code installed
- GitHub is the source of truth for all Astralis repos
- SSH keys configured (`.ssh` present)

Bootstrap commands (run in PowerShell, then continue in WSL2):
```powershell
mkdir C:\Users\saleh\netherchat
cd C:\Users\saleh\netherchat
Copy-Item PATH_TO_THIS_CLAUDE_MD .\CLAUDE.md
code .
```

Then in WSL2:
```bash
cd /mnt/c/Users/saleh/netherchat
git init
git checkout -b main
echo "# Netherchat" > README.md
git add . && git commit -m "chore: initial commit with CLAUDE.md"
```

---

*CLAUDE.md version 1.0 — prepared June 2026 — Astralis Software Systems, LLC*
*Do not modify this file without operator approval. It is the source of truth for the project.*
