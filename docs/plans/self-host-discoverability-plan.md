# Plan — Self-hosting discoverability & the two-artifact story

**Status:** proposal (copy + installer-script + small CLI-string change). No Go
behavior change beyond hint strings; no wire/protocol change; no release-pipeline
change. **Scope guard:** this document is a plan only. Nothing here is implemented yet.

**Target:** `main` @ `ac559cd`. Audiences to satisfy simultaneously: security
engineers (who reward craftsmanship and honesty) and enterprise/federal buyers (who
reward a sound, intentional deployment model). The fix must read as *intentional
architecture*, never as an apology for an omission.

---

## 1. Corrected diagnosis (settled — from the completed read)

The self-hosting story is Docker-centric and leaves a discovery gap, sharpest on
Windows. Two facts reshape the fix:

1. **The server binary is already in the release archive the installer downloads —
   and the installer discards it.** GoReleaser bundles *both* binaries into
   `netherchat_<os>_<arch>.{zip,tar.gz}` (`.goreleaser.yaml` → `archives.ids:
   [netherchat, netherchat-server]`). `install.ps1` downloads that archive, extracts
   only `netherchat.exe` (hard-coded `$Binary = 'netherchat.exe'`, line 26/110-111),
   and deletes the rest with the temp dir (line 117). `netherchat-server.exe` is in
   hand and thrown away. `install.sh` behaves identically (`BINARY="netherchat"`,
   line 22/154).

2. **The installer already mentions the server — but points only to Docker.** Both
   footers print `Run a server: docker run -p 3000:3000 salkreiner/netherchat`
   (`install.ps1:133`, `install.sh:175`). The gap is not "server never mentioned";
   it is "self-hosting is framed as Docker-only, and there is **no documented
   native-binary server path on Windows**," despite a Windows server binary shipping
   in every release.

### Ground truth on obtaining the relay (every blessed path must match one of these)

| # | Path | Real today? | Notes |
|---|------|-------------|-------|
| 1 | Container image (server-only) — `docker run -p 3000:3000 salkreiner/netherchat` | ✅ documented | Linux image → Windows needs Docker Desktop |
| 2 | `go build -o bin/ ./cmd/netherchat-server` | ✅ documented | needs Go 1.26+ |
| 3 | Extract `netherchat-server[.exe]` from the release archive `netherchat_<os>_<arch>.{tar.gz,zip}` | ✅ real, **undocumented** | works on Windows; it is the exact archive the installer already downloads |
| 4 | Homebrew cask archive (macOS) | ✅ includes both | cask draws from the `default` archive |

The fix blesses only paths that already exist. It invents nothing.

---

## 2. Settled intent (the plan is built to these)

- **Client install stays minimal by default.** The featherweight client is correct
  default behavior. Do **not** bundle/install the server by default. Any server
  option is strictly opt-in.
- **The client/server split must read as an intentional two-artifact
  architecture** — "install the endpoint client lightweight; provision the relay
  deliberately when you self-host" — not as an omission or apology. This framing is
  what earns the enterprise/federal buyer.
- **The tooling must be self-explaining at the moment of need.** A human (or an AI
  assistant helping them) who needs the server should be told where to get it exactly
  when they hit the need, phrased as intent. This is what earns the security engineer.
- **Accuracy over enthusiasm.** Every instruction points to a real acquisition path
  and a command that exists.

---

## 3. Decision A — which acquisition path becomes first-class; does the installer grow an opt-in server option?

### Candidates

- **A1 — Opt-in `-Server` / `--server` installer flag** that extracts the
  *already-downloaded* server binary from the temp dir (zero extra download).
  Featherweight by default; native relay one flag away. Docker stays as an alternative.
- **A2 — Keep Docker as the single blessed path.** Consistent with all current docs;
  leaves Windows-native / non-Docker users with no option.
- **A3 — Bless native binary and Docker equally, everywhere** (docs-only emphasis,
  no installer change).

### Analysis

| Criterion | A1 (opt-in flag) | A2 (Docker only) | A3 (dual docs, no flag) |
|-----------|------------------|------------------|-------------------------|
| Engineer craftsmanship | **Strong** — "the server was already in the zip; one flag installs it, no second download" is an elegant, self-aware detail | Weak — forces Docker for a tiny static Go relay | Moderate — honest but still a manual extract |
| Enterprise "sound deployment model" | **Strong** — one checksum-verified archive, native tiered artifacts, air-gap friendly, no registry/Docker-Desktop licensing dependency | Moderate — registry + Docker Desktop licensing friction at scale | Moderate |
| Windows-native / no-Docker users | **Fixed** — native relay, one flag | **Unfixed** | Partially — they can extract by hand |
| Consistency w/ existing docs | Requires doc update (already doing that in Decision B) | Best (no change) | Requires doc update |
| Implementation footprint | Small — binary already extracted in temp; add flag + copy + footer branch + uninstall cleanup, symmetric in both scripts | None | None (docs only) |
| Cross-platform symmetry | Clean — `-Server` (PS switch) ⇄ `--server` (sh flag) | n/a | n/a |

### Recommendation — **A1 (opt-in `-Server` / `--server` flag), with docs blessing native and Docker as context-appropriate co-equals**

A1 is the only option that closes the Windows-native gap, and it does so with the
most persuasive story for *both* audiences: the engineer sees the craft (the binary
was already there; we don't re-download), the enterprise sees a clean tiered-artifact
deployment with one verified archive and no mandatory container runtime. The default
stays featherweight — the flag changes only opt-in behavior. Because the native path
is now one flag away, docs should present it as first-class *alongside* Docker
(Docker remains first-class for containerized/Linux/team deployments), which is
effectively A3's doc posture layered on A1's mechanism. No pipeline change is
required (the binary already ships).

### Specified behavior for BOTH installers (opt-in only; default unchanged)

Applies symmetrically to `install.ps1` and `install.sh`:

1. **Flag.** `install.ps1`: add `[switch]$Server` to `param(...)`. `install.sh`: add
   `--server` to the arg loop (sets `DO_SERVER=1`), and document it in the header
   usage block. Honor an env toggle for parity with existing vars only if trivial
   (optional; not required).
2. **Extraction (zero extra download).** After the client binary is copied, and only
   when the flag is set, look for the sibling server binary in the **same temp
   extraction dir** the client came from:
   - PS: `Join-Path $tmp 'netherchat-server.exe'`
   - sh: `"$tmp/netherchat-server"`
   Copy it into the **same `BinDir`** as the client
   (`%LOCALAPPDATA%\Programs\netherchat` / `~/.local/bin`).
3. **PATH.** No new PATH entry — installing into the same `BinDir` (already added to
   PATH for the client) puts `netherchat-server` on PATH automatically. Symmetric,
   minimal.
4. **Defensive.** If the flag is set but the server binary is absent from the archive
   (older release), **warn and continue** — never fail the client install over an
   opt-in extra. (Contrast: the client binary being absent is still fatal, unchanged.)
5. **Uninstall symmetry.** `-Uninstall` / `--uninstall` should also remove
   `netherchat-server[.exe]` from `BinDir` when present. (Small addition to both
   uninstall paths; see Open Questions if we prefer to leave uninstall client-only.)
6. **Footer.** Two states (drafts in §5).

**Flag-name note:** `-Server` / `--server` is short and matches the task framing, but
the *client* CLI already uses `--server <url>` to mean the relay URL (different
binary, different context). `--with-server` / `-WithServer` removes any ambiguity.
Recommendation: ship `-Server` / `--server`; raised in Open Questions for a final call.

---

## 4. Decision B — which surfaces get the self-explaining hint?

Four surfaces, four audiences: installer footer (post-install human), no-relay error
(mid-failure human/AI), CLI `usage()` (help-reader), docs (doc-reader).

### Analysis

- **Installer footer — YES (essential).** The orienting moment right after install.
  Today it asserts Docker as *the* way. Reframe to teach the two-artifact model and
  advertise `-Server`. This surface also carries the Decision-A flag.
- **No-relay error — YES (highest contextual value).** This is the surface an AI
  assistant reads mid-task when a user runs `netherchat connect` against a dead relay.
  Today it is a bare `connection failed: dial <url>: … connection refused` with no
  guidance. It should point to **both** self-hosting **and** `netherchat pair`
  (Sneakernet), because Sneakernet is the relay-less fallback and is currently
  invisible at failure time (only surfaced if the user happens to type `/help`,
  `commands.go:124-127`). Interactive choke point: `tui/ui/app/model.go:387-393`
  (`onRoomConnected`). Non-interactive: the plaintext `dial()` wrapper
  (`cmd/netherchat/main.go:256-262`) — **not** `dialErr` (`:239-253`), which feeds
  `--json`; keeping the hint out of `dialErr` preserves JSON purity.
- **CLI `usage()` — YES (low cost, moderate value).** `netherchat --help`
  (`main.go:264-304`) says nothing about self-hosting. A short "self-hosting" footer
  teaches the two-artifact split to anyone reading help. Pure string change.
  `connect --help` (`main.go:94-97`): leave focused on flags (optional one-liner).
- **Docs — YES (essential, the anchor).** `docs/self-hosting.md` and `README.md:47-88`
  carry the intentional-architecture reframing **and** the currently-missing fact that
  the server binary ships inside the client's release archive — regardless of whether
  the other surfaces change.

### Recommendation — **touch all four**, at calibrated depth:

1. **Docs** — the anchor: two-artifact framing + the release-archive fact + all four
   real acquisition paths. Essential.
2. **No-relay error (interactive)** — highest contextual value; point to self-host +
   Sneakernet. Essential.
3. **Installer footer** — reframe to two-artifact; advertise `-Server`. Essential.
4. **CLI `usage()`** — short self-hosting footer. Worth it, trivial.
5. **No-relay error (non-interactive)** — secondary; contained to the plaintext
   `dial()` wrapper so `--json` stays clean.

---

## 5. Draft wording (the copy IS the deliverable — review these)

All drafts use the project's established voice ("endpoint client", "relay", "war
room", "§1.1"), the existing image string `salkreiner/netherchat`, and the existing
in-repo doc path `docs/self-hosting.md`. `<ver>` / `<you>` are the installer's
existing interpolations. **Drafts, pending copy review.**

### 5.1 Installer footer — `install.ps1` (replaces lines 129-134)

**Default (no `-Server`):**
```
Netherchat <ver> installed — the endpoint client.  Messaging that lives below the surface.
  Connect:    netherchat connect ws://localhost:3000 --name <you>
  Self-host:  re-run with -Server for the native relay (netherchat-server — already in
              this release, no extra download), or: docker run -p 3000:3000 salkreiner/netherchat
              Full guide: docs/self-hosting.md
```

**With `-Server`:**
```
Netherchat <ver> installed — client + relay.  Messaging that lives below the surface.
  Connect:     netherchat connect ws://localhost:3000 --name <you>
  Run a relay: netherchat-server --addr :3000   (or: docker run -p 3000:3000 salkreiner/netherchat)
              Full guide: docs/self-hosting.md
```

### 5.2 Installer footer — `install.sh` (replaces lines 173-176, symmetric)

**Default (no `--server`):**
```
Netherchat <ver> installed — the endpoint client.  Messaging that lives below the surface.
  Connect:    netherchat connect ws://localhost:3000 --name "$USER"
  Self-host:  re-run with --server for the native relay (netherchat-server — already in
              this release, no extra download), or: docker run -p 3000:3000 salkreiner/netherchat
  Uninstall:  curl -fsSL https://netherchat.com/install | bash -s -- --uninstall
```

**With `--server`:**
```
Netherchat <ver> installed — client + relay.  Messaging that lives below the surface.
  Connect:     netherchat connect ws://localhost:3000 --name "$USER"
  Run a relay: netherchat-server --addr :3000   (or: docker run -p 3000:3000 salkreiner/netherchat)
  Uninstall:   curl -fsSL https://netherchat.com/install | bash -s -- --uninstall
```

### 5.3 No-relay error — interactive TUI (`tui/ui/app/model.go`, `onRoomConnected` failure branch, ~387-393)

Today the failure branch prints one line: `connection failed: <err>`. Append an
advisory block after it (added output only — no new state, no retry, no error
classification):
```
connection failed: dial ws://localhost:3000: … connection refused
  no relay reachable at ws://localhost:3000
  → self-host a relay:  see docs/self-hosting.md   (netherchat-server — native binary or Docker)
  → or go relay-less:   netherchat pair --lan       (Sneakernet war room, no server — §1.1)
```
Notes: the first advisory line names the actual address from `m.url`. Wording points
to the doc for acquisition (accurate to all real paths) and offers the immediate
relay-less alternative, making Sneakernet visible at failure time. Because virtually
all `Client.Connect` failures at this stage are transport/dial failures (invite
rejection and similar arrive later as events, not from `Connect`), the "no relay
reachable" framing is accurate in the overwhelming majority; the raw error remains
shown above it either way.

### 5.4 No-relay error — non-interactive plaintext `dial()` wrapper (`cmd/netherchat/main.go:256-262`)

Emit one advisory to **stderr** in the plaintext `dial()` wrapper before it exits —
**not** in `dialErr` (which feeds `--json`):
```
netherchat: connect to ws://localhost:3000: dial ws://localhost:3000: … connection refused
netherchat: no relay reachable — self-host one (docs/self-hosting.md) or go relay-less: netherchat pair --lan
```

### 5.5 CLI `usage()` footer (`cmd/netherchat/main.go:264-304`, appended after the examples block)

```
self-hosting:
  the relay is a separate artifact — netherchat-server. install it via the installer's
  -Server/--server flag or from a release archive, or run it in a container; see
  docs/self-hosting.md. no relay? netherchat pair forms a relay-less war room (§1.1).
```

### 5.6 Docs — `docs/self-hosting.md` (new intro framing + acquisition fact, near the top / "Run it")

**Two-artifact architecture paragraph (see §6):** insert as the opening framing.

**Missing fact — "Every release archive contains both binaries":**
```
Every release archive contains both binaries. The client installers pull
netherchat_<os>_<arch>.{tar.gz,zip} from the release, which already includes
netherchat-server next to netherchat (plus README, PROTOCOL, LICENSE). You can obtain
the relay four ways, all producing the same checksum-verified binary:

  1. Installer, native (recommended for self-hosters): re-run the client installer
     with -Server (Windows) / --server (Linux/macOS). It installs the netherchat-server
     binary that already came down in the release archive — no second download.
  2. Container: docker run -p 3000:3000 salkreiner/netherchat
     (server-only image; on Windows this needs Docker Desktop).
  3. By hand from a release archive: download netherchat_<os>_<arch>.{tar.gz,zip} and
     extract netherchat-server[.exe].
  4. From source: go build -o bin/ ./cmd/netherchat-server (Go 1.26+).
```

### 5.7 Docs — `README.md` Install section (reframe lines 47-88)

```
## Install

Netherchat is two artifacts by design: the endpoint client you install everywhere,
and the relay you provision where you self-host. Install the client to talk; add the
relay to host.

### The client
macOS / Linux:      curl -fsSL https://netherchat.com/install | bash
Windows (PowerShell): irm https://netherchat.com/install.ps1 | iex

### The relay (self-hosting)
The relay binary (netherchat-server) ships in the same release archive as the client.
Provision it whichever way fits your deployment:
  - Native, via the installer:  add -Server (Windows) / --server (Linux/macOS) — installs
    netherchat-server from the archive already downloaded, no second fetch.
  - Container:  docker run -p 3000:3000 salkreiner/netherchat   (or docker compose up -d)
  - From source:  go build -o bin/ ./cmd/netherchat-server

See docs/self-hosting.md for the full deployment guide (TLS, Tor, config-as-code).
```

---

## 6. Two-artifact architecture framing (for `docs/self-hosting.md` / `README.md`)

> **Netherchat ships as two artifacts, by design.** The endpoint **client**
> (`netherchat`) is where all encryption happens; it is what you install on every
> participant's machine, and it stays featherweight — a single static binary with no
> runtime dependencies. The **relay** (`netherchat-server`) is a separate artifact you
> provision only where you choose to host: a *blind* router that moves ciphertext
> between clients and holds no keys. Keeping them separate is deliberate. The machine
> that relays traffic and the machine that reads messages are never required to be the
> same, and the client never carries server code it doesn't need — a property the
> build graph enforces, not a promise. You install the client to talk; you provision
> the relay to host.

This paragraph is the load-bearing reframe: it converts "the installer only gives you
the client" from an omission into a stated architectural choice, and it sets up the
acquisition list (§5.6) as *how you provision the second artifact*, not *how you work
around a gap*.

---

## 7. Invariant register (must hold across implementation)

1. **Default install unchanged.** Client-only remains the default; `netherchat-server`
   is installed **only** when `-Server` / `--server` is passed.
2. **`.ps1` and `.sh` stay behaviorally parallel.** Every installer change lands in
   both, symmetrically: flag, extraction source (temp dir), install location
   (`BinDir`), PATH behavior (none new), footer copy, uninstall cleanup.
3. **No `.goreleaser.yaml` / release-pipeline change.** The server binary already ships
   in the archive — confirmed. (If a pipeline change is ever thought necessary, it is a
   *separate* scope question, not folded in here.)
4. **No wire/protocol change.** `PROTOCOL.md` untouched.
5. **No Go behavior change beyond hint strings.** The only Go edits are added output
   strings: the interactive advisory block (§5.3), the plaintext `dial()` advisory
   (§5.4), and the `usage()` footer (§5.5). No error-type classification, no retry, no
   reconnection, no auto-fallback, no new state.
6. **JSON purity.** The non-interactive hint lives only in the plaintext `dial()`
   wrapper, never in `dialErr` (which feeds `--json` callers).
7. **Every blessed path is real.** `-Server` extraction (binary is in temp),
   `docker run … salkreiner/netherchat` (existing image), release-archive extraction
   (bundled), `go build ./cmd/netherchat-server` (exists), `netherchat pair --lan`
   (exists), `docs/self-hosting.md` (exists). No invented path or command.
8. **Confidentiality.** Generic framing throughout; no named third parties in copy,
   comments, or commit messages.

---

## 8. What this is NOT doing

- **Not** changing the default install (no auto-bundling / auto-installing the server).
- **Not** changing the release pipeline / `.goreleaser.yaml`.
- **Not** changing any Go logic or behavior beyond added hint strings — no retry, no
  automatic Sneakernet fallback, no error classification, no reconnection.
- **Not** changing the wire protocol / `PROTOCOL.md`.
- **Not** adding a new download source or a command that does not already exist.
- **Not** renaming binaries or changing the default client's install location or PATH
  handling.
- **Not** substantively rewriting `connect --help` (an optional one-liner at most).

If implementation finds itself proposing real Go behavior changes beyond hint strings,
or a pipeline change, **stop and re-scope** — that is out of bounds for this plan.

---

## 9. Verification (scripts + copy — behavioral, not unit)

- **Installer, default path:** run `install.ps1` / `install.sh` against a
  staged/local release; confirm only the client installs and the footer prints the new
  two-artifact + `-Server`/`--server` copy (§5.1/§5.2 default). Confirm
  `netherchat-server` is **absent** from `BinDir`.
- **Installer, `-Server` / `--server` path:** run with the flag; confirm
  `netherchat-server[.exe]` is extracted from the **same** temp dir (verify only one
  archive is fetched — no second download), installed to `BinDir`, and on PATH
  (`netherchat-server --version` / `--healthcheck`). Confirm the footer prints the
  client+relay copy. Confirm `-Uninstall` / `--uninstall` removes **both** binaries.
- **No-relay error, interactive:** run `netherchat connect ws://localhost:3000` with no
  relay listening; confirm the room shows the advisory block pointing to
  `docs/self-hosting.md` and `netherchat pair --lan`.
- **No-relay error, non-interactive:** `echo x | netherchat send ops --server
  ws://localhost:59999` (dead port); confirm stderr shows the hint. Run a `--json`
  variant and confirm the hint is **absent** from JSON output (purity preserved).
- **`usage()`:** `netherchat --help`; confirm the self-hosting footer renders.
- **Docs:** render `docs/self-hosting.md` and `README.md` (markdown preview / doc
  site); confirm the two-artifact section, the four acquisition paths, and links
  resolve.
- **Cross-platform parity:** diff the behavior lists of `.ps1` and `.sh` to confirm
  symmetry (flag, extraction, location, footer, uninstall).
- **Go hygiene (strings changed):** `go build ./...`, `go vet ./...`, `gofmt -l .`
  (must be empty), `go test ./...`. **Check for tests that snapshot `usage()` or assert
  the exact connection-failure string**; if any exist, update their expectations —
  this is a test-expectation update, not a product-behavior change.

*(Environment note: per project memory, run Go tests via PowerShell one package at a
time; `go` subprocess startup is slow here, so `go`-shelling tests may be slow rather
than failing.)*

---

## 10. Open questions

1. **Installer flag name.** `-Server` / `--server` (short, matches task framing) vs
   `-WithServer` / `--with-server` (unambiguous against the client's `--server <url>`).
   Recommendation: `-Server` / `--server`; confirm.
2. **Uninstall symmetry.** Should `-Uninstall` remove `netherchat-server` too when
   present (recommended, symmetric) — or stay client-only? (Removing both is cleaner;
   confirm.)
3. **Non-interactive hint scope.** Plaintext `dial()` only (recommended, keeps JSON
   clean) vs also gating on dial-error classification for precision (a small logic
   change — out of this scope; note as a future refinement).
4. **Interactive hint conditionality.** Unconditional advisory on any connect failure
   (recommended, pure string, correct for the dominant dial-failure case) vs gating on
   error type (logic change, deferred).
5. **Doc links in CLI copy.** Repo-relative `docs/self-hosting.md` (recommended for
   CLI/error strings, matches existing precedent at `commands.go:127`) vs a
   `https://netherchat.com/…` URL (fine for README/installer footers where a browser
   is likely).
6. **Docker vs native emphasis in docs.** Present native as primary for self-hosters
   and Docker first-class for containerized/Linux/team deployments (recommended,
   context-appropriate dual) vs strictly co-equal everywhere.
7. **Server install location.** Same `BinDir` as the client (recommended — already on
   PATH, symmetric, one directory) — confirm no objection to co-locating.
