# Netherchat dev tasks — canonical task runner (ARCHITECTURE_DECISION.md §5).
# Requires: go 1.26+, just. Optional: air (hot reload for `just dev`).
# On Windows, just runs recipes via PowerShell.
set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

# List available recipes.
default:
    @just --list

# Run the server with hot reload (rebuilds on save). Needs `air`.
dev:
    air -c .air.toml

# Run the server once on the given address.
server addr=":3000":
    go run ./cmd/netherchat-server --addr {{addr}}

# Launch a TUI client against a server.
connect url="ws://localhost:3000" room="general" name="dev":
    go run ./cmd/netherchat connect {{url}} --room {{room}} --name {{name}}

# Build both binaries into ./bin.
build:
    go build -o bin/ ./cmd/...

# Run the full test suite.
test:
    go test ./...

# Static analysis.
vet:
    go vet ./...

# Format all Go source.
fmt:
    gofmt -w .

# Tidy module dependencies.
tidy:
    go mod tidy

# Prove the blind-relay boundary: the server must not link the client crypto package.
check-boundary:
    go test ./tui/e2e/ -run TestServerBinaryDoesNotLinkClientCrypto -v

# Prove the egress claim: no outbound call site, and no new third-party module, may
# enter the relay binary without an allowlist edit in tui/e2e/egress_test.go.
check-egress:
    go test ./tui/e2e/ -run TestServerEgress -v

# Run the mDNS LAN discovery test, which `just test` skips by default. This one
# ADVERTISES `_netherchat._tcp` on your local network and binds UDP 5353 — Windows
# will prompt for firewall permission the first time (grant Private, not Public).
# Two recipes because the shells differ: PowerShell on Windows (see windows-shell
# above), sh elsewhere.
[windows]
test-mdns:
    $env:NETHERCHAT_TEST_MDNS = "1"; go test ./tui/sneakernet/ -run TestMDNS -v

[unix]
test-mdns:
    NETHERCHAT_TEST_MDNS=1 go test ./tui/sneakernet/ -run TestMDNS -v

# Scan for known vulnerabilities — BOTH modules. govulncheck only walks the current
# module, so the provider needs its own scan (-C) or its findings stay invisible.
# Same two scans CI runs. No shell-specific syntax, so one recipe covers both.
govulncheck:
    go install golang.org/x/vuln/cmd/govulncheck@latest
    govulncheck ./...
    govulncheck -C terraform-provider-netherchat ./...
