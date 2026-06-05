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
