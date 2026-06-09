package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadRunbook(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runbook.toml")
	write := func(s string) {
		if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write(`
[[allow]]
cmd     = "drain"
command = "go version"
timeout = "10s"

[[allow]]
cmd     = "rollback"
command = "/usr/local/bin/rollback.sh canary"
`)
	rb, err := loadRunbook(path)
	if err != nil {
		t.Fatalf("loadRunbook: %v", err)
	}
	if len(rb) != 2 {
		t.Fatalf("actions = %d, want 2", len(rb))
	}
	if rb["drain"].Command != "go version" || rb["drain"].Timeout != "10s" {
		t.Errorf("drain = %+v", rb["drain"])
	}
	if rb["rollback"].Command != "/usr/local/bin/rollback.sh canary" {
		t.Errorf("rollback = %+v", rb["rollback"])
	}

	// Duplicate action names are rejected.
	write("[[allow]]\ncmd=\"x\"\ncommand=\"a\"\n[[allow]]\ncmd=\"x\"\ncommand=\"b\"\n")
	if _, err := loadRunbook(path); err == nil {
		t.Error("expected an error on duplicate action")
	}

	// An entry missing its command is rejected.
	write("[[allow]]\ncmd=\"x\"\n")
	if _, err := loadRunbook(path); err == nil {
		t.Error("expected an error on missing command")
	}

	// An empty runbook is rejected.
	write("# nothing here\n")
	if _, err := loadRunbook(path); err == nil {
		t.Error("expected an error on empty runbook")
	}
}

// TestLoadRunbookQuorum proves the agent reads [action.runbook] quorum from
// netherchat.toml (§1.3), defaulting to single-actor (1) when the file is absent or
// the action unset, and honoring 0 (disabled).
func TestLoadRunbookQuorum(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "netherchat.toml")

	if err := os.WriteFile(path, []byte("[action.runbook]\nquorum = 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := loadRunbookQuorum(path); got != 2 {
		t.Fatalf("loadRunbookQuorum(quorum=2) = %d, want 2", got)
	}

	if err := os.WriteFile(path, []byte("[action.runbook]\nquorum = 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := loadRunbookQuorum(path); got != 0 {
		t.Fatalf("loadRunbookQuorum(quorum=0) = %d, want 0 (disabled)", got)
	}

	// A config with no [action.runbook], and a missing file, both default to 1.
	if err := os.WriteFile(path, []byte("[server]\naddr = \":3000\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := loadRunbookQuorum(path); got != 1 {
		t.Fatalf("loadRunbookQuorum(unset) = %d, want 1", got)
	}
	if got := loadRunbookQuorum(filepath.Join(dir, "does-not-exist.toml")); got != 1 {
		t.Fatalf("loadRunbookQuorum(missing) = %d, want 1", got)
	}
}

func TestExecuteAllowed(t *testing.T) {
	// A real, cross-platform command succeeds with exit 0 and captured output.
	exit, out := executeAllowed(allowEntry{Cmd: "ver", Command: "go version"}, 10*time.Second, 1<<16)
	if exit != 0 {
		t.Fatalf("exit = %d, output = %q", exit, out)
	}
	if !strings.Contains(out, "go version") {
		t.Errorf("output = %q, want it to contain 'go version'", out)
	}

	// A non-existent binary yields a non-zero exit and an explanatory line.
	exit2, _ := executeAllowed(allowEntry{Cmd: "x", Command: "netherchat-no-such-binary-zzz"}, 10*time.Second, 1<<16)
	if exit2 == 0 {
		t.Error("expected a non-zero exit code for a missing binary")
	}
}
