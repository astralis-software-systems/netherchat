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
