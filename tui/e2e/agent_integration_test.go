package e2e

import (
	"bytes"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/tui/client"
)

// TestAgentBinaryRunsRunbook is the Sprint 1 demo, automated: it builds the real
// `netherchat` binary, runs `netherchat agent --room ops --allow runbook.toml`
// against a live relay, and confirms that an /exec request from an operator is
// run by the agent on its own host and a signed result comes back — while the
// relay only ever routes ciphertext. It also confirms a non-allowlisted action is
// denied. Skipped in -short (it compiles the binary).
func TestAgentBinaryRunsRunbook(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the netherchat binary; skipped in -short")
	}

	dir := t.TempDir()
	bin := filepath.Join(dir, "netherchat")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.Command("go", "build", "-o", bin, "./cmd/netherchat")
	build.Dir = projectRoot(t)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build netherchat binary: %v\n%s", err, out)
	}

	// A runbook mapping "ping" to a real, cross-platform command (the test toolchain).
	runbook := filepath.Join(dir, "runbook.toml")
	if err := os.WriteFile(runbook, []byte(`
[[allow]]
cmd     = "ping"
command = "go version"
timeout = "20s"
`), 0o644); err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(server.Handler(config.Default(), quietLogger()))
	defer ts.Close()
	wsURL := strings.Replace(ts.URL, "http", "ws", 1)

	var stderr syncBuffer
	agent := exec.Command(bin, "agent", "--server", wsURL, "--room", "ops", "--allow", runbook, "--name", "agent@test")
	agent.Stderr = &stderr
	if err := agent.Start(); err != nil {
		t.Fatalf("start agent: %v", err)
	}
	defer func() { _ = agent.Process.Kill(); _ = agent.Wait() }()

	// Wait until the agent has connected and is watching the room.
	waitFor(t, 15*time.Second, func() bool { return strings.Contains(stderr.String(), "watching #ops") })

	// An operator joins and requests the allowlisted action.
	op := connect(t, ts.URL, "ops", "alice", "")
	waitMatch[client.EvKeyReady](t, op, nil, 5*time.Second)

	id, err := op.RequestExec("ping")
	if err != nil {
		t.Fatalf("request exec: %v", err)
	}
	res := waitMatch[client.EvExecResult](t, op, func(e client.EvExecResult) bool { return e.ID == id }, 20*time.Second)
	if !res.Allowed || res.ExitCode != 0 {
		t.Fatalf("allowed action result = %+v\nagent log:\n%s", res, stderr.String())
	}
	if !strings.Contains(res.Output, "go version") {
		t.Errorf("agent output = %q", res.Output)
	}
	if !strings.HasPrefix(res.FromFingerprint, "SHA256:") {
		t.Errorf("agent fingerprint = %q", res.FromFingerprint)
	}

	// A non-allowlisted action is denied (and never run).
	id2, _ := op.RequestExec("rm-everything")
	denied := waitMatch[client.EvExecResult](t, op, func(e client.EvExecResult) bool { return e.ID == id2 }, 10*time.Second)
	if denied.Allowed {
		t.Errorf("non-allowlisted action must be denied: %+v", denied)
	}

	// The agent logged both attempts locally (the audit property).
	log := stderr.String()
	if !strings.Contains(log, "exec ALLOWED") || !strings.Contains(log, "exec DENIED") {
		t.Errorf("agent did not log both attempts; log:\n%s", log)
	}
}

func projectRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd() // .../tui/e2e
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("timed out waiting for condition")
}

// syncBuffer is a concurrency-safe io.Writer for capturing a subprocess's stderr.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
