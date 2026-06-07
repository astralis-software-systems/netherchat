package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/output"
)

// captureOut runs fn with output.Out redirected to a buffer and returns what was
// written. Restores output.Out afterward. (Tests are not run in parallel.)
func captureOut(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	prev := output.Out
	output.Out = &buf
	defer func() { output.Out = prev }()
	fn()
	return buf.String()
}

// strictUnmarshal decodes JSON into v, rejecting any field not present in v's
// struct — the spec's "no extra fields with DisallowUnknownFields" requirement.
func strictUnmarshal(t *testing.T, data string, v any) {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("strict decode failed (%v) for: %s", err, data)
	}
}

func TestVersionJSON(t *testing.T) {
	out := captureOut(t, func() { versionCmd([]string{"--json"}) })
	var v versionOut
	strictUnmarshal(t, out, &v)
	if v.ProtocolVersion == 0 {
		t.Error("protocol_version missing")
	}
	if !strings.HasPrefix(v.GoVersion, "go") {
		t.Errorf("go_version = %q", v.GoVersion)
	}
	if !strings.Contains(v.Platform, "/") {
		t.Errorf("platform = %q", v.Platform)
	}
	if v.Version == "" {
		t.Error("version empty")
	}
}

func TestWhoamiJSON(t *testing.T) {
	keyPath := writeTempSSHKey(t)
	out := captureOut(t, func() {
		whoamiCmd([]string{"--json", "--identity", keyPath, "--name", "tester", "--room", "ops"})
	})
	var w whoamiOut
	strictUnmarshal(t, out, &w)

	if !strings.HasPrefix(w.Identity.Fpr, "SHA256:") {
		t.Errorf("identity.fpr = %q, want ssh format", w.Identity.Fpr)
	}
	if w.Identity.Name != "tester" {
		t.Errorf("identity.name = %q", w.Identity.Name)
	}
	if w.Identity.Source == "" {
		t.Error("identity.source empty")
	}
	if w.Room != "ops" || w.Encryption == "" || w.ProtocolVersion == 0 {
		t.Errorf("whoami fields = %+v", w)
	}
}

func TestRoomsJSON(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietTestLogger()))
	defer ts.Close()

	// Make a room active by joining it (rooms only appear once they have members).
	c, err := client.New(ts.URL, "ops", "alice", writeTempSSHKey(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	waitKeyReady(t, c, 5*time.Second)

	base, err := httpBase(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	rooms, err := fetchRooms(base)
	if err != nil {
		t.Fatalf("fetchRooms: %v", err)
	}

	var ops *roomInfo
	for i := range rooms {
		if rooms[i].Name == "ops" {
			ops = &rooms[i]
		}
	}
	if ops == nil {
		t.Fatalf("room 'ops' not in %+v", rooms)
	}
	if ops.Members < 1 {
		t.Errorf("ops members = %d", ops.Members)
	}

	// The JSON the command would print is a strict-decodable array.
	out := captureOut(t, func() { _ = output.WriteJSON(rooms) })
	var decoded []roomInfo
	strictUnmarshal(t, out, &decoded)
}

// --- helpers ---

func writeTempSSHKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "test@netherchat")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func quietTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func waitKeyReady(t *testing.T, c *client.Client, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case ev := <-c.Events():
			if _, ok := ev.(client.EvKeyReady); ok {
				return
			}
		case <-c.Done():
			t.Fatal("disconnected before key ready")
		case <-deadline:
			t.Fatal("timed out waiting for key")
		}
	}
}
