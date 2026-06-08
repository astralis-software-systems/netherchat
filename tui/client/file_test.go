package client

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestSanitizeFilename pins the mandatory filename hardening (§2.3): directory
// components are stripped (both separators), and dotfiles / traversal are rejected.
func TestSanitizeFilename(t *testing.T) {
	ok := []struct{ in, want string }{
		{"../../../etc/passwd", "passwd"},
		{"foo/bar/secret.key", "secret.key"},
		{`C:\Windows\System32\evil.dll`, "evil.dll"},
		{"heap.prof", "heap.prof"},
	}
	for _, c := range ok {
		got, _, err := sanitizeFilename(c.in)
		if err != nil || got != c.want {
			t.Errorf("sanitizeFilename(%q) = (%q, %v), want %q", c.in, got, err, c.want)
		}
	}
	for _, bad := range []string{".bashrc", "..", "", "."} {
		if _, _, err := sanitizeFilename(bad); err == nil {
			t.Errorf("sanitizeFilename(%q) should be rejected", bad)
		}
	}
	if _, changed, _ := sanitizeFilename("foo/bar.txt"); !changed {
		t.Error("a stripped path should report changed=true")
	}
	if _, changed, _ := sanitizeFilename("bar.txt"); changed {
		t.Error("an already-clean name should report changed=false")
	}
}

// TestFinalizeRecvSHAMismatch proves a corrupt artifact is never written, a
// FileAbort is sent, and the failure is surfaced (§2.3).
func TestFinalizeRecvSHAMismatch(t *testing.T) {
	t.Chdir(t.TempDir())
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewWithIdentity("ws://x", "ops", "bob", id)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.ctx, c.cancel = ctx, cancel
	defer cancel()

	c.recvs["t1"] = &recvState{
		meta:      protocol.FileOfferMeta{SHA256: "not-the-real-hash", Chunks: 1, Filename: "secret.key", Size: 5},
		cleanName: "secret.key", senderName: "alice",
		chunks: [][]byte{[]byte("hello")}, have: []bool{true}, received: 1,
	}
	c.finalizeRecv("t1")

	if _, err := os.Lstat("secret.key"); !os.IsNotExist(err) {
		t.Error("a corrupt artifact must not land on disk")
	}
	select {
	case env := <-c.sendCh:
		if env.Type != protocol.OpFileAbort {
			t.Errorf("expected a file_abort, got %s", env.Type)
		}
	default:
		t.Error("expected a FileAbort to be sent on mismatch")
	}
	select {
	case ev := <-c.events:
		if e, ok := ev.(EvFileComplete); !ok || e.OK {
			t.Errorf("expected EvFileComplete OK=false, got %#v", ev)
		}
	default:
		t.Error("expected an EvFileComplete failure event")
	}
}

// --- server-enforced limits (raw frames, real relay) ------------------------

func connectClient(t *testing.T, url, room, name string) *Client {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewWithIdentity(url, room, name, id)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func waitKeyReady(t *testing.T, c *Client) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case ev := <-c.Events():
			if _, ok := ev.(EvKeyReady); ok {
				return
			}
		case <-deadline:
			t.Fatal("timed out waiting for key")
		}
	}
}

func waitErrorContains(t *testing.T, c *Client, substr string) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case ev := <-c.Events():
			if e, ok := ev.(EvError); ok && strings.Contains(e.Err.Error(), substr) {
				return
			}
		case <-deadline:
			t.Fatalf("timed out waiting for an error containing %q", substr)
		}
	}
}

// TestServerRejectsOversizedChunk proves the relay rejects a chunk over the wire
// cap with an OpError — bounding per-frame memory without ever decrypting.
func TestServerRejectsOversizedChunk(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), discardLog()))
	defer ts.Close()
	c := connectClient(t, ts.URL, "ops", "alice")
	waitKeyReady(t, c)

	c.enqueue(protocol.OpFileChunk, protocol.FileChunk{
		TransferID: "deadbeefdeadbeef", Index: 0, Total: 1,
		Nonce: make([]byte, 24), Data: make([]byte, protocol.MaxChunkWire+1),
	})
	waitErrorContains(t, c, "chunk")
}

// TestServerConcurrencyLimit proves the relay rejects a new offer once a room is
// at max_concurrent_transfers — using only the content-free transfer ids.
func TestServerConcurrencyLimit(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.MaxConcurrentTransfers = 2
	ts := httptest.NewServer(server.Handler(cfg, discardLog()))
	defer ts.Close()
	c := connectClient(t, ts.URL, "ops", "alice")
	waitKeyReady(t, c)

	// Two offers hold their slots (no final chunk follows); the third is rejected.
	// The relay processes a connection's frames in order, so the error is deterministic.
	for _, tid := range []string{"1111111111111111", "2222222222222222", "3333333333333333"} {
		c.enqueue(protocol.OpFileOffer, protocol.FileOffer{TransferID: tid})
	}
	waitErrorContains(t, c, "transfer")
}
