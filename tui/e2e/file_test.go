package e2e

import (
	"bytes"
	"crypto/rand"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/eventlog"
)

// twoInRoom connects a receiver then a sender to the same room, both with their
// room key, and returns them. The receiver joins first so it mints epoch 0.
func twoInRoom(t *testing.T, url, room string) (sender, receiver *client.Client) {
	t.Helper()
	receiver = connect(t, url, room, "bob", "")
	waitMatch[client.EvKeyReady](t, receiver, nil, 5*time.Second)
	sender = connect(t, url, room, "alice", "")
	waitMatch[client.EvKeyReady](t, sender, nil, 5*time.Second)
	return sender, receiver
}

// sendAndReceive runs a full transfer of data named filename and returns the
// receiver's completion event plus the bytes written to disk.
func sendAndReceive(t *testing.T, data []byte, filename string) (client.EvFileComplete, []byte) {
	t.Helper()
	ts := httptest.NewServer(server.Handler(config.Default(), quietLogger()))
	t.Cleanup(ts.Close)

	recvDir := t.TempDir()
	t.Chdir(recvDir) // the receiver auto-saves to the working directory
	src := filepath.Join(t.TempDir(), filename)
	if err := os.WriteFile(src, data, 0o600); err != nil {
		t.Fatal(err)
	}

	alice, bob := twoInRoom(t, ts.URL, "ops")
	if err := alice.SendFile(src); err != nil {
		t.Fatalf("send: %v", err)
	}
	off := waitMatch[client.EvFileOffer](t, bob, func(e client.EvFileOffer) bool {
		return e.Filename == filename
	}, 5*time.Second)
	comp := waitMatch[client.EvFileComplete](t, bob, func(e client.EvFileComplete) bool {
		return e.TransferID == off.TransferID
	}, 20*time.Second)

	var got []byte
	if comp.OK {
		b, err := os.ReadFile(filepath.Join(recvDir, filename))
		if err != nil {
			t.Fatalf("artifact not written: %v", err)
		}
		got = b
	}
	return comp, got
}

// TestFileTransferSmall: a sub-chunk artifact round-trips and verifies (§2.3).
func TestFileTransferSmall(t *testing.T) {
	data := []byte("a small but important secret artifact")
	comp, got := sendAndReceive(t, data, "secret.key")
	if !comp.OK {
		t.Fatalf("transfer failed: %s", comp.Err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("content mismatch:\n got %q\nwant %q", got, data)
	}
}

// TestFileTransferLarge: a many-chunk artifact (>10 chunks) round-trips and the
// reassembled SHA-256 matches (proven by OK + byte equality).
func TestFileTransferLarge(t *testing.T) {
	data := make([]byte, 11*64*1024+777) // 12 chunks
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	comp, got := sendAndReceive(t, data, "heap.prof")
	if !comp.OK {
		t.Fatalf("transfer failed: %s", comp.Err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("content mismatch (len got=%d want=%d)", len(got), len(data))
	}
}

// TestFileMaxSizeRejectedAtOffer: an artifact over the cap is refused before any
// frame is sent.
func TestFileMaxSizeRejectedAtOffer(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLogger()))
	defer ts.Close()
	t.Chdir(t.TempDir())
	src := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(src, make([]byte, 500), 0o600); err != nil {
		t.Fatal(err)
	}

	alice := connect(t, ts.URL, "ops", "alice", "")
	waitMatch[client.EvKeyReady](t, alice, nil, 5*time.Second)
	alice.SetMaxFileBytes(100) // smaller than the file

	err := alice.SendFile(src)
	if err == nil {
		t.Fatal("expected SendFile to reject an oversized artifact at offer time")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("rejected at offer time")) {
		t.Fatalf("error = %v, want it to mention rejection at offer time", err)
	}
}

// TestFileSenderDisconnect: a sender dropping mid-transfer aborts the receiver.
func TestFileSenderDisconnect(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLogger()))
	defer ts.Close()
	t.Chdir(t.TempDir())
	data := make([]byte, 5<<20) // 5 MiB — cannot complete instantly
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "dump.bin")
	if err := os.WriteFile(src, data, 0o600); err != nil {
		t.Fatal(err)
	}

	alice, bob := twoInRoom(t, ts.URL, "ops")
	if err := alice.SendFile(src); err != nil {
		t.Fatalf("send: %v", err)
	}
	// Once the receiver has the offer, drop the sender mid-stream.
	waitMatch[client.EvFileOffer](t, bob, func(e client.EvFileOffer) bool { return e.Filename == "dump.bin" }, 5*time.Second)
	_ = alice.Close()

	comp := waitMatch[client.EvFileComplete](t, bob, func(e client.EvFileComplete) bool { return !e.OK }, 10*time.Second)
	if comp.OK {
		t.Fatal("transfer should have aborted when the sender disconnected")
	}
}

// TestFileTailEvents: a receiver's file events map to file_offer and file_complete
// in the structured event stream (§1.7) that `tail --json` emits.
func TestFileTailEvents(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLogger()))
	defer ts.Close()
	t.Chdir(t.TempDir())
	src := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(src, []byte("k = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	alice, bob := twoInRoom(t, ts.URL, "ops")
	if err := alice.SendFile(src); err != nil {
		t.Fatalf("send: %v", err)
	}
	off := waitMatch[client.EvFileOffer](t, bob, func(e client.EvFileOffer) bool { return e.Filename == "config.toml" }, 5*time.Second)
	comp := waitMatch[client.EvFileComplete](t, bob, func(e client.EvFileComplete) bool { return e.TransferID == off.TransferID }, 10*time.Second)

	m := eventlog.NewMapper("ops", false)
	offEvts := m.Map(off)
	if len(offEvts) != 1 || offEvts[0].Type != "file_offer" || offEvts[0].Filename != "config.toml" || offEvts[0].TransferID != off.TransferID {
		t.Fatalf("file_offer event = %+v", offEvts)
	}
	compEvts := m.Map(comp)
	if len(compEvts) != 1 || compEvts[0].Type != "file_complete" || compEvts[0].OK == nil || !*compEvts[0].OK {
		t.Fatalf("file_complete event = %+v", compEvts)
	}
}
