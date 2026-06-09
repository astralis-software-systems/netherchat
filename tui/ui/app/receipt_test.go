package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/client"
)

// TestReceiptFilename pins the scuttle-receipt output naming (§1.5).
func TestReceiptFilename(t *testing.T) {
	name := receiptFilename("inc-3f9a")
	if !strings.HasPrefix(name, "netherchat-receipt-inc-3f9a-") || !strings.HasSuffix(name, ".json") {
		t.Errorf("unexpected receipt filename: %q", name)
	}
}

// TestScuttleReceiptWritesFile proves the EvScuttleReceipt handler writes the
// receipt to the working directory and confirms it.
func TestScuttleReceiptWritesFile(t *testing.T) {
	dir := t.TempDir()
	cwd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })

	m := newModel("ws://localhost:3000", "me", "", "ops", "")
	m.resize(100, 30)
	r := m.activeRoom()

	rec := &attest.ScuttleReceipt{
		ReceiptCore: attest.ReceiptCore{Version: attest.ReceiptVersion, Room: "ops", KeysZeroized: true},
		ReceiptHash: "00",
		Signatures:  map[string]string{},
		SignerKeys:  map[string]string{},
	}
	m.handleRoomEvent("ops", client.EvScuttleReceipt{Receipt: rec})

	files, _ := filepath.Glob(filepath.Join(dir, "netherchat-receipt-ops-*.json"))
	if len(files) != 1 {
		t.Fatalf("expected 1 receipt file written, found %d", len(files))
	}
	last := r.lines[len(r.lines)-1]
	if last.kind != lineSystem || !strings.Contains(last.text, "Room scuttled. Receipt written to") {
		t.Errorf("expected the receipt confirmation, got %+v", last)
	}
}
