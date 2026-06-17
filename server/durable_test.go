package server

import (
	"path/filepath"
	"testing"

	"github.com/salehkreiner/netherchat/server/config"
)

// TestOpenStoreForDurableRoomWithGlobalOff proves a store is opened (encrypted
// SQLite at the configured path) when global persistence is OFF but a room opts
// into the durable case-room profile.
func TestOpenStoreForDurableRoomWithGlobalOff(t *testing.T) {
	cfg := config.Default()
	cfg.Persistence.Enabled = false
	cfg.Persistence.Path = filepath.Join(t.TempDir(), "case.db")
	cfg.Persistence.Key = "test-at-rest-secret"
	cfg.Persistence.History = 50
	cfg.Rooms = map[string]config.RoomConfig{"case-001": {Durable: true}}

	st := openStore(cfg, discardLog())
	if st == nil {
		t.Fatal("openStore returned nil despite a durable case room")
	}
	t.Cleanup(func() { _ = st.Close() })
}

// TestOpenStoreNilWhenNothingPersisted confirms the default keeps no store at all.
func TestOpenStoreNilWhenNothingPersisted(t *testing.T) {
	cfg := config.Default() // global off, no durable rooms
	if st := openStore(cfg, discardLog()); st != nil {
		_ = st.Close()
		t.Fatal("openStore should return nil when nothing is persisted")
	}
}
