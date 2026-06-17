package config

import "testing"

// TestDurableRoomParsing parses the opt-in durable case-room profile and checks
// the persistence-gating helpers.
func TestDurableRoomParsing(t *testing.T) {
	cfg, err := Parse([]byte(`
[persistence]
enabled = false
path = "/tmp/nc.db"

[rooms.case-001]
durable = true

[rooms.chatter]
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if !cfg.Room("case-001").Durable {
		t.Fatal("case-001 should be durable")
	}
	if cfg.Room("chatter").Durable {
		t.Fatal("chatter must not be durable")
	}
	if !cfg.AnyDurableRoom() {
		t.Fatal("AnyDurableRoom should be true")
	}

	// Default (global off): only the durable room is persisted; others keep nothing.
	if !cfg.PersistRoom("case-001") {
		t.Fatal("a durable room must be persisted")
	}
	if cfg.PersistRoom("chatter") {
		t.Fatal("a non-durable room must not be persisted when global persistence is off")
	}
	// History defaulted because a durable room exists, even with global off.
	if cfg.Persistence.History != 100 {
		t.Fatalf("history defaulted to %d, want 100", cfg.Persistence.History)
	}
}

// TestGlobalPersistencePersistsAllRooms confirms the legacy behavior is unchanged:
// with global persistence on, every room is persisted regardless of durable.
func TestGlobalPersistencePersistsAllRooms(t *testing.T) {
	cfg, err := Parse([]byte(`
[persistence]
enabled = true
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !cfg.PersistRoom("anything") {
		t.Fatal("global persistence should persist every room")
	}
}

// TestNoPersistenceByDefault confirms the documented default: nothing is persisted.
func TestNoPersistenceByDefault(t *testing.T) {
	cfg := Default()
	if cfg.AnyDurableRoom() {
		t.Fatal("default config has no durable rooms")
	}
	if cfg.PersistRoom("ops") {
		t.Fatal("default config must persist nothing")
	}
}
