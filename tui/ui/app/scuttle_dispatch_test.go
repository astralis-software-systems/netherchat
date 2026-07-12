package app

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
)

// These tests drive the REAL command dispatch a user takes — m.runCommand("/scuttle
// now") — with the client's own quorum policy installed. The read found this path
// wholly untested (every prior "two-person scuttle" test hand-rolled RequestAction),
// which is how a wiring gap passed CI green. They assert branch selection: gated when
// quorum > 1, instant when quorum <= 1.

// TestScuttleCommandGatesWhenQuorumConfigured proves /scuttle now opens an approval
// gate (does not burn) when [action.scuttle] quorum > 1.
func TestScuttleCommandGatesWhenQuorumConfigured(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), discardLogger()))
	defer ts.Close()

	alice := connectCore(t, ts.URL, "ops", "alice")
	waitKeyReady(t, alice)
	bob := connectCore(t, ts.URL, "ops", "bob")
	waitKeyReady(t, bob)
	alice.SetActionQuorum(map[string]int{"scuttle": 2})

	m := newModel(ts.URL, "alice", "", "ops", "")
	r := m.activeRoom()
	r.client = alice
	r.connected = true
	before := alice.Epoch()

	m.runCommand("/scuttle now")

	p := waitPending(t, alice)
	if p.Action != "scuttle" || p.Needed != 2 || !p.Initiator {
		t.Fatalf("pending = %+v, want an initiator scuttle needing 2", p)
	}
	if alice.Epoch() != before {
		t.Fatal("the room burned — /scuttle now did not gate at quorum 2")
	}
}

// TestScuttleCommandInstantWhenSingleActor proves /scuttle now takes the instant
// branch (no gate) at the default single-actor quorum — the emergency dead-man's
// switch is preserved (D1).
func TestScuttleCommandInstantWhenSingleActor(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), discardLogger()))
	defer ts.Close()

	alice := connectCore(t, ts.URL, "ops", "alice")
	waitKeyReady(t, alice)
	bob := connectCore(t, ts.URL, "ops", "bob")
	waitKeyReady(t, bob)
	// No SetActionQuorum → default quorum 1 (single-actor).

	m := newModel(ts.URL, "alice", "", "ops", "")
	r := m.activeRoom()
	r.client = alice
	r.connected = true
	before := alice.Epoch()

	m.runCommand("/scuttle now")

	// The instant branch opens NO approval request…
	if p := alice.PendingActions(); len(p) != 0 {
		t.Fatalf("instant /scuttle now should open no pending request, got %+v", p)
	}
	// …and the burn fires (the room key ratchets after the receipt round + control).
	deadline := time.Now().Add(6 * time.Second)
	for alice.Epoch() == before {
		if time.Now().After(deadline) {
			t.Fatal("single-actor /scuttle now did not burn (no ratchet)")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
