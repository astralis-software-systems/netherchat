package eventlog

import (
	"testing"

	"github.com/salehkreiner/netherchat/tui/client"
)

// TestMapperScuttle proves the dead-man's switch (§1.6) surfaces in the
// structured event stream as a metadata-only scuttle event carrying the reason
// and ttl_remaining=0 — the auditable fact that the room scuttled, never content.
func TestMapperScuttle(t *testing.T) {
	m := NewMapper("ops", false)
	out := m.Map(client.EvControl{Action: "scuttle", Reason: "idle"})
	if len(out) != 1 {
		t.Fatalf("scuttle control mapped to %d events, want 1", len(out))
	}
	e := out[0]
	if e.Type != "scuttle" || e.Room != "ops" || e.Reason != "idle" {
		t.Fatalf("scuttle event = %+v", e)
	}
	if e.TTLRemaining == nil || *e.TTLRemaining != 0 {
		t.Fatalf("ttl_remaining = %v, want 0 (emitted)", e.TTLRemaining)
	}
}

// TestMapperActionEvents proves all five Two-Person Rule (§1.3) client events map
// to the right structured tail event type carrying the expected fields.
func TestMapperActionEvents(t *testing.T) {
	const id = "a3f9c1d2e4b5a6f7"
	m := NewMapper("ops", false)

	req := m.Map(client.EvActionRequest{RequestID: id, Action: "scuttle", RequesterName: "alice", RequesterFpr: fpr, QuorumNeeded: 2, ExpiresUnix: 1749230400})
	if len(req) != 1 || req[0].Type != "action_request" || req[0].Actor != "alice" || req[0].Action != "scuttle" || req[0].RequestID != id {
		t.Fatalf("action_request mapping = %+v", req)
	}
	if req[0].QuorumNeeded == nil || *req[0].QuorumNeeded != 2 || req[0].ExpiresUnix != 1749230400 {
		t.Fatalf("action_request quorum/expiry = %+v", req[0])
	}

	app := m.Map(client.EvActionApproval{RequestID: id, Action: "scuttle", ApproverName: "bob", ApproverFpr: fpr2, Count: 2, Needed: 2})
	if len(app) != 1 || app[0].Type != "action_approval" || app[0].Actor != "bob" {
		t.Fatalf("action_approval mapping = %+v", app)
	}
	if app[0].QuorumCurrent == nil || *app[0].QuorumCurrent != 2 || app[0].QuorumNeeded == nil || *app[0].QuorumNeeded != 2 {
		t.Fatalf("action_approval quorum = %+v", app[0])
	}

	exe := m.Map(client.EvActionExecuted{RequestID: id, Action: "scuttle", RequesterName: "alice", RequesterFpr: fpr, Quorum: 2})
	if len(exe) != 1 || exe[0].Type != "action_executed" || exe[0].Actor != "alice" || exe[0].Quorum != float64(2) {
		t.Fatalf("action_executed mapping = %+v (quorum %v)", exe, exe[0].Quorum)
	}

	vet := m.Map(client.EvActionVetoed{RequestID: id, Action: "scuttle", VetoerName: "bob", VetoerFpr: fpr2, Reason: "wrong room"})
	if len(vet) != 1 || vet[0].Type != "action_vetoed" || vet[0].Actor != "bob" || vet[0].Reason != "wrong room" {
		t.Fatalf("action_vetoed mapping = %+v", vet)
	}

	exp := m.Map(client.EvActionExpired{RequestID: id, Action: "scuttle", ApprovalsReceived: 1, QuorumNeeded: 2})
	if len(exp) != 1 || exp[0].Type != "action_expired" {
		t.Fatalf("action_expired mapping = %+v", exp)
	}
	if exp[0].ApprovalsReceived == nil || *exp[0].ApprovalsReceived != 1 {
		t.Fatalf("action_expired approvals_received = %+v", exp[0])
	}
}

// TestMapperBeaconEvents proves the beacon_set/beacon_cleared controls (§1.2) map
// to the corresponding metadata-only events (never any status content).
func TestMapperBeaconEvents(t *testing.T) {
	m := NewMapper("ops", false)
	m.Map(client.EvMemberJoined{ID: "1", Name: "alice", Fingerprint: fpr}) // seed the directory

	set := m.Map(client.EvControl{Action: "beacon_set", ByName: "alice", TTLSeconds: 3600})
	if len(set) != 1 || set[0].Type != "beacon_set" || set[0].Actor != "alice" || set[0].TTLSeconds != 3600 || set[0].Fpr != fpr {
		t.Fatalf("beacon_set mapping = %+v", set)
	}

	clr := m.Map(client.EvControl{Action: "beacon_cleared", ByName: "alice"})
	if len(clr) != 1 || clr[0].Type != "beacon_cleared" || clr[0].Actor != "alice" {
		t.Fatalf("beacon_cleared mapping = %+v", clr)
	}
}

// TestMapperControlNonScuttle proves ttl and scuttle_arm controls are not part of
// the v1 event schema (they map to nothing).
func TestMapperControlNonScuttle(t *testing.T) {
	m := NewMapper("ops", false)
	for _, action := range []string{"ttl", "scuttle_arm"} {
		if out := m.Map(client.EvControl{Action: action, TTLSeconds: 600}); out != nil {
			t.Errorf("%s control mapped to %d events, want none", action, len(out))
		}
	}
	// vanish still maps (regression guard).
	if out := m.Map(client.EvControl{Action: "vanish", ByName: "alice"}); len(out) != 1 || out[0].Type != "vanish" {
		t.Errorf("vanish mapping regressed: %+v", out)
	}
}
