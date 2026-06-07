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
