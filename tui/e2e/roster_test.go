package e2e

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/client"
)

// TestRosterAttestation proves /roster --signed produces a roster.json that both
// present members co-sign, and that the artifact verifies offline (§1.4) — the
// Demo 1 acceptance path.
func TestRosterAttestation(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLogger()))
	defer ts.Close()

	alice := connect(t, ts.URL, "ops", "alice", "")
	waitMatch[client.EvKeyReady](t, alice, nil, 5*time.Second)
	bob := connect(t, ts.URL, "ops", "bob", "")
	waitMatch[client.EvKeyReady](t, bob, nil, 5*time.Second)
	// alice must see bob in her membership set before she attests it.
	waitMatch[client.EvMemberJoined](t, alice, func(e client.EvMemberJoined) bool { return e.Name == "bob" }, 5*time.Second)

	if err := alice.SignRoster(nil); err != nil {
		t.Fatalf("sign roster: %v", err)
	}
	ev := waitMatch[client.EvRosterComplete](t, alice, nil, 8*time.Second)

	att := ev.Attestation
	if att == nil {
		t.Fatal("no attestation produced")
	}
	if len(att.Members) != 2 {
		t.Fatalf("attestation members = %d, want 2", len(att.Members))
	}
	if len(att.Signatures) != 2 {
		t.Fatalf("signatures = %d, want 2 (alice + bob co-signed)", len(att.Signatures))
	}

	res, err := attest.VerifyRoster(att)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.Valid {
		t.Fatalf("roster should verify VALID: %s", res.Reason)
	}
	if len(res.Signers) != 2 {
		t.Errorf("verified signers = %d, want 2", len(res.Signers))
	}
}
