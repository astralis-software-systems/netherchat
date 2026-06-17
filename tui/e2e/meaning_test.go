package e2e

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/record"
)

// TestSealWithMeaning proves /seal can carry a declared electronic-signature
// meaning end-to-end (item 2): two clients co-seal with different meanings, and
// the finalized record records each signer's meaning/name/time, verifies VALID,
// and is labeled v2.
func TestSealWithMeaning(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLogger()))
	defer ts.Close()

	alice := connect(t, ts.URL, "inc-m", "Dr. Alice Example", "")
	waitMatch[client.EvKeyReady](t, alice, nil, 5*time.Second)
	bob := connect(t, ts.URL, "inc-m", "Bob Engineer", "")
	waitMatch[client.EvKeyReady](t, bob, nil, 5*time.Second)
	waitMatch[client.EvMemberJoined](t, alice, func(e client.EvMemberJoined) bool { return e.Name == "Bob Engineer" }, 5*time.Second)

	if err := alice.Decide("approve release 5.2"); err != nil {
		t.Fatalf("decide: %v", err)
	}
	waitMatch[client.EvRecordEntry](t, bob, func(e client.EvRecordEntry) bool {
		return !e.Self && e.Kind == record.KindDecision
	}, 5*time.Second)

	// alice initiates declaring "approved"; bob co-signs declaring "reviewed".
	if err := alice.SealAs(record.MeaningApproved); err != nil {
		t.Fatalf("alice seal as: %v", err)
	}
	waitMatch[client.EvSealRequest](t, bob, func(e client.EvSealRequest) bool { return !e.Self && e.Matches }, 5*time.Second)
	if err := bob.SealAs(record.MeaningReviewed); err != nil {
		t.Fatalf("bob seal as: %v", err)
	}

	done := waitMatch[client.EvSealComplete](t, alice, nil, 10*time.Second)
	rec := done.Record
	if rec == nil {
		t.Fatal("seal complete carried no record")
	}
	if rec.Version != record.FormatVersionV2 {
		t.Fatalf("meaning-bearing record version = %q, want %q", rec.Version, record.FormatVersionV2)
	}
	if len(rec.Endorsements) != 2 {
		t.Fatalf("endorsements = %d, want 2", len(rec.Endorsements))
	}
	meanings := map[string]bool{}
	for _, e := range rec.Endorsements {
		if e.Name == "" || e.SignedAt == "" {
			t.Fatalf("endorsement missing name/time: %+v", e)
		}
		meanings[e.Meaning] = true
	}
	if !meanings[record.MeaningApproved] || !meanings[record.MeaningReviewed] {
		t.Fatalf("declared meanings missing: %+v", rec.Endorsements)
	}

	res, err := record.Verify(rec)
	if err != nil || !res.Valid {
		t.Fatalf("meaning-bearing record did not verify: err=%v reason=%q", err, res.Reason)
	}
}

// TestApprovalCarriesMeaning proves a two-person-rule approval carries a declared
// meaning end-to-end (item 2): the meaning surfaces on the approval event, and the
// signature still drives the quorum gate.
func TestApprovalCarriesMeaning(t *testing.T) {
	_, alice, bob := twoMembers(t)

	id, err := alice.RequestAction("runbook", "cmd=drain, requested_by=carol", 2, func() {})
	if err != nil {
		t.Fatalf("request action: %v", err)
	}
	waitMatch[client.EvActionRequest](t, bob, nil, 5*time.Second)

	if err := bob.ApproveActionAs(id, record.MeaningReviewed); err != nil {
		t.Fatalf("bob approve as: %v", err)
	}
	ap := waitMatch[client.EvActionApproval](t, alice, func(e client.EvActionApproval) bool { return !e.Self }, 5*time.Second)
	if ap.Meaning != record.MeaningReviewed {
		t.Fatalf("approval meaning = %q, want %q", ap.Meaning, record.MeaningReviewed)
	}
	// The signed, meaning-bearing approval still satisfies quorum and fires.
	waitMatch[client.EvActionExecuted](t, alice, nil, 5*time.Second)
}
