package e2e

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/record"
)

// TestSealRoundTrip is the §1.4 acceptance test: two real clients build the same
// record chain through the relay, one seals, the other co-signs, and the
// resulting record.json verifies and renders to minutes. It exercises the whole
// loop — /decide and /action broadcast as E2E entries, the seal request/ack
// handshake, multi-party signing, and verification — end to end.
func TestSealRoundTrip(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLogger()))
	defer ts.Close()

	alice := connect(t, ts.URL, "inc-001", "alice", "")
	waitMatch[client.EvKeyReady](t, alice, nil, 5*time.Second)
	bob := connect(t, ts.URL, "inc-001", "bob", "")
	waitMatch[client.EvKeyReady](t, bob, nil, 5*time.Second)
	// alice must observe bob so her seal denominator (present members) is 2.
	waitMatch[client.EvMemberJoined](t, alice, func(e client.EvMemberJoined) bool { return e.Name == "bob" }, 5*time.Second)

	// alice marks two entries; bob receives each before the next so the chains
	// build in the same order (ordered relay guarantees convergence).
	if err := alice.Decide("rolled back to v2.3.1 at 03:47 UTC"); err != nil {
		t.Fatalf("decide: %v", err)
	}
	waitMatch[client.EvRecordEntry](t, bob, func(e client.EvRecordEntry) bool {
		return !e.Self && e.Kind == record.KindDecision && strings.Contains(e.Body, "v2.3.1")
	}, 5*time.Second)

	if err := alice.Action("bob", "write post-mortem by Friday"); err != nil {
		t.Fatalf("action: %v", err)
	}
	waitMatch[client.EvRecordEntry](t, bob, func(e client.EvRecordEntry) bool {
		return !e.Self && e.Kind == record.KindAction && e.Actionee == "bob"
	}, 5*time.Second)

	// Both clients must have built the identical chain.
	aliceEntries, bobEntries := alice.RecordEntries(), bob.RecordEntries()
	if len(aliceEntries) != 2 || len(bobEntries) != 2 {
		t.Fatalf("chain lengths: alice=%d bob=%d, want 2 and 2", len(aliceEntries), len(bobEntries))
	}
	for i := range aliceEntries {
		ah, bh := aliceEntries[i].Hash(), bobEntries[i].Hash()
		if ah != bh {
			t.Fatalf("entry %d differs between alice and bob (chains diverged)", i)
		}
	}

	// alice initiates the seal; bob must see the request before co-signing.
	if err := alice.Seal(); err != nil {
		t.Fatalf("alice seal: %v", err)
	}
	waitMatch[client.EvSealRequest](t, bob, func(e client.EvSealRequest) bool {
		return !e.Self && e.Matches && e.NumEntries == 2
	}, 5*time.Second)
	if err := bob.Seal(); err != nil {
		t.Fatalf("bob co-sign: %v", err)
	}

	done := waitMatch[client.EvSealComplete](t, alice, nil, 10*time.Second)
	rec := done.Record
	if rec == nil {
		t.Fatal("seal complete carried no record")
	}
	if len(rec.Entries) != 2 {
		t.Fatalf("sealed %d entries, want 2", len(rec.Entries))
	}
	if len(rec.Signatures) != 2 {
		t.Fatalf("sealed with %d signatures, want 2 (alice + bob)", len(rec.Signatures))
	}

	// The record must verify, and the minutes must name the decision and action.
	res, err := record.Verify(rec)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if !res.Valid {
		t.Fatalf("sealed record did not verify: %s", res.Reason)
	}
	if len(res.Signers) != 2 {
		t.Errorf("verified %d signers, want 2", len(res.Signers))
	}

	md := record.RenderMinutes(rec)
	for _, want := range []string{
		"# Incident Record — inc-001",
		"rolled back to v2.3.1 at 03:47 UTC",
		"write post-mortem by Friday (assigned by alice)",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("minutes missing %q\n---\n%s", want, md)
		}
	}

	// round-trip the record through its on-disk form.
	b, err := rec.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parsed, err := record.Parse(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if res2, _ := record.Verify(parsed); !res2.Valid {
		t.Fatalf("round-tripped record failed to verify: %s", res2.Reason)
	}
}

// TestSealMarkPromotesLastMessage proves /mark promotes the most recent message
// into the record as a note attributed to the marker, preserving the original
// speaker in the body.
func TestSealMarkPromotesLastMessage(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLogger()))
	defer ts.Close()

	alice := connect(t, ts.URL, "inc-002", "alice", "")
	waitMatch[client.EvKeyReady](t, alice, nil, 5*time.Second)

	if err := alice.Send("all nodes confirmed healthy"); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := alice.Mark(); err != nil {
		t.Fatalf("mark: %v", err)
	}
	e := waitMatch[client.EvRecordEntry](t, alice, func(e client.EvRecordEntry) bool { return e.Self }, 5*time.Second)
	if e.Kind != record.KindNote {
		t.Errorf("marked entry kind = %q, want note", e.Kind)
	}
	if !strings.Contains(e.Body, "all nodes confirmed healthy") {
		t.Errorf("marked body = %q", e.Body)
	}
}
