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

// waitReceipt waits for a scuttle receipt to be produced and verifies it is a
// VALID artifact, returning it for further assertions (§1.5).
func waitReceipt(t *testing.T, c *client.Client) *attest.ScuttleReceipt {
	t.Helper()
	ev := waitMatch[client.EvScuttleReceipt](t, c, nil, 8*time.Second)
	rec := ev.Receipt
	if rec == nil {
		t.Fatal("EvScuttleReceipt carried no receipt")
	}
	res, err := attest.VerifyReceipt(rec)
	if err != nil {
		t.Fatalf("verify receipt: %v", err)
	}
	if !res.Valid {
		t.Fatalf("receipt should verify VALID: %s", res.Error)
	}
	if !rec.KeysZeroized {
		t.Error("receipt keys_zeroized should be true")
	}
	return rec
}

// TestScuttleReceiptNow proves /scuttle now writes a receipt BEFORE key
// zeroization, co-signed by a second present member (Demo 2).
func TestScuttleReceiptNow(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLogger()))
	defer ts.Close()

	alice := connect(t, ts.URL, "ops", "alice", "")
	waitMatch[client.EvKeyReady](t, alice, nil, 5*time.Second)
	bob := connect(t, ts.URL, "ops", "bob", "")
	waitMatch[client.EvKeyReady](t, bob, nil, 5*time.Second)
	waitMatch[client.EvMemberJoined](t, alice, func(e client.EvMemberJoined) bool { return e.Name == "bob" }, 5*time.Second)

	beforeEpoch := alice.Epoch()
	alice.ScuttleNow()

	rec := waitReceipt(t, alice)
	if rec.Reason != "manual" {
		t.Errorf("reason = %q, want manual", rec.Reason)
	}
	if len(rec.Signatures) != 2 {
		t.Fatalf("signatures = %d, want 2 (alice + bob co-signed)", len(rec.Signatures))
	}
	// epoch_range.last is the LIVE epoch — proof the receipt was built before the
	// ratchet/zeroize that the burn triggers.
	if rec.EpochRange.Last != beforeEpoch {
		t.Errorf("epoch_range.last = %d, want the pre-scuttle epoch %d", rec.EpochRange.Last, beforeEpoch)
	}
}

// TestScuttleReceiptIdle proves a server-triggered idle scuttle makes the client
// write its own (self-signed) receipt.
func TestScuttleReceiptIdle(t *testing.T) {
	cfg := scuttleConfig(config.ScuttlePolicy{
		IdleAfter: config.Duration(150 * time.Millisecond),
		Heartbeat: config.Duration(25 * time.Millisecond),
	})
	ts := httptest.NewServer(server.Handler(cfg, quietLogger()))
	defer ts.Close()

	alice := connect(t, ts.URL, "ops", "alice", "")
	waitMatch[client.EvKeyReady](t, alice, nil, 5*time.Second)

	rec := waitReceipt(t, alice)
	if rec.Reason != "idle" {
		t.Fatalf("reason = %q, want idle", rec.Reason)
	}
	if len(rec.Signatures) != 1 {
		t.Errorf("a self-signed receipt should have 1 signature, got %d", len(rec.Signatures))
	}
}

// TestScuttleReceiptArmed proves the /scuttle arm countdown produces a receipt
// when it fires.
func TestScuttleReceiptArmed(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLogger()))
	defer ts.Close()

	alice := connect(t, ts.URL, "ops", "alice", "")
	waitMatch[client.EvKeyReady](t, alice, nil, 5*time.Second)
	alice.ScuttleArm(1) // 1-second countdown

	rec := waitReceipt(t, alice)
	if rec.Reason != "armed" {
		t.Fatalf("reason = %q, want armed", rec.Reason)
	}
}

// TestScuttleReceiptOwnerLoss proves an owner-loss scuttle makes the remaining
// member write a receipt.
func TestScuttleReceiptOwnerLoss(t *testing.T) {
	cfg := scuttleConfig(config.ScuttlePolicy{OwnerLossBurn: true})
	ts := httptest.NewServer(server.Handler(cfg, quietLogger()))
	defer ts.Close()

	alice := connect(t, ts.URL, "ops", "alice", "") // founder
	waitMatch[client.EvKeyReady](t, alice, nil, 5*time.Second)
	bob := connect(t, ts.URL, "ops", "bob", "")
	waitMatch[client.EvKeyReady](t, bob, nil, 5*time.Second)
	waitMatch[client.EvMemberJoined](t, alice, func(e client.EvMemberJoined) bool { return e.Name == "bob" }, 5*time.Second)

	_ = alice.Close() // the founder disconnects → owner_loss scuttle

	rec := waitReceipt(t, bob)
	if rec.Reason != "owner_loss" {
		t.Fatalf("reason = %q, want owner_loss", rec.Reason)
	}
}
