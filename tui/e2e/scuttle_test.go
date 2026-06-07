package e2e

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/tui/client"
)

// scuttleConfig builds a config with a scuttle policy on room "ops".
func scuttleConfig(p config.ScuttlePolicy) config.Config {
	c := config.Default()
	c.Rooms = map[string]config.RoomConfig{"ops": {Scuttle: p}}
	return c
}

// waitScuttle waits for the dead-man's-switch control to reach a client and
// returns it. It filters to Action=="scuttle" so an earlier scuttle_arm notice is
// skipped.
func waitScuttle(t *testing.T, c *client.Client) client.EvControl {
	t.Helper()
	return waitMatch[client.EvControl](t, c, func(e client.EvControl) bool {
		return e.Action == "scuttle"
	}, 8*time.Second)
}

// TestScuttleIdle proves a quiet room scuttles itself after idle_after, the
// client receives the burn with reason "idle", and it has ratcheted its room key
// forward (epoch advanced) — forward secrecy on the way out.
func TestScuttleIdle(t *testing.T) {
	cfg := scuttleConfig(config.ScuttlePolicy{
		IdleAfter: config.Duration(150 * time.Millisecond),
		Heartbeat: config.Duration(25 * time.Millisecond),
	})
	ts := httptest.NewServer(server.Handler(cfg, quietLogger()))
	defer ts.Close()

	alice := connect(t, ts.URL, "ops", "alice", "")
	waitMatch[client.EvKeyReady](t, alice, nil, 5*time.Second)
	before := alice.Epoch()

	ev := waitScuttle(t, alice)
	if ev.Reason != "idle" {
		t.Fatalf("scuttle reason = %q, want idle", ev.Reason)
	}
	if got := alice.Epoch(); got != before+1 {
		t.Fatalf("key ratchet did not run: epoch %d → %d, want +1", before, got)
	}
}

// TestScuttleOwnerLoss proves the room burns when its founding connection drops
// while others remain (owner_loss_burn).
func TestScuttleOwnerLoss(t *testing.T) {
	cfg := scuttleConfig(config.ScuttlePolicy{OwnerLossBurn: true})
	ts := httptest.NewServer(server.Handler(cfg, quietLogger()))
	defer ts.Close()

	alice := connect(t, ts.URL, "ops", "alice", "") // founder
	waitMatch[client.EvKeyReady](t, alice, nil, 5*time.Second)
	bob := connect(t, ts.URL, "ops", "bob", "")
	waitMatch[client.EvKeyReady](t, bob, nil, 5*time.Second)
	// alice must still be present (and the founder) when she leaves.
	waitMatch[client.EvMemberJoined](t, alice, func(e client.EvMemberJoined) bool { return e.Name == "bob" }, 5*time.Second)

	before := bob.Epoch()
	_ = alice.Close() // the founder disconnects

	ev := waitScuttle(t, bob)
	if ev.Reason != "owner_loss" {
		t.Fatalf("scuttle reason = %q, want owner_loss", ev.Reason)
	}
	if got := bob.Epoch(); got != before+1 {
		t.Fatalf("key ratchet did not run on bob: epoch %d → %d", before, got)
	}
}

// TestScuttleNow proves /scuttle now burns the room immediately for everyone.
func TestScuttleNow(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLogger()))
	defer ts.Close()

	alice := connect(t, ts.URL, "ops", "alice", "")
	waitMatch[client.EvKeyReady](t, alice, nil, 5*time.Second)
	bob := connect(t, ts.URL, "ops", "bob", "")
	waitMatch[client.EvKeyReady](t, bob, nil, 5*time.Second)
	waitMatch[client.EvMemberJoined](t, alice, func(e client.EvMemberJoined) bool { return e.Name == "bob" }, 5*time.Second)

	before := bob.Epoch()
	alice.ScuttleNow()

	ev := waitScuttle(t, bob)
	if ev.Reason != "manual" {
		t.Fatalf("scuttle reason = %q, want manual", ev.Reason)
	}
	if got := bob.Epoch(); got != before+1 {
		t.Fatalf("key ratchet did not run on bob: epoch %d → %d", before, got)
	}
}

// TestScuttleArm proves /scuttle arm shows a visible countdown to all
// participants and then auto-burns when it elapses.
func TestScuttleArm(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLogger()))
	defer ts.Close()

	alice := connect(t, ts.URL, "ops", "alice", "")
	waitMatch[client.EvKeyReady](t, alice, nil, 5*time.Second)
	bob := connect(t, ts.URL, "ops", "bob", "")
	waitMatch[client.EvKeyReady](t, bob, nil, 5*time.Second)
	waitMatch[client.EvMemberJoined](t, alice, func(e client.EvMemberJoined) bool { return e.Name == "bob" }, 5*time.Second)

	alice.ScuttleArm(1) // 1-second countdown (minimum granularity)

	// Everyone sees the countdown first…
	arm := waitMatch[client.EvControl](t, bob, func(e client.EvControl) bool {
		return e.Action == "scuttle_arm"
	}, 5*time.Second)
	if arm.TTLSeconds != 1 {
		t.Fatalf("arm countdown = %ds, want 1", arm.TTLSeconds)
	}
	// …then the burn fires when it reaches zero.
	if ev := waitScuttle(t, bob); ev.Reason != "armed" {
		t.Fatalf("scuttle reason = %q, want armed", ev.Reason)
	}
}
