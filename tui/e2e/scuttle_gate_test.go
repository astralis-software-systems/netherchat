package e2e

import (
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/client"
)

// These tests exercise the CLIENT-CORE two-person-rule gate on the destructive
// actions (§1.3) via the public entry points every caller uses — client.ScuttleNow /
// client.BreakGlass — with the quorum installed as the client's OWN policy
// (SetActionQuorum). They are the regression tests for the governance bypass: before
// the fix these primitives destroyed unconditionally, so a configured quorum did
// nothing from any non-TUI caller.

// drainNoScuttle fails the test if a scuttle actually fires on c within d — either a
// receipt is produced or the scuttle control lands.
func drainNoScuttle(t *testing.T, c *client.Client, d time.Duration) {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case ev := <-c.Events():
			switch e := ev.(type) {
			case client.EvScuttleReceipt:
				t.Fatal("a scuttle receipt was produced but quorum was not met")
			case client.EvControl:
				if e.Action == "scuttle" {
					t.Fatal("the scuttle burn fired but quorum was not met")
				}
			}
		case <-deadline:
			return
		case <-c.Done():
			return
		}
	}
}

// drainNoBreakGlass fails the test if a break-glass war room stands up on c within d.
func drainNoBreakGlass(t *testing.T, c *client.Client, d time.Duration) {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case ev := <-c.Events():
			if _, ok := ev.(client.EvBreakGlass); ok {
				t.Fatal("a break-glass war room stood up but quorum was not met")
			}
		case <-deadline:
			return
		case <-c.Done():
			return
		}
	}
}

// TestScuttleNowQuorumBlocksLoneActor is the headline regression: with the client's
// OWN [action.scuttle] quorum set to 2, a direct client.ScuttleNow() — the exact call
// that used to burn unconditionally from any non-TUI caller — must NOT destroy the
// room. It opens an approval gate instead; with no approver the room survives.
func TestScuttleNowQuorumBlocksLoneActor(t *testing.T) {
	_, alice, _ := twoMembers(t)
	alice.SetActionQuorum(map[string]int{protocol.ActionScuttleAction: 2})
	before := alice.Epoch()

	if err := alice.ScuttleNow(); err != nil {
		t.Fatalf("ScuttleNow opened the gate but returned error: %v", err)
	}
	// No one approves. The room must NOT scuttle.
	drainNoScuttle(t, alice, 700*time.Millisecond)
	if alice.Epoch() != before {
		t.Fatal("the room key ratcheted — a quorum-2 scuttle burned with only the initiator")
	}
}

// TestScuttleNowGatedExecutesWithApproval proves the gated path works end to end:
// alice's quorum-2 ScuttleNow opens a request; bob's single independent approval tips
// it; alice performs the scuttle, writing a VALID co-signed receipt, and the burn
// propagates. The second Ed25519 approval is REQUIRED before any destruction.
func TestScuttleNowGatedExecutesWithApproval(t *testing.T) {
	_, alice, bob := twoMembers(t)
	alice.SetActionQuorum(map[string]int{protocol.ActionScuttleAction: 2})
	before := bob.Epoch()

	if err := alice.ScuttleNow(); err != nil {
		t.Fatalf("ScuttleNow (gated open) returned error: %v", err)
	}
	req := waitMatch[client.EvActionRequest](t, bob, func(e client.EvActionRequest) bool {
		return e.Action == protocol.ActionScuttleAction
	}, 5*time.Second)
	if req.QuorumNeeded != 2 {
		t.Fatalf("bob saw quorum %d, want 2", req.QuorumNeeded)
	}
	if err := bob.ApproveAction(req.RequestID); err != nil {
		t.Fatalf("bob approve: %v", err)
	}

	ev := waitMatch[client.EvScuttleReceipt](t, alice, nil, 8*time.Second)
	if res, verr := attest.VerifyReceipt(ev.Receipt); verr != nil || !res.Valid {
		t.Fatalf("scuttle receipt invalid: %v / %+v", verr, res)
	}
	if sc := waitScuttle(t, bob); sc.Reason != "manual" {
		t.Fatalf("bob saw scuttle reason %q, want manual", sc.Reason)
	}
	if bob.Epoch() != before+1 {
		t.Fatalf("bob epoch %d, want %d (ratchet on burn)", bob.Epoch(), before+1)
	}
}

// TestScuttleNowInstantAtQuorumOne proves the emergency dead-man's-switch is preserved
// (D1): quorum 1 burns immediately, no approval gate.
func TestScuttleNowInstantAtQuorumOne(t *testing.T) {
	_, alice, bob := twoMembers(t)
	alice.SetActionQuorum(map[string]int{protocol.ActionScuttleAction: 1})
	before := bob.Epoch()

	if err := alice.ScuttleNow(); err != nil {
		t.Fatalf("instant ScuttleNow returned error: %v", err)
	}
	if sc := waitScuttle(t, bob); sc.Reason != "manual" {
		t.Fatalf("bob saw scuttle reason %q, want manual", sc.Reason)
	}
	if bob.Epoch() != before+1 {
		t.Fatalf("ratchet did not run on bob: epoch %d → %d", before, bob.Epoch())
	}
}

// TestScuttleDisabledAtQuorumZero proves quorum 0 disables the command: it refuses and
// nothing burns.
func TestScuttleDisabledAtQuorumZero(t *testing.T) {
	_, alice, _ := twoMembers(t)
	alice.SetActionQuorum(map[string]int{protocol.ActionScuttleAction: 0})
	before := alice.Epoch()

	if err := alice.ScuttleNow(); err == nil {
		t.Fatal("ScuttleNow with quorum 0 must refuse")
	}
	drainNoScuttle(t, alice, 400*time.Millisecond)
	if alice.Epoch() != before {
		t.Fatal("the room burned despite quorum 0 (disabled)")
	}
}

// TestScuttleArmQuorumBlocksLoneActor proves /scuttle arm is gated too: a quorum-2 arm
// opens a request rather than starting the countdown unilaterally.
func TestScuttleArmQuorumBlocksLoneActor(t *testing.T) {
	_, alice, bob := twoMembers(t)
	alice.SetActionQuorum(map[string]int{protocol.ActionScuttleAction: 2})

	if err := alice.ScuttleArm(1); err != nil {
		t.Fatalf("ScuttleArm opened the gate but returned error: %v", err)
	}
	// bob observes a gated request; without approval no arm countdown is broadcast.
	waitMatch[client.EvActionRequest](t, bob, func(e client.EvActionRequest) bool {
		return e.Action == protocol.ActionScuttleAction
	}, 5*time.Second)
	// No scuttle_arm control should reach bob within the window.
	deadline := time.After(600 * time.Millisecond)
	for {
		select {
		case ev := <-bob.Events():
			if c, ok := ev.(client.EvControl); ok && c.Action == "scuttle_arm" {
				t.Fatal("an arm countdown was broadcast without quorum")
			}
		case <-deadline:
			return
		case <-bob.Done():
			return
		}
	}
}

// TestBreakGlassQuorumBlocksLoneActor proves the twin action is fixed by the same
// stroke: a quorum-2 client.BreakGlass opens a request and does NOT stand up the war
// room until a second member approves.
func TestBreakGlassQuorumBlocksLoneActor(t *testing.T) {
	_, alice, bob := twoMembers(t)
	alice.SetActionQuorum(map[string]int{protocol.ActionBreakGlass: 2})

	if err := alice.BreakGlass([]string{"carol"}, 3600); err != nil {
		t.Fatalf("BreakGlass opened the gate but returned error: %v", err)
	}
	waitMatch[client.EvActionRequest](t, bob, func(e client.EvActionRequest) bool {
		return e.Action == protocol.ActionBreakGlass
	}, 5*time.Second)
	// Without approval the war room must not be created.
	drainNoBreakGlass(t, alice, 500*time.Millisecond)
}
