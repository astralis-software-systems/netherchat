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

// twoMembers stands up a relay and connects alice + bob to room ops, returning
// both with the room key established and each aware of the other.
func twoMembers(t *testing.T) (*httptest.Server, *client.Client, *client.Client) {
	t.Helper()
	ts := httptest.NewServer(server.Handler(config.Default(), quietLogger()))
	t.Cleanup(ts.Close)

	alice := connect(t, ts.URL, "ops", "alice", "")
	waitMatch[client.EvKeyReady](t, alice, nil, 5*time.Second)
	bob := connect(t, ts.URL, "ops", "bob", "")
	waitMatch[client.EvKeyReady](t, bob, nil, 5*time.Second)
	// alice must observe bob (and his keys) before she can attribute his approval.
	waitMatch[client.EvMemberJoined](t, alice, func(e client.EvMemberJoined) bool { return e.Name == "bob" }, 5*time.Second)
	return ts, alice, bob
}

// drainNoExecute fails the test if an EvActionExecuted arrives on c within d.
func drainNoExecute(t *testing.T, c *client.Client, d time.Duration) {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case ev := <-c.Events():
			if _, ok := ev.(client.EvActionExecuted); ok {
				t.Fatal("action executed but quorum was not met")
			}
		case <-deadline:
			return
		case <-c.Done():
			return
		}
	}
}

// TestTwoPersonRuleScuttleExecutes is the headline acceptance path: with quorum 2,
// alice (the requester, endorser #1) cannot scuttle alone; bob's single independent
// approval supplies the second endorsement, the gate opens, and the scuttle fires —
// writing a co-signed receipt. The second Ed25519 signature is REQUIRED.
func TestTwoPersonRuleScuttleExecutes(t *testing.T) {
	_, alice, bob := twoMembers(t)

	// alice opens the gated request and performs the scuttle when quorum is reached.
	id, err := alice.RequestAction("scuttle", "room=ops, reason=manual", 2, func() { alice.ScuttleNow() })
	if err != nil {
		t.Fatalf("request action: %v", err)
	}

	// bob receives the request and approves it.
	req := waitMatch[client.EvActionRequest](t, bob, nil, 5*time.Second)
	if req.RequestID != id || req.Action != "scuttle" || req.QuorumNeeded != 2 {
		t.Fatalf("bob saw request %+v", req)
	}
	if err := bob.ApproveAction(id); err != nil {
		t.Fatalf("bob approve: %v", err)
	}

	// alice reaches quorum (2/2) and executes.
	ex := waitMatch[client.EvActionExecuted](t, alice, nil, 5*time.Second)
	if ex.RequestID != id || ex.Quorum != 2 || !ex.Self {
		t.Fatalf("alice executed = %+v (want id=%s quorum=2 self=true)", ex, id)
	}

	// The scuttle actually fired: a valid receipt is produced…
	ev := waitMatch[client.EvScuttleReceipt](t, alice, nil, 8*time.Second)
	if res, verr := attest.VerifyReceipt(ev.Receipt); verr != nil || !res.Valid {
		t.Fatalf("scuttle receipt invalid: %v / %+v", verr, res)
	}
	// …and the burn propagated to the room (bob sees the scuttle control fire).
	if sc := waitScuttle(t, bob); sc.Reason != "manual" {
		t.Fatalf("bob saw scuttle reason %q, want manual", sc.Reason)
	}
}

// TestTwoPersonRuleSingleActorBlocked proves the security property: with quorum 2
// and NO approver, the action does not execute. A single actor cannot proceed.
func TestTwoPersonRuleSingleActorBlocked(t *testing.T) {
	_, alice, _ := twoMembers(t)
	before := alice.Epoch()

	executed := false
	if _, err := alice.RequestAction("scuttle", "room=ops, reason=manual", 2, func() { executed = true }); err != nil {
		t.Fatalf("request action: %v", err)
	}
	// No one approves. Give it a moment; the action must NOT fire.
	drainNoExecute(t, alice, 600*time.Millisecond)
	if executed {
		t.Fatal("action executed with only the initiator — the two-person rule was bypassed")
	}
	if alice.Epoch() != before {
		t.Fatal("the room key ratcheted — the scuttle ran without quorum")
	}
}

// TestTwoPersonRuleInitiatorCannotApprove proves the initiator cannot approve their
// own request to reach quorum.
func TestTwoPersonRuleInitiatorCannotApprove(t *testing.T) {
	_, alice, _ := twoMembers(t)
	id, err := alice.RequestAction("scuttle", "room=ops, reason=manual", 2, func() {})
	if err != nil {
		t.Fatalf("request action: %v", err)
	}
	if err := alice.ApproveAction(id); err == nil {
		t.Fatal("alice must NOT be able to approve her own request")
	}
}

// TestTwoPersonRuleDuplicateApproval proves a second approval from the same member
// does not increment the count, so quorum 3 is not reached by one repeated approver.
func TestTwoPersonRuleDuplicateApproval(t *testing.T) {
	_, alice, bob := twoMembers(t)
	executed := false
	id, err := alice.RequestAction("scuttle", "room=ops, reason=manual", 3, func() { executed = true })
	if err != nil {
		t.Fatalf("request action: %v", err)
	}
	waitMatch[client.EvActionRequest](t, bob, nil, 5*time.Second)
	if err := bob.ApproveAction(id); err != nil {
		t.Fatalf("bob approve: %v", err)
	}
	// alice counts bob's approval → 2/3, not enough.
	ap := waitMatch[client.EvActionApproval](t, alice, nil, 5*time.Second)
	if ap.Count != 2 {
		t.Fatalf("after bob, count = %d, want 2 (alice + bob)", ap.Count)
	}
	// A duplicate from bob is refused locally and changes nothing.
	if err := bob.ApproveAction(id); err == nil {
		t.Fatal("bob's duplicate approval should be refused")
	}
	drainNoExecute(t, alice, 500*time.Millisecond)
	if executed {
		t.Fatal("quorum 3 was satisfied by a single repeated approver")
	}
}

// TestTwoPersonRuleVeto proves any member can cancel a pending request immediately,
// and the action never fires.
func TestTwoPersonRuleVeto(t *testing.T) {
	_, alice, bob := twoMembers(t)
	executed := false
	id, err := alice.RequestAction("scuttle", "room=ops, reason=manual", 2, func() { executed = true })
	if err != nil {
		t.Fatalf("request action: %v", err)
	}
	waitMatch[client.EvActionRequest](t, bob, nil, 5*time.Second)
	if err := bob.VetoAction(id, "wrong room"); err != nil {
		t.Fatalf("bob veto: %v", err)
	}
	v := waitMatch[client.EvActionVetoed](t, alice, nil, 5*time.Second)
	if v.RequestID != id || v.VetoerName != "bob" || v.Reason != "wrong room" {
		t.Fatalf("alice saw veto %+v", v)
	}
	drainNoExecute(t, alice, 500*time.Millisecond)
	if executed {
		t.Fatal("a vetoed action must not execute")
	}
}

// TestTwoPersonRuleRunbookGate exercises the agent's runbook gate at the client
// level (§1.3, §7): a member opens a quorum-gated "runbook" request — exactly what
// `netherchat agent` does when it receives an /exec under [action.runbook] quorum>1
// — and the command callback runs ONLY after a second member co-signs. quorum 2
// blocks the solo actor; the second approval lets it run.
func TestTwoPersonRuleRunbookGate(t *testing.T) {
	_, agent, bob := twoMembers(t) // "agent" stands in for the netherchat agent
	ran := make(chan struct{}, 1)

	id, err := agent.RequestAction("runbook", "cmd=drain, requested_by=carol", 2, func() { ran <- struct{}{} })
	if err != nil {
		t.Fatalf("request action: %v", err)
	}
	waitMatch[client.EvActionRequest](t, bob, func(e client.EvActionRequest) bool { return e.Action == "runbook" }, 5*time.Second)

	// With only the agent's request (endorser #1), the command must NOT run.
	select {
	case <-ran:
		t.Fatal("runbook ran before a second approval — the gate was bypassed")
	case <-time.After(400 * time.Millisecond):
	}

	// A second authorized member co-signs → the agent runs the command.
	if err := bob.ApproveAction(id); err != nil {
		t.Fatalf("bob approve: %v", err)
	}
	waitMatch[client.EvActionExecuted](t, agent, func(e client.EvActionExecuted) bool { return e.Action == "runbook" }, 5*time.Second)
	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("runbook did not run after quorum was reached")
	}
}

// TestTwoPersonRuleQuorumThree proves quorum 3 requires two independent approvers
// (requester + 2): one approver is not enough, the second tips it over.
func TestTwoPersonRuleQuorumThree(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLogger()))
	defer ts.Close()
	alice := connect(t, ts.URL, "ops", "alice", "")
	waitMatch[client.EvKeyReady](t, alice, nil, 5*time.Second)
	bob := connect(t, ts.URL, "ops", "bob", "")
	waitMatch[client.EvKeyReady](t, bob, nil, 5*time.Second)
	carol := connect(t, ts.URL, "ops", "carol", "")
	waitMatch[client.EvKeyReady](t, carol, nil, 5*time.Second)
	waitMatch[client.EvMemberJoined](t, alice, func(e client.EvMemberJoined) bool { return e.Name == "carol" }, 5*time.Second)

	executed := false
	id, err := alice.RequestAction("break_glass", "invite=x, ttl=4h", 3, func() { executed = true })
	if err != nil {
		t.Fatalf("request action: %v", err)
	}
	waitMatch[client.EvActionRequest](t, bob, nil, 5*time.Second)
	if err := bob.ApproveAction(id); err != nil {
		t.Fatalf("bob approve: %v", err)
	}
	// 2/3 — not yet.
	waitMatch[client.EvActionApproval](t, alice, func(e client.EvActionApproval) bool { return e.Count == 2 }, 5*time.Second)
	drainNoExecute(t, alice, 400*time.Millisecond)
	if executed {
		t.Fatal("quorum 3 reached with only one approver")
	}
	// carol tips it to 3/3.
	if err := carol.ApproveAction(id); err != nil {
		t.Fatalf("carol approve: %v", err)
	}
	waitMatch[client.EvActionExecuted](t, alice, nil, 5*time.Second)
	if !executed {
		t.Fatal("quorum 3 with two approvers should execute")
	}
}
