package client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// TestTrackedActionEndorsementCount proves the endorsement count counts the
// requester as endorser #1 plus distinct approvers, so quorum=2 is reached by one
// independent approver (the demo's "1/2" pending → "2/2 executes").
func TestTrackedActionEndorsementCount(t *testing.T) {
	ta := &trackedAction{
		req:       protocol.ActionRequestBody{RequesterFpr: "SHA256:alice", QuorumNeeded: 2},
		approvers: map[string]bool{},
	}
	if got := ta.endorsements(); got != 1 {
		t.Fatalf("with no approvers, endorsements = %d, want 1 (the requester)", got)
	}
	if !ta.addApprover("SHA256:bob") {
		t.Fatal("first distinct approver should be counted")
	}
	if got := ta.endorsements(); got != 2 {
		t.Fatalf("after bob, endorsements = %d, want 2", got)
	}
}

// TestTrackedActionInitiatorExcluded proves the requester's own fingerprint never
// counts as an approver — a single actor cannot satisfy a quorum alone.
func TestTrackedActionInitiatorExcluded(t *testing.T) {
	ta := &trackedAction{
		req:       protocol.ActionRequestBody{RequesterFpr: "SHA256:alice", QuorumNeeded: 2},
		approvers: map[string]bool{},
	}
	if ta.addApprover("SHA256:alice") {
		t.Fatal("the requester must not be counted as an approver")
	}
	if got := ta.endorsements(); got != 1 {
		t.Fatalf("endorsements = %d, want 1 (requester only)", got)
	}
}

// TestTrackedActionDeduplicates proves a duplicate approval from the same
// fingerprint does not increment the count.
func TestTrackedActionDeduplicates(t *testing.T) {
	ta := &trackedAction{
		req:       protocol.ActionRequestBody{RequesterFpr: "SHA256:alice", QuorumNeeded: 3},
		approvers: map[string]bool{},
	}
	if !ta.addApprover("SHA256:bob") {
		t.Fatal("first bob approval should count")
	}
	if ta.addApprover("SHA256:bob") {
		t.Fatal("duplicate bob approval must NOT count again")
	}
	if got := ta.endorsements(); got != 2 {
		t.Fatalf("endorsements = %d, want 2 (requester + one distinct bob)", got)
	}
}

// TestTrackedActionResolvedRejects proves a resolved request accepts no further
// approvals (late approvals are silently discarded).
func TestTrackedActionResolvedRejects(t *testing.T) {
	ta := &trackedAction{
		req:       protocol.ActionRequestBody{RequesterFpr: "SHA256:alice", QuorumNeeded: 2},
		approvers: map[string]bool{},
		resolved:  true,
	}
	if ta.addApprover("SHA256:bob") {
		t.Fatal("a resolved request must not count new approvers")
	}
}

// TestActionParamsHashDeterministic proves the params hash is the SHA-256 of the
// exact params string and changes when the params change — the binding that makes
// an approval of "room=ops" un-replayable against "room=prod".
func TestActionParamsHashDeterministic(t *testing.T) {
	a := actionParamsHash("room=ops, reason=manual")
	if a != actionParamsHash("room=ops, reason=manual") {
		t.Fatal("params hash must be deterministic")
	}
	if a == actionParamsHash("room=prod, reason=manual") {
		t.Fatal("different params must yield a different hash")
	}
	// It is exactly the hex SHA-256 of the params bytes (what an approver recomputes
	// to verify the hash matches the displayed params).
	sum := sha256.Sum256([]byte("room=ops, reason=manual"))
	if a != hex.EncodeToString(sum[:]) {
		t.Fatalf("actionParamsHash = %s, want hex(sha256(params)) = %s", a, hex.EncodeToString(sum[:]))
	}
}

// TestResolveActionIDLocked proves a unique id prefix resolves, while an ambiguous
// or unknown prefix does not.
func TestResolveActionIDLocked(t *testing.T) {
	c := &Client{actions: map[string]*trackedAction{
		"a3f9000000000000": {req: protocol.ActionRequestBody{RequestID: "a3f9000000000000"}},
		"b1c2000000000000": {req: protocol.ActionRequestBody{RequestID: "b1c2000000000000"}},
		"a3ff000000000000": {req: protocol.ActionRequestBody{RequestID: "a3ff000000000000"}},
	}}

	if id, ok := c.resolveActionIDLocked("b1c2"); !ok || id != "b1c2000000000000" {
		t.Fatalf("unique prefix b1c2 => (%q, %v)", id, ok)
	}
	if _, ok := c.resolveActionIDLocked("a3f"); ok {
		t.Fatal("ambiguous prefix a3f should not resolve")
	}
	if _, ok := c.resolveActionIDLocked("zzzz"); ok {
		t.Fatal("unknown prefix should not resolve")
	}
	// An exact id always resolves even when it is a prefix of another.
	if id, ok := c.resolveActionIDLocked("a3f9000000000000"); !ok || id != "a3f9000000000000" {
		t.Fatalf("exact id => (%q, %v)", id, ok)
	}
}

// TestOnActionApprovalParamsHashMismatch proves an approval whose params_hash does
// not match the request is rejected and not counted — an approval of one action
// cannot be redirected to a different one.
func TestOnActionApprovalParamsHashMismatch(t *testing.T) {
	approver, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{
		ctx:    context.Background(),
		events: make(chan Event, 8),
		actions: map[string]*trackedAction{
			"req1": {
				req: protocol.ActionRequestBody{
					RequestID: "req1", ParamsHash: "correcthash",
					RequesterFpr: "SHA256:alice", QuorumNeeded: 2, Nonce: "n1",
				},
				approvers: map[string]bool{},
			},
		},
	}

	c.onActionApproval("bob", approver.SignPub, protocol.ActionApprovalBody{
		RequestID: "req1", ParamsHash: "WRONGHASH",
		ApproverFpr: crypto.Fingerprint(approver.SignPub), Sig: []byte("whatever"),
	})

	if n := len(c.actions["req1"].approvers); n != 0 {
		t.Fatalf("a params_hash-mismatched approval was counted (%d approvers)", n)
	}
}

// TestOnActionApprovalBadSignatureRejected proves an approval with a correct
// params_hash but an invalid signature is rejected and not counted.
func TestOnActionApprovalBadSignatureRejected(t *testing.T) {
	approver, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{
		ctx:    context.Background(),
		events: make(chan Event, 8),
		actions: map[string]*trackedAction{
			"req1": {
				req: protocol.ActionRequestBody{
					RequestID: "req1", ParamsHash: "correcthash",
					RequesterFpr: "SHA256:alice", QuorumNeeded: 2, Nonce: "n1",
				},
				approvers: map[string]bool{},
			},
		},
	}

	c.onActionApproval("bob", approver.SignPub, protocol.ActionApprovalBody{
		RequestID: "req1", ParamsHash: "correcthash",
		ApproverFpr: crypto.Fingerprint(approver.SignPub), Sig: []byte("not-a-valid-signature"),
	})

	if n := len(c.actions["req1"].approvers); n != 0 {
		t.Fatalf("an approval with an invalid signature was counted (%d approvers)", n)
	}
}
