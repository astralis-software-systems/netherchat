package protocol

import (
	"encoding/hex"
	"testing"
)

// TestActionApprovalSigningBytesVector pins the exact byte layout of
// ActionApprovalSigningBytes for a fixed input (the Two-Person Rule, §1.3). If the
// layout ever changes, action approvals stop verifying across versions and this
// test fails — a deliberate tripwire.
func TestActionApprovalSigningBytesVector(t *testing.T) {
	got := hex.EncodeToString(ActionApprovalSigningBytes("a3f9", "deadbeef", "SHA256:abc", "nonce0"))

	const want = "000000000000001d6e6574686572636861742f616374696f6e2d617070726f76616c2f7631" + // field("netherchat/action-approval/v1")
		"0000000000000004" + "61336639" + // field("a3f9")
		"0000000000000008" + "6465616462656566" + // field("deadbeef")
		"000000000000000a" + "5348413235363a616263" + // field("SHA256:abc")
		"0000000000000006" + "6e6f6e636530" // field("nonce0")

	if got != want {
		t.Fatalf("ActionApprovalSigningBytes layout changed:\n got %s\nwant %s", got, want)
	}
}

// TestActionApprovalSigningBytesBinding proves each bound field changes the
// preimage: flipping the request id, params hash, approver, or nonce yields
// distinct signing bytes, so an approval cannot be replayed across any of them.
func TestActionApprovalSigningBytesBinding(t *testing.T) {
	base := ActionApprovalSigningBytes("req1", "hashA", "fprX", "n1")
	variants := map[string][]byte{
		"request_id": ActionApprovalSigningBytes("req2", "hashA", "fprX", "n1"),
		"params":     ActionApprovalSigningBytes("req1", "hashB", "fprX", "n1"),
		"approver":   ActionApprovalSigningBytes("req1", "hashA", "fprY", "n1"),
		"nonce":      ActionApprovalSigningBytes("req1", "hashA", "fprX", "n2"),
	}
	for field, v := range variants {
		if hex.EncodeToString(v) == hex.EncodeToString(base) {
			t.Errorf("changing %s did not change the signing bytes", field)
		}
	}
}
