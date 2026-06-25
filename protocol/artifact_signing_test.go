package protocol

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestArtifactApprovalSigningBytesVector pins the exact byte layout of
// ArtifactApprovalSigningBytes (NC-W1): the artifact-approval substrate of the
// Two-Person Rule, and the cryptographic foundation the role-typed-quorum work
// builds on. It is the frozen tripwire every other signing preimage already has
// (record v1/v2, seal v1/v2, action-approval v1/v2) — this one was the lone gap.
// Because the signer and every verifier call this same function, a field reorder or
// a change to the length-prefixing would pass all end-to-end tests yet silently
// break any independent verifier. If this layout ever changes, artifact approvals
// stop verifying across versions/implementations and this test fails — by design.
func TestArtifactApprovalSigningBytesVector(t *testing.T) {
	got := hex.EncodeToString(ArtifactApprovalSigningBytes("a3f9", "deadbeef", "SHA256:abc", "nonce0"))

	const want = "000000000000001f" + "6e6574686572636861742f61727469666163742d617070726f76616c2f7631" + // field("netherchat/artifact-approval/v1")
		"0000000000000004" + "61336639" + // field("a3f9")
		"0000000000000008" + "6465616462656566" + // field("deadbeef")
		"000000000000000a" + "5348413235363a616263" + // field("SHA256:abc")
		"0000000000000006" + "6e6f6e636530" // field("nonce0")

	if got != want {
		t.Fatalf("ArtifactApprovalSigningBytes layout changed (breaking — bump the v1 tag):\n got %s\nwant %s", got, want)
	}
}

// TestArtifactApprovalSigningBytesVectorRederived re-derives the expected preimage
// from first principles — the documented field order and the field(b) =
// uint64-big-endian(len(b)) || b construction — WITHOUT calling the production
// function, then asserts the two agree. Like the v2 vectors, refField is an
// independent re-implementation of writeField, so this is a genuine cross-check, not
// a tautology: it proves the function does what the spec SAYS, so a field reorder is
// caught even if the frozen constant above were ever edited to match a drifted
// function. (refField/cat are defined in v2_signing_test.go, same package.)
func TestArtifactApprovalSigningBytesVectorRederived(t *testing.T) {
	got := ArtifactApprovalSigningBytes("a3f9", "deadbeef", "SHA256:abc", "nonce0")

	want := cat(
		refField("netherchat/artifact-approval/v1"), // domain-separation tag
		refField("a3f9"),       // proposal_id
		refField("deadbeef"),   // artifact_hash
		refField("SHA256:abc"), // approver_fpr
		refField("nonce0"),     // nonce
	)
	if !bytes.Equal(got, want) {
		t.Fatalf("ArtifactApprovalSigningBytes disagrees with its documented field order:\n got %x\nwant %x", got, want)
	}
}

// TestArtifactApprovalSigningBytesBinding proves each bound field changes the
// preimage: flipping the proposal id, artifact hash, approver, or nonce yields
// distinct signing bytes, so an approval cannot be replayed across any of them
// (mirrors TestActionApprovalSigningBytesBinding).
func TestArtifactApprovalSigningBytesBinding(t *testing.T) {
	base := ArtifactApprovalSigningBytes("p1", "hashA", "fprX", "n1")
	variants := map[string][]byte{
		"proposal_id":   ArtifactApprovalSigningBytes("p2", "hashA", "fprX", "n1"),
		"artifact_hash": ArtifactApprovalSigningBytes("p1", "hashB", "fprX", "n1"),
		"approver":      ArtifactApprovalSigningBytes("p1", "hashA", "fprY", "n1"),
		"nonce":         ArtifactApprovalSigningBytes("p1", "hashA", "fprX", "n2"),
	}
	for field, v := range variants {
		if hex.EncodeToString(v) == hex.EncodeToString(base) {
			t.Errorf("changing %s did not change the signing bytes", field)
		}
	}
}
