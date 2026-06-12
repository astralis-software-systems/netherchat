package protocol

import "bytes"

// ArtifactApprovalSigningBytes returns the canonical bytes an artifact approval
// covers (NC-W1): a named human attesting "I approve this exact agent-produced
// artifact." The preimage is domain-separated and binds, in order, the proposal id,
// the artifact's content hash, the approver's fingerprint, and the proposal nonce.
// That binding makes the approval un-replayable: an approval of artifact hash H1
// cannot be reused to endorse a different artifact H2 (different artifact_hash), nor
// attributed to a different approver (their fingerprint is in the preimage), nor
// replayed against a different proposal instance (the nonce differs).
//
// Layout (artifact-approval v1):
//
//	field("netherchat/artifact-approval/v1")
//	  || field(proposal_id) || field(artifact_hash) || field(approver_fpr) || field(nonce)
//
// where field(b) = uint64-big-endian(len(b)) || b. Each field is length-prefixed so
// the encoding is injective. Both the approver (signer) and every verifier derive
// these exact bytes, so a signature always means the same thing everywhere.
func ArtifactApprovalSigningBytes(proposalID, artifactHash, approverFpr, nonce string) []byte {
	var buf bytes.Buffer
	writeField(&buf, []byte("netherchat/artifact-approval/v1")) // domain-separation tag
	writeField(&buf, []byte(proposalID))
	writeField(&buf, []byte(artifactHash))
	writeField(&buf, []byte(approverFpr))
	writeField(&buf, []byte(nonce))
	return buf.Bytes()
}
