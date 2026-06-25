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

// ArtifactApprovalSigningBytesV2 returns the canonical bytes covered by a ROLE-TYPED
// artifact approval: a named human attesting "I approve this exact agent-produced
// artifact, acting as <role>" (e.g. the QA reviewer, the system owner). It extends the
// v1 preimage — same proposal/artifact/approver/nonce binding — with a single declared
// role field, under a distinct domain tag, so the role is part of what is signed and
// cannot be altered after the fact: relabeling, adding, or stripping the role yields a
// different preimage and the signature no longer verifies.
//
// Role is opaque and consumer-defined (like the seal Endorsement Meaning and the typed
// Entry Schema); the library performs NO normalization on it — no case-folding, no
// trimming — because it is inside the signed bytes. A non-empty role is what
// distinguishes a v2 approval from a v1 one; an empty role is not a valid v2 approval
// (use ArtifactApprovalSigningBytes for the roleless v1 form).
//
// Layout (artifact-approval v2):
//
//	field("netherchat/artifact-approval/v2")
//	  || field(proposal_id) || field(artifact_hash) || field(approver_fpr) || field(nonce)
//	  || field(role)
//
// where field(b) = uint64-big-endian(len(b)) || b. The four v1 fields are emitted
// verbatim and in the same order; field(role) is appended last.
func ArtifactApprovalSigningBytesV2(proposalID, artifactHash, approverFpr, nonce, role string) []byte {
	var buf bytes.Buffer
	writeField(&buf, []byte("netherchat/artifact-approval/v2")) // domain-separation tag
	writeField(&buf, []byte(proposalID))
	writeField(&buf, []byte(artifactHash))
	writeField(&buf, []byte(approverFpr))
	writeField(&buf, []byte(nonce))
	writeField(&buf, []byte(role))
	return buf.Bytes()
}
