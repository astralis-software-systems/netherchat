package record

import "encoding/json"

// This file holds the structured Body of an "artifact" record entry (NC-W1): an
// agent-produced artifact that a named human approved under the Two-Person Rule.
//
// An artifact entry is an ordinary chain Entry (Kind == KindArtifact) whose Body is
// the JSON below — exactly as a decision/action/note entry uses Body for text. It is
// covered by the entry's Ed25519 signature like any other Body, so the approval is
// tamper-evident and offline-verifiable. The artifact CONTENT never appears here:
// ArtifactHash (hex SHA-256) is its only representation.

// ArtifactMeta is the structured Body of an artifact record entry.
//
// The first six fields are the original (v1.8.0) shape. The last three are the
// additive, omitempty extensions that make two-person approval offline-provable
// (GAP-1/GAP-2): they let an offline verifier reconstruct the artifact-approval
// preimage (protocol.ArtifactApprovalSigningBytes binds proposal_id + artifact_hash
// + approver_fpr + nonce) and enforce the second law (approver ≠ proposer). They
// are part of the entry's SIGNED Body, so they are tamper-evident; an old record
// simply lacks them and verifies byte-for-byte as before. ApproverFpr remains the
// writer's claimed approver but is NOT authoritative on its own — authoritative,
// offline-verified approvers come from SealedRecord.ArtifactApprovals (see Verify).
type ArtifactMeta struct {
	Source       string `json:"source"`        // agent/tool label, e.g. "requirements-agent"
	ArtifactRef  string `json:"artifact_ref"`  // title or reference id of the artifact
	ArtifactHash string `json:"artifact_hash"` // hex SHA-256 of the artifact content — NEVER the content
	ApproverFpr  string `json:"approver_fpr"`  // Ed25519 fingerprint of the writer's claimed approver (NOT authoritative alone)
	ProposedAt   string `json:"proposed_at"`   // RFC3339, when the agent submitted the proposal
	ApprovedAt   string `json:"approved_at"`   // RFC3339, when the human approved

	// Additive (omitempty): the proposal correlator, nonce, and proposer needed to
	// verify the record-level ArtifactApprovals proofs offline. Absent on old records.
	ProposalID  string `json:"proposal_id,omitempty"`  // correlates the approval proofs; bound into the approval preimage
	Nonce       string `json:"nonce,omitempty"`        // proposal nonce; bound into the approval preimage
	ProposerFpr string `json:"proposer_fpr,omitempty"` // the proposer/agent; excluded from the approver set (the second law)
}

// MarshalArtifactBody renders an ArtifactMeta as the entry Body (compact JSON). The
// result is what gets signed and chained as the entry's Body.
func MarshalArtifactBody(m ArtifactMeta) (string, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ParseArtifactBody decodes an artifact entry's Body back into its metadata. It is
// used by the report and minutes renderers; a non-artifact Body returns an error.
func ParseArtifactBody(body string) (ArtifactMeta, error) {
	var m ArtifactMeta
	err := json.Unmarshal([]byte(body), &m)
	return m, err
}

// ArtifactOf returns the parsed artifact metadata for an entry, or ok=false if the
// entry is not an artifact entry (or its Body does not parse).
func ArtifactOf(e Entry) (ArtifactMeta, bool) {
	if e.Kind != KindArtifact {
		return ArtifactMeta{}, false
	}
	m, err := ParseArtifactBody(e.Body)
	if err != nil {
		return ArtifactMeta{}, false
	}
	return m, true
}

// shortHash returns the first n characters of a hex hash, or the whole string when
// it is already short. Used to show an artifact/content hash as a reference.
func shortHash(h string, n int) string {
	if len(h) <= n {
		return h
	}
	return h[:n]
}
