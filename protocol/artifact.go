package protocol

// This file holds the Agent-Decision Attestation payloads (NC-W1). See protocol.go
// for the opcode set and artifact_signing.go for the approval preimage.
//
// The flow mirrors the Two-Person Rule (§1.3): a proposer broadcasts an
// ArtifactProposal naming an agent-produced artifact (by reference and content
// HASH — never the content itself); named humans broadcast a signed
// ArtifactApproval; once Quorum distinct human approvers (the proposer is NEVER one
// of them) have endorsed it, the artifact becomes a signed "artifact" record entry.

// ActionArtifact is the [action.artifact] policy key (the Two-Person Rule quorum for
// approving an agent-produced artifact). Its quorum defaults to 1 (a single human
// approver) when unset.
const ActionArtifact = "artifact"

// ArtifactProposalBody is the END-TO-END-ENCRYPTED plaintext of an
// OpArtifactProposal Message (NC-W1): a proposer submits an agent-produced artifact
// for human approval. It carries ONLY metadata — the artifact's reference and the
// hex SHA-256 of its content (ArtifactHash). The artifact content itself NEVER
// appears here, on the relay, or in any log: the hash is its only representation.
//
// ProposerFpr is the proposer's fingerprint (verified against the signed Message
// sender) and is recorded so it can be excluded from approving its own proposal.
// Nonce binds every approval to this exact proposal instance.
type ArtifactProposalBody struct {
	ProposalID   string `json:"proposal_id"`   // random 16-char hex correlating approvals/rejections
	Source       string `json:"source"`        // agent/tool label, e.g. "requirements-agent"
	ArtifactRef  string `json:"artifact_ref"`  // title or reference id of the artifact
	ArtifactHash string `json:"artifact_hash"` // hex SHA-256 of the artifact content — NEVER the content
	Summary      string `json:"summary,omitempty"`
	ProposerFpr  string `json:"proposer_fpr"` // must equal the signing sender; can never approve (second law)
	Quorum       int    `json:"quorum"`       // distinct human approvers required (from [action.artifact])
	ProposedAt   string `json:"proposed_at"`  // RFC3339, when the agent submitted the proposal
	ExpiresUnix  int64  `json:"expires_unix"` // discarded after this (≈300s after issue)
	Nonce        string `json:"nonce"`        // random hex bound into every approval; prevents replay
}

// ArtifactApprovalBody is the END-TO-END-ENCRYPTED plaintext of an
// OpArtifactApproval Message (NC-W1): a named human co-signs a pending proposal. Sig
// is the Ed25519 signature over ArtifactApprovalSigningBytes(ProposalID,
// ArtifactHash, ApproverFpr, Nonce) — domain-separated and bound to the proposal id,
// the exact artifact (via its hash), the approver, and the proposal nonce, so an
// approval of one artifact can never be replayed to endorse a different one.
//
// ATTESTATION IS THE APPROVER'S CREDENTIAL, CARRIED VERBATIM. It is the standalone
// identity artifact's marshalled bytes — the same bytes a file on disk holds and the
// same bytes a record entry carries — so one parser and one verifier serve every
// arrival path and no second shape of the artifact enters the tree. It is []byte for
// the same reason IdentityKey and KXKey are: encoding/json base64s it, and the relay
// fans it out without looking inside. This package neither parses nor verifies it;
// a reader supplies the issuer key and the evaluation time, and this frame supplies
// only the statement an issuer signed.
type ArtifactApprovalBody struct {
	ProposalID   string `json:"proposal_id"`
	ArtifactHash string `json:"artifact_hash"` // the approver independently verifies this matches the proposal
	ApproverFpr  string `json:"approver_fpr"`  // must equal the signing sender's fingerprint
	Sig          []byte `json:"sig"`

	// Attestation is the approver's identity attestation as the issuer wrote it,
	// or nil when the approver carries none. omitempty is what keeps this change
	// additive: an approver carrying none marshals to exactly the bytes this
	// struct marshalled to before the field existed; an older peer decoding a
	// frame that has it ignores an unknown key (Envelope.Decode is a plain
	// json.Unmarshal, and no wire struct here uses DisallowUnknownFields); and a
	// newer peer decoding an older frame gets a nil slice, which means "the
	// sender carried none" and is not an error.
	Attestation []byte `json:"attestation,omitempty"`

	// Role is which of the roles Attestation names the approver signed as, or
	// empty for a roleless approval. It is the same content discriminator the
	// sealed record's ApprovalProof.Role is: EMPTY means Sig covers
	// ArtifactApprovalSigningBytes (v1); NON-EMPTY means it covers
	// ArtifactApprovalSigningBytesV2, which binds the role, so relabelling,
	// adding or stripping a role yields a different preimage and the signature
	// stops verifying. Both ends dispatch on this field and on nothing else.
	//
	// The vocabulary is not this package's and never becomes one: a role is a
	// string an issuer signed into the approver's own attestation, matched
	// byte-for-byte and never normalized. A role that arrives without an
	// attestation naming it is carried, surfaced, and left for a reader to judge
	// — this layer states what was signed, not what it is enough for.
	Role string `json:"role,omitempty"`
}

// ArtifactRejectionBody is the END-TO-END-ENCRYPTED plaintext of an
// OpArtifactRejection Message (NC-W1): any present member can reject a pending
// proposal. The rejecter is the signed Message's sender; Reason is an optional note.
type ArtifactRejectionBody struct {
	ProposalID  string `json:"proposal_id"`
	RejecterFpr string `json:"rejecter_fpr"`
	Reason      string `json:"reason,omitempty"`
}
