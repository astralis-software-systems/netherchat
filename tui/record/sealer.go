package record

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
)

// VerifyBytes parses a sealed record from its on-disk JSON and verifies it in a
// single call — the network-free entry point used by `netherchat verify` and by
// any external consumer of this library. The returned VerifyResult reports VALID
// (Valid==true) or TAMPERED (Valid==false with a specific Reason); err is
// non-nil only for input too malformed to parse, or a structurally invalid field
// (e.g. a non-hex head_hash) that prevents verification entirely.
func VerifyBytes(b []byte) (*VerifyResult, error) {
	rec, err := Parse(b)
	if err != nil {
		return nil, err
	}
	return Verify(rec)
}

// headOf returns the chain head for a finished slice of entries: the hash of the
// last entry's canonical bytes, or 32 zero bytes for an empty slice. It mirrors
// Chain.Head so an offline Sealer signs exactly what a live /seal would.
func headOf(entries []Entry) []byte {
	if len(entries) == 0 {
		return zeroHash()
	}
	h := entries[len(entries)-1].Hash()
	return h[:]
}

// Sealer assembles a SealedRecord offline by collecting seal co-signatures over a
// finished entry chain, with no relay and no network. It is the public,
// importable core of /seal: a participant (or an external program) signs the
// chain head — a domain-separated, room-bound preimage (protocol.SealSigningBytes)
// — and the collected signatures are finalized into a self-verifying record.
//
// Typical use:
//
//	sealer := record.NewSealer("ops", author.ID, chain.Entries())
//	if err := sealer.Sign(author); err != nil { /* ... */ } // first co-signer
//	// ... collect more co-signatures from other participants via AddCosignature ...
//	rec, err := sealer.Finalize()
//
// A Sealer is not safe for concurrent use.
type Sealer struct {
	room         string
	sealedBy     string
	entries      []Entry
	head         []byte
	sigs         map[string][]byte
	keys         map[string][]byte
	endorsements map[string]Endorsement     // signers who declared a meaning (item 2)
	approvals    map[string][]ApprovalProof // artifact two-person proofs, keyed by proposal id (GAP-1/GAP-2)
}

// NewSealer starts a seal over a finished chain. entries is the exact entry slice
// to seal (typically Chain.Entries()); sealedBy is recorded as the participant
// who initiated the seal (conventionally the first co-signer's fingerprint). The
// head to be co-signed is computed from entries, so it matches what Verify
// recomputes.
func NewSealer(room, sealedBy string, entries []Entry) *Sealer {
	snapshot := make([]Entry, len(entries))
	copy(snapshot, entries)
	return &Sealer{
		room:     room,
		sealedBy: sealedBy,
		entries:  snapshot,
		head:     headOf(snapshot),
		sigs:     map[string][]byte{},
		keys:     map[string][]byte{},
	}
}

// Head returns a copy of the chain head being sealed (32 bytes): the value every
// co-signer signs, via SigningBytes.
func (s *Sealer) Head() []byte { return append([]byte(nil), s.head...) }

// SigningBytes returns the exact preimage each co-signer must sign:
// protocol.SealSigningBytes(room, head). Exposed so a caller holding only a raw
// signing function (e.g. an ssh-agent identity) can produce a co-signature
// without importing the protocol package.
func (s *Sealer) SigningBytes() []byte { return protocol.SealSigningBytes(s.room, s.head) }

// AddCosignature records a bare (v1) co-signature from a participant's public key
// after verifying it against the seal preimage. The signer is identified by the
// fingerprint of pub (the same key recorded in the finalized record), so a caller
// cannot misattribute a signature. It returns the signer fingerprint.
func (s *Sealer) AddCosignature(pub ed25519.PublicKey, sig []byte) (string, error) {
	return s.addVerified(pub, sig, s.SigningBytes(), nil)
}

// EndorsementSigningBytes returns the v2 seal preimage a co-signer must sign to
// attach a declared meaning (item 2): protocol.SealSigningBytesV2(room, meaning,
// signerName, signedAt, head). signedAt should be an RFC3339 UTC timestamp.
func (s *Sealer) EndorsementSigningBytes(meaning, signerName, signedAt string) []byte {
	return protocol.SealSigningBytesV2(s.room, meaning, signerName, signedAt, s.head)
}

// AddEndorsement records a meaning-bearing (v2) co-signature: the signer declared
// why they signed (meaning), under their printed name, at signedAt (RFC3339 UTC).
// The signature is verified against the v2 preimage, and the meaning/name/time
// are recorded so a verifier reconstructs the same preimage. Returns the signer
// fingerprint.
func (s *Sealer) AddEndorsement(pub ed25519.PublicKey, sig []byte, meaning, name, signedAt string) (string, error) {
	return s.addVerified(pub, sig, s.EndorsementSigningBytes(meaning, name, signedAt),
		&Endorsement{Meaning: meaning, Name: name, SignedAt: signedAt})
}

// addVerified verifies sig against preimage, then records the co-signature (and,
// when end != nil, the declared meaning) keyed by the signer's fingerprint.
func (s *Sealer) addVerified(pub ed25519.PublicKey, sig, preimage []byte, end *Endorsement) (string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("seal co-signature: public key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
	if !ed25519.Verify(pub, preimage, sig) {
		return "", errors.New("seal co-signature does not verify against the chain head")
	}
	fpr := Fingerprint(pub)
	s.sigs[fpr] = append([]byte(nil), sig...)
	s.keys[fpr] = append([]byte(nil), pub...)
	if end != nil {
		if s.endorsements == nil {
			s.endorsements = map[string]Endorsement{}
		}
		s.endorsements[fpr] = *end
	}
	return fpr, nil
}

// Sign co-signs the chain head with an Author (its Sign function and public key)
// as a bare (v1) co-signature and records the result. It is a convenience over
// SigningBytes + AddCosignature for the common case where the caller holds the
// signing identity directly.
func (s *Sealer) Sign(a Author) error {
	sig, err := a.Sign(s.SigningBytes())
	if err != nil {
		return fmt.Errorf("sign seal: %w", err)
	}
	_, err = s.AddCosignature(a.Key, sig)
	return err
}

// SignAs co-signs the chain head with an Author while declaring a meaning (item
// 2). The signer's printed name is taken from the Author and the UTC timestamp is
// recorded now; both, with the meaning, become part of the signed v2 preimage.
func (s *Sealer) SignAs(a Author, meaning string) error {
	signedAt := time.Now().UTC().Format(time.RFC3339)
	sig, err := a.Sign(s.EndorsementSigningBytes(meaning, a.Name, signedAt))
	if err != nil {
		return fmt.Errorf("sign seal: %w", err)
	}
	_, err = s.AddEndorsement(a.Key, sig, meaning, a.Name, signedAt)
	return err
}

// AddArtifactApproval records an offline-verifiable human approval of an artifact
// entry (NC-W1, GAP-1/GAP-2), keyed by the entry's proposal id. It reconstructs the
// EXISTING approval preimage (protocol.ArtifactApprovalSigningBytes) from the
// matching artifact entry's SIGNED body — its artifact hash and nonce — and verifies
// sig before recording, so a caller cannot record an approval that would not verify.
// pub is the approver's public key (its fingerprint is bound into the preimage and
// recorded). Returns the approver fingerprint. The proposer-vs-approver (second law)
// distinction is enforced by the verifier from the recorded proposer_fpr, not here.
func (s *Sealer) AddArtifactApproval(proposalID string, pub ed25519.PublicKey, sig []byte) (string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("artifact approval: public key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
	m, ok := s.artifactMetaByProposal(proposalID)
	if !ok {
		return "", fmt.Errorf("artifact approval: no artifact entry with proposal_id %q", proposalID)
	}
	if m.Nonce == "" {
		return "", fmt.Errorf("artifact approval: artifact %q has no nonce to bind the approval", proposalID)
	}
	fpr := Fingerprint(pub)
	preimage := protocol.ArtifactApprovalSigningBytes(proposalID, m.ArtifactHash, fpr, m.Nonce)
	if !ed25519.Verify(pub, preimage, sig) {
		return "", errors.New("artifact approval does not verify against the artifact hash")
	}
	if s.approvals == nil {
		s.approvals = map[string][]ApprovalProof{}
	}
	s.approvals[proposalID] = append(s.approvals[proposalID], ApprovalProof{
		ApproverFpr: fpr,
		ApproverKey: base64.StdEncoding.EncodeToString(pub),
		Sig:         base64.StdEncoding.EncodeToString(sig),
	})
	return fpr, nil
}

// artifactMetaByProposal finds the artifact entry in the snapshot whose signed body
// carries proposalID and returns its parsed metadata.
func (s *Sealer) artifactMetaByProposal(proposalID string) (ArtifactMeta, bool) {
	for _, e := range s.entries {
		if e.Kind != KindArtifact {
			continue
		}
		if m, ok := ArtifactOf(e); ok && m.ProposalID == proposalID {
			return m, true
		}
	}
	return ArtifactMeta{}, false
}

// Count is the number of distinct co-signatures collected so far.
func (s *Sealer) Count() int { return len(s.sigs) }

// Finalize assembles the SealedRecord from the entry snapshot and the collected
// co-signatures. It errors if no co-signature has been added — an unsigned record
// would never verify.
func (s *Sealer) Finalize() (*SealedRecord, error) {
	if len(s.sigs) == 0 {
		return nil, errors.New("cannot finalize a seal with no co-signatures")
	}
	return newSealedRecord(s.room, s.sealedBy, s.entries, s.head, s.sigs, s.keys, s.endorsements, s.approvals), nil
}
