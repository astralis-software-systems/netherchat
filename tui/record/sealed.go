package record

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// FormatVersion is the baseline on-disk record.json schema version, written for a
// record that uses no v2 feature. FormatVersionV2 is written when a record uses a
// v2 feature (signature meanings, typed entry kinds, or traceability links).
// Verify accepts both; a record produced before v2 existed is FormatVersion and
// continues to verify byte-for-byte as before.
const (
	FormatVersion   = "v1"
	FormatVersionV2 = "v2"
)

// Built-in electronic-signature meanings (item 2): the declared reason a
// participant attached to a seal co-signature. The set is EXTENSIBLE — a consumer
// may declare additional meanings, and the library treats Endorsement.Meaning as
// an opaque, signed string — but these four ship as the documented defaults.
const (
	MeaningAuthored = "authored"
	MeaningReviewed = "reviewed"
	MeaningApproved = "approved"
	MeaningRejected = "rejected"
)

// Endorsement is the declared meaning a seal co-signer attached to their
// signature (item 2): WHY they signed (Meaning), their printed Name, and the UTC
// time they signed (SignedAt, RFC3339). All three are bound into the v2 seal
// preimage (protocol.SealSigningBytesV2), so none can be altered without
// invalidating that signer's signature — the meaning is a signed fact, not
// editable metadata.
type Endorsement struct {
	Meaning  string `json:"meaning"`
	Name     string `json:"name"`
	SignedAt string `json:"signed_at"`
}

// ApprovalProof is one human's offline-verifiable approval of a specific artifact
// (NC-W1, GAP-1/GAP-2). It is the approver's Ed25519 signature, retained from the
// live Two-Person Rule exchange, over the EXISTING approval preimage
// protocol.ArtifactApprovalSigningBytes(proposalID, artifactHash, ApproverFpr,
// nonce) — proposalID/artifactHash/nonce come from the artifact entry's signed
// Body (ArtifactMeta). A verifier reconstructs that preimage, checks the signature
// with ApproverKey, and checks Fingerprint(ApproverKey)==ApproverFpr, so the
// approver attribution is unforgeable: only the holder of the approver's private
// key can produce a proof that verifies under their fingerprint.
//
// Proofs are self-authenticating and live at the record level
// (SealedRecord.ArtifactApprovals); they are NOT covered by any entry or seal
// signature. Adding a junk/forged proof makes verification fail (fail-closed);
// adding a proof signed by an attacker's own key contributes only an UNRECOGNIZED
// fingerprint, which a consumer's authorized-reviewer policy rejects. Forging a
// victim's approval is impossible without the victim's key.
type ApprovalProof struct {
	ApproverFpr string `json:"approver_fpr"`
	ApproverKey string `json:"approver_key"` // base64 Ed25519 public key
	Sig         string `json:"sig"`          // base64 Ed25519 signature over the approval preimage
}

// SealedRecord is the machine-readable artifact written by /seal: the entire
// entry chain plus, for each participant who co-signed, an Ed25519 signature over
// the chain head (§1.4). It is self-verifying — SignerKeys carries the public
// keys needed to check the seal signatures, and each entry carries the key needed
// to check its own — so `netherchat verify` needs nothing but the file.
type SealedRecord struct {
	Version    string            `json:"netherchat_record"` // FormatVersion ("v1")
	Room       string            `json:"room"`
	SealedAt   string            `json:"sealed_at"` // RFC3339 UTC
	SealedBy   string            `json:"sealed_by"` // fingerprint of the participant who ran /seal
	Entries    []Entry           `json:"entries"`
	HeadHash   string            `json:"head_hash"`   // hex SHA-256 of the last entry's canonical bytes
	Signatures map[string]string `json:"signatures"`  // fingerprint -> base64 Ed25519 sig over the seal preimage
	SignerKeys map[string]string `json:"signer_keys"` // fingerprint -> base64 Ed25519 public key (to verify Signatures)

	// Endorsements carries, per signer fingerprint, the declared meaning/name/UTC
	// time bound into that signer's v2 seal preimage (item 2). It is present only
	// for records that use signature meanings; a signer WITHOUT an entry here
	// co-signed the bare v1 head preimage. Absent entirely on v1 records.
	Endorsements map[string]Endorsement `json:"endorsements,omitempty"`

	// ArtifactApprovals carries, per artifact PROPOSAL ID, the set of identity-bound
	// approval proofs collected under the Two-Person Rule (GAP-1/GAP-2). Keying by
	// proposal_id (unique per proposal) makes the same-content-twice collision
	// structurally impossible; the artifact hash stays bound in each proof's preimage.
	// Additive and omitempty: absent on every pre-existing record, so those verify
	// byte-for-byte. NOT part of any entry or seal signing preimage.
	ArtifactApprovals map[string][]ApprovalProof `json:"artifact_approvals,omitempty"`
}

// NewSealedRecord assembles a record from a finished chain and the collected seal
// signatures (the v1 path: bare head co-signatures, no declared meanings).
// sealerSigs and sealerKeys are keyed by fingerprint and hold raw bytes; they are
// base64-encoded here. The record's Version is v2 if any entry is extended
// (typed kind / links), else v1.
func NewSealedRecord(room, sealedBy string, entries []Entry, head []byte, sealerSigs, sealerKeys map[string][]byte) *SealedRecord {
	return newSealedRecord(room, sealedBy, entries, head, sealerSigs, sealerKeys, nil, nil)
}

// newSealedRecord is the shared assembler. endorsements (item 2) and approvals
// (artifact two-person proofs) are optional: when either is non-empty those facts
// are recorded and the record is labeled v2.
func newSealedRecord(room, sealedBy string, entries []Entry, head []byte, sealerSigs, sealerKeys map[string][]byte, endorsements map[string]Endorsement, approvals map[string][]ApprovalProof) *SealedRecord {
	sigs := make(map[string]string, len(sealerSigs))
	for fpr, sig := range sealerSigs {
		sigs[fpr] = base64.StdEncoding.EncodeToString(sig)
	}
	keys := make(map[string]string, len(sealerKeys))
	for fpr, k := range sealerKeys {
		keys[fpr] = base64.StdEncoding.EncodeToString(k)
	}
	rec := &SealedRecord{
		Version:    recordVersion(entries, endorsements, approvals),
		Room:       room,
		SealedAt:   time.Now().UTC().Format(time.RFC3339),
		SealedBy:   sealedBy,
		Entries:    entries,
		HeadHash:   hex.EncodeToString(head),
		Signatures: sigs,
		SignerKeys: keys,
	}
	if len(endorsements) > 0 {
		rec.Endorsements = endorsements
	}
	if len(approvals) > 0 {
		rec.ArtifactApprovals = approvals
	}
	return rec
}

// recordVersion picks the on-disk schema version: v2 if any v2 feature is used
// (declared signature meanings, artifact approval proofs, or an entry with a typed
// kind / traceability links), else v1 — so a plain record stays v1 and maximally
// compatible. A proofs-bearing record stays under the v2 label (no new label), so
// the existing version gate keeps accepting it.
func recordVersion(entries []Entry, endorsements map[string]Endorsement, approvals map[string][]ApprovalProof) string {
	if len(endorsements) > 0 || len(approvals) > 0 {
		return FormatVersionV2
	}
	for _, e := range entries {
		if e.extended() {
			return FormatVersionV2
		}
	}
	return FormatVersion
}

// Marshal renders the record as indented JSON suitable for writing to disk.
func (r *SealedRecord) Marshal() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }

// Parse decodes a record.json, rejecting unknown fields so a record with extra or
// renamed keys (a different/forward format) fails loudly rather than verifying a
// shape we do not fully understand.
func Parse(b []byte) (*SealedRecord, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var r SealedRecord
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("parse record: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("parse record: trailing data after JSON object")
	}
	return &r, nil
}

// VerifyResult summarizes a verification. Valid is true only if the chain links,
// every entry signature, the head hash, every seal signature, AND every artifact
// approval proof all check out.
//
// IMPORTANT (GAP-5): Valid==true means the record is cryptographically SOUND, not
// that any POLICY (e.g. the two-person rule) is satisfied. To treat an artifact as
// two-person approved, read ArtifactApprovers (or VerifiedArtifactApprovers) and
// apply your own policy: at least N distinct fingerprints you recognize, none the
// author/proposer. A record sealed before this feature carries no proofs and is
// surfaced with an empty ArtifactApprovers — it is a single attested approver, NOT
// offline-provable as two-person.
type VerifyResult struct {
	Valid    bool     `json:"valid"`
	Room     string   `json:"room"`
	Entries  int      `json:"entries"`
	Signers  []string `json:"signers"`          // fingerprints whose seal signature verified
	HeadHash string   `json:"head_hash"`        // recomputed, hex
	Reason   string   `json:"reason,omitempty"` // failure detail when !Valid

	// ArtifactApprovers maps an artifact PROPOSAL ID to the sorted set of DISTINCT,
	// cryptographically verified approver fingerprints, EXCLUDING the artifact entry's
	// author and the recorded proposer. It is the offline-provable two-person evidence:
	// the library surfaces the verified set; it imposes NO quorum minimum (consumer
	// policy). Empty/absent for legacy artifact entries (approval not offline-provable).
	ArtifactApprovers map[string][]string `json:"artifact_approvers,omitempty"`
}

// VerifiedArtifactApprovers returns the sorted set of distinct, cryptographically
// verified approver fingerprints for an artifact proposal (excluding the artifact
// entry's author and proposer), or nil if there are none. It is a nil-safe accessor
// over VerifyResult.ArtifactApprovers and imposes NO quorum minimum: a consumer
// enforcing the two-person rule checks len(set) against its own N and confirms each
// fingerprint is a reviewer it recognizes (GAP-5).
func VerifiedArtifactApprovers(res *VerifyResult, proposalID string) []string {
	if res == nil {
		return nil
	}
	return res.ArtifactApprovers[proposalID]
}

// Verify recomputes the chain from scratch and checks every integrity property
// (§1.4):
//
//  1. each entry's Seq is its index and PrevHash links to the prior entry's hash;
//  2. each entry's Ed25519 signature verifies against its author (and the author
//     key hashes to the claimed AuthorID);
//  3. the recomputed head equals the stored head_hash;
//  4. every seal signature verifies against the signer's key over the
//     domain-separated, room-bound head preimage, and the signer key hashes to
//     its fingerprint.
//
// Any failure yields Valid=false with a specific Reason; err is non-nil only for
// malformed inputs (e.g. a non-hex head_hash) that prevent verification entirely.
func Verify(r *SealedRecord) (*VerifyResult, error) {
	res := &VerifyResult{Room: r.Room, Entries: len(r.Entries)}

	if r.Version != FormatVersion && r.Version != FormatVersionV2 {
		res.Reason = fmt.Sprintf("unsupported record version %q (want %q or %q)", r.Version, FormatVersion, FormatVersionV2)
		return res, nil
	}

	// 1 + 2: walk the chain.
	prev := zeroHash()
	for i, e := range r.Entries {
		if e.Seq != uint64(i) {
			res.Reason = fmt.Sprintf("entry %d has seq %d (chain reordered or entries removed)", i, e.Seq)
			return res, nil
		}
		if !bytes.Equal(e.PrevHash, prev) {
			res.Reason = fmt.Sprintf("entry %d prev_hash does not link to the previous entry (chain tampered)", i)
			return res, nil
		}
		if err := VerifyEntry(e); err != nil {
			res.Reason = err.Error()
			return res, nil
		}
		h := e.Hash()
		prev = h[:]
	}

	// 3: the head the sealers signed must be the recomputed head.
	res.HeadHash = hex.EncodeToString(prev)
	storedHead, err := hex.DecodeString(r.HeadHash)
	if err != nil {
		return res, fmt.Errorf("head_hash is not valid hex: %w", err)
	}
	if !bytes.Equal(storedHead, prev) {
		res.Reason = fmt.Sprintf("head_hash %s does not match the recomputed chain head %s", r.HeadHash, res.HeadHash)
		return res, nil
	}

	// 4: seal signatures.
	if len(r.Signatures) == 0 {
		res.Reason = "record has no seal signatures"
		return res, nil
	}
	v1preimage := protocol.SealSigningBytes(r.Room, prev)
	signers := make([]string, 0, len(r.Signatures))
	for fpr, sigB64 := range r.Signatures {
		keyB64, ok := r.SignerKeys[fpr]
		if !ok {
			res.Reason = fmt.Sprintf("no signer key for %s (cannot verify its seal signature)", fpr)
			return res, nil
		}
		key, err := base64.StdEncoding.DecodeString(keyB64)
		if err != nil || len(key) != ed25519.PublicKeySize {
			res.Reason = fmt.Sprintf("signer key for %s is malformed", fpr)
			return res, nil
		}
		if crypto.Fingerprint(ed25519.PublicKey(key)) != fpr {
			res.Reason = fmt.Sprintf("signer key for %s does not match its fingerprint", fpr)
			return res, nil
		}
		sig, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			res.Reason = fmt.Sprintf("seal signature for %s is not valid base64", fpr)
			return res, nil
		}
		// A signer with a recorded endorsement co-signed the meaning-bearing v2
		// preimage; one without co-signed the bare v1 head. The choice is driven by
		// the (signed) endorsement data, so deleting, adding, or editing an
		// endorsement changes the preimage and breaks this signature.
		preimage := v1preimage
		if end, ok := r.Endorsements[fpr]; ok {
			preimage = protocol.SealSigningBytesV2(r.Room, end.Meaning, end.Name, end.SignedAt, prev)
		}
		if !ed25519.Verify(ed25519.PublicKey(key), preimage, sig) {
			res.Reason = fmt.Sprintf("seal signature for %s does not verify against the head", fpr)
			return res, nil
		}
		signers = append(signers, fpr)
	}
	sort.Strings(signers)
	res.Signers = signers

	// 5: artifact approval proofs (GAP-1/GAP-2). Independent of the seal/entry
	// signatures above and impossible to confuse with them — approvals sign the
	// "netherchat/artifact-approval/v1" preimage, entries sign "netherchat/record/*",
	// seals sign "netherchat/seal/*", so a signature from one context can never
	// verify in another. This block only ADDS failure conditions; it runs before
	// res.Valid is set, so a bad proof keeps the record invalid (fail-closed). It is
	// skipped entirely when no proofs are present, so old records are unaffected.
	if len(r.ArtifactApprovals) > 0 {
		approvers, err := r.verifyArtifactApprovals()
		if err != nil {
			res.Reason = err.Error()
			return res, nil
		}
		if len(approvers) > 0 {
			res.ArtifactApprovers = approvers
		}
	}

	res.Valid = true
	return res, nil
}

// verifyArtifactApprovals strictly verifies every record-level artifact approval
// proof and returns, per proposal id, the sorted set of DISTINCT verified approver
// fingerprints EXCLUDING the artifact entry's author and the recorded proposer (the
// second law). It fails closed: any unanchored proof set (no matching artifact
// entry), any proof whose key does not hash to its claimed fingerprint, or any
// signature that does not verify over the reconstructed approval preimage returns
// an error so Verify reports Valid=false. The artifact hash and nonce come from the
// entry's SIGNED body, so they cannot be altered without breaking the entry itself.
func (r *SealedRecord) verifyArtifactApprovals() (map[string][]string, error) {
	// Index artifact entries by proposal id (from their signed bodies); a duplicate
	// proposal id across entries is ambiguous and rejected.
	metaByProposal := make(map[string]ArtifactMeta)
	authorByProposal := make(map[string]string)
	for _, e := range r.Entries {
		if e.Kind != KindArtifact {
			continue
		}
		m, ok := ArtifactOf(e)
		if !ok || m.ProposalID == "" {
			continue
		}
		if _, dup := metaByProposal[m.ProposalID]; dup {
			return nil, fmt.Errorf("artifact_approvals: duplicate proposal_id %q across artifact entries", m.ProposalID)
		}
		metaByProposal[m.ProposalID] = m
		authorByProposal[m.ProposalID] = e.AuthorID
	}

	out := make(map[string][]string)
	for pid, proofs := range r.ArtifactApprovals {
		m, ok := metaByProposal[pid]
		if !ok {
			return nil, fmt.Errorf("artifact_approvals references unknown proposal %q", pid)
		}
		if m.Nonce == "" {
			return nil, fmt.Errorf("artifact %q has approval proofs but no nonce to verify them", pid)
		}
		distinct := make(map[string]bool)
		for _, p := range proofs {
			key, err := base64.StdEncoding.DecodeString(p.ApproverKey)
			if err != nil || len(key) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("artifact %q: approver key for %s is malformed", pid, p.ApproverFpr)
			}
			if crypto.Fingerprint(ed25519.PublicKey(key)) != p.ApproverFpr {
				return nil, fmt.Errorf("artifact %q: approver key does not match fingerprint %s", pid, p.ApproverFpr)
			}
			sig, err := base64.StdEncoding.DecodeString(p.Sig)
			if err != nil {
				return nil, fmt.Errorf("artifact %q: approval signature for %s is not valid base64", pid, p.ApproverFpr)
			}
			preimage := protocol.ArtifactApprovalSigningBytes(pid, m.ArtifactHash, p.ApproverFpr, m.Nonce)
			if !ed25519.Verify(ed25519.PublicKey(key), preimage, sig) {
				return nil, fmt.Errorf("artifact %q: approval by %s does not verify against the artifact hash", pid, p.ApproverFpr)
			}
			distinct[p.ApproverFpr] = true
		}
		// Surface the verified set minus the entry author and the proposer: the
		// "second person(s)" beyond the author who recorded the entry.
		set := make([]string, 0, len(distinct))
		for fpr := range distinct {
			if fpr == authorByProposal[pid] || fpr == m.ProposerFpr {
				continue
			}
			set = append(set, fpr)
		}
		sort.Strings(set)
		if len(set) > 0 {
			out[pid] = set
		}
	}
	return out, nil
}

// nameByFingerprint builds a fingerprint -> display name map from entry authors,
// for rendering signer names in the minutes (names are cosmetic; the fingerprint
// is the authenticated identity).
func (r *SealedRecord) nameByFingerprint() map[string]string {
	m := make(map[string]string)
	for _, e := range r.Entries {
		if _, ok := m[e.AuthorID]; !ok && e.AuthorName != "" {
			m[e.AuthorID] = e.AuthorName
		}
	}
	return m
}

// RenderMinutes produces the human-readable minutes.md (§1.4): decisions, action
// items, and notes grouped under headings, with a participant line and a verify
// hint. It does not re-verify — call Verify first.
func RenderMinutes(r *SealedRecord) string {
	names := r.nameByFingerprint()
	var b strings.Builder

	room := r.Room
	if room == "" {
		room = "(unnamed)"
	}
	fmt.Fprintf(&b, "# Incident Record — %s\n", room)
	fmt.Fprintf(&b, "Sealed: %s\n", r.SealedAt)

	// Participants: every fingerprint that co-signed, by display name where known.
	signers := make([]string, 0, len(r.Signatures))
	for fpr := range r.Signatures {
		signers = append(signers, fpr)
	}
	sort.Strings(signers)
	parts := make([]string, 0, len(signers))
	for _, fpr := range signers {
		who := names[fpr]
		if who == "" {
			who = shortFpr(fpr)
		}
		parts = append(parts, who+" (✓)")
	}
	fmt.Fprintf(&b, "Participants: %s\n", strings.Join(parts, ", "))

	var decisions, actions, notes, artifacts []Entry
	for _, e := range r.Entries {
		switch e.Kind {
		case KindDecision:
			decisions = append(decisions, e)
		case KindAction:
			actions = append(actions, e)
		case KindNote:
			notes = append(notes, e)
		case KindArtifact:
			artifacts = append(artifacts, e)
		}
	}

	if len(decisions) > 0 {
		b.WriteString("\n## Decisions\n")
		for i, e := range decisions {
			fmt.Fprintf(&b, "%d. [%s] **%s**: %s\n", i+1, hhmmUTC(e.TS), e.AuthorName, e.Body)
		}
	}
	if len(actions) > 0 {
		b.WriteString("\n## Actions\n")
		for _, e := range actions {
			fmt.Fprintf(&b, "- [ ] **%s**: %s (assigned by %s)\n", e.Actionee, e.Body, e.AuthorName)
		}
	}
	if len(artifacts) > 0 {
		b.WriteString("\n## AI-Drafted Artifacts (human-approved)\n")
		for _, e := range artifacts {
			m, ok := ArtifactOf(e)
			if !ok {
				continue
			}
			// RenderMinutes does not take a VerifyResult and therefore cannot verify
			// the approval, so it must NOT present an approver as authoritative — the
			// body's approver_fpr is the writer's unverified claim (GAP-1). Show the
			// entry author (who at least signed the entry) as the recorder and point
			// readers at the verified report for authoritative approvers.
			fmt.Fprintf(&b, "- **%s** — source: %s · hash: %s… · recorded by %s (approval not verified here; see the report for verified approvers)\n",
				m.ArtifactRef, m.Source, shortHash(m.ArtifactHash, 16), e.AuthorName)
		}
	}
	if len(notes) > 0 {
		b.WriteString("\n## Notes\n")
		for _, e := range notes {
			fmt.Fprintf(&b, "- [%s] **%s**: %s\n", hhmmUTC(e.TS), e.AuthorName, e.Body)
		}
	}

	fmt.Fprintf(&b, "\n---\n*Sealed by %d participant(s). Verify: netherchat verify record.json*\n", len(r.Signatures))
	return b.String()
}

// hhmmUTC formats a unix timestamp as "15:04 UTC", matching the minutes example.
func hhmmUTC(ts int64) string { return time.Unix(ts, 0).UTC().Format("15:04") + " UTC" }

// shortFpr abbreviates a long "SHA256:…" fingerprint for display when no name is
// known. Falls back to the full string if it is unexpectedly short.
func shortFpr(fpr string) string {
	const n = 16
	if len(fpr) <= n {
		return fpr
	}
	return fpr[:n] + "…"
}
