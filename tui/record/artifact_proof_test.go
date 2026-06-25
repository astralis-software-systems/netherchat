package record

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/salehkreiner/netherchat/protocol"
)

// These tests pin the GAP-1/GAP-2 fix: artifact two-person approval is offline-
// provable via record-level ArtifactApprovals proofs, and approver attribution is
// unforgeable. Each test is written so that reverting its guard flips the result.

// fixedAuthor builds a deterministic Author (and exposes its raw keys for signing
// approval proofs) from a one-byte seed, so records are reproducible.
func fixedAuthor(seed byte, name string) (Author, ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, fpr := fixedKey(seed)
	a := Author{ID: fpr, Name: name, Key: pub, Sign: func(b []byte) ([]byte, error) { return ed25519.Sign(priv, b), nil }}
	return a, pub, priv
}

// proofOver builds an ApprovalProof: pub/priv sign the EXISTING approval preimage
// for (proposalID, hash, Fingerprint(pub), nonce).
func proofOver(proposalID, hash, nonce string, pub ed25519.PublicKey, priv ed25519.PrivateKey) ApprovalProof {
	return proofClaiming(proposalID, hash, nonce, Fingerprint(pub), pub, priv)
}

// proofClaiming builds a proof where pub/priv produce a VALID signature over the
// approval preimage for claimFpr — which may DIFFER from Fingerprint(pub). This is
// the shape of a forged-attribution attempt: the signature verifies under the
// provided key, so only the key→fingerprint binding can reject it.
func proofClaiming(proposalID, hash, nonce, claimFpr string, pub ed25519.PublicKey, priv ed25519.PrivateKey) ApprovalProof {
	sig := ed25519.Sign(priv, protocol.ArtifactApprovalSigningBytes(proposalID, hash, claimFpr, nonce))
	return ApprovalProof{
		ApproverFpr: claimFpr,
		ApproverKey: base64.StdEncoding.EncodeToString(pub),
		Sig:         base64.StdEncoding.EncodeToString(sig),
	}
}

// artifactRecord builds a one-artifact-entry sealed record authored and sealed by
// author. bodyApproverFpr is what the (untrusted) ArtifactMeta.approver_fpr claims;
// proposerFpr is recorded in the body. No proofs are attached (caller adds them).
func artifactRecord(t *testing.T, author Author, bodyApproverFpr, proposalID, hash, nonce, proposerFpr string) *SealedRecord {
	t.Helper()
	meta := ArtifactMeta{
		Source: "agent", ArtifactRef: "ref", ArtifactHash: hash, ApproverFpr: bodyApproverFpr,
		ProposalID: proposalID, Nonce: nonce, ProposerFpr: proposerFpr,
	}
	body, err := MarshalArtifactBody(meta)
	if err != nil {
		t.Fatalf("marshal artifact body: %v", err)
	}
	c := NewChain()
	if _, err := c.Append(author, EntrySpec{Kind: KindArtifact, Body: body}); err != nil {
		t.Fatalf("append artifact entry: %v", err)
	}
	s := NewSealer("ops", author.ID, c.Entries())
	if err := s.Sign(author); err != nil {
		t.Fatalf("seal: %v", err)
	}
	rec, err := s.Finalize()
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	return rec
}

const (
	pid   = "p100000000000000"
	hash  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	nonce = "n200000000000000"
)

// (A1) The exact audit forgery: an attacker authors the artifact entry with their
// OWN key (valid AuthorID), sets the body's approver_fpr to a victim, and attaches
// NO proof. The record is cryptographically sound (Valid), but the verifier must
// NOT treat the body's approver_fpr as an approver: the surfaced set is empty.
func TestArtifactForgeryNoProofsNotTwoPerson(t *testing.T) {
	attacker, _, _ := fixedAuthor(10, "attacker")
	victimFpr := "SHA256:VICTIMxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	rec := artifactRecord(t, attacker, victimFpr, pid, hash, nonce, "SHA256:agent")

	res, err := Verify(rec)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.Valid {
		t.Fatalf("a legitimately-signed single-author record should be Valid: %s", res.Reason)
	}
	if len(res.ArtifactApprovers) != 0 {
		t.Fatalf("no proofs → no offline-proven approvers, got %v", res.ArtifactApprovers)
	}
	if got := VerifiedArtifactApprovers(res, pid); got != nil {
		t.Fatalf("VerifiedArtifactApprovers should be nil with no proofs, got %v", got)
	}
}

// (A2) The attacker, lacking the victim's key, fabricates a proof claiming the
// victim's fingerprint but backed by a key that does not hash to it → Valid=false.
func TestArtifactForgeryBogusProofFailsClosed(t *testing.T) {
	attacker, atkPub, atkPriv := fixedAuthor(10, "attacker")
	victimFpr := "SHA256:VICTIMxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	rec := artifactRecord(t, attacker, victimFpr, pid, hash, nonce, "SHA256:agent")

	// The attacker, lacking the victim's key, signs the approval preimage FOR the
	// victim's fpr with their OWN key. The signature is valid under the attacker's key,
	// so ONLY the key→fingerprint binding can catch this forged attribution.
	rec.ArtifactApprovals = map[string][]ApprovalProof{
		pid: {proofClaiming(pid, hash, nonce, victimFpr, atkPub, atkPriv)},
	}
	res, _ := Verify(rec)
	if res.Valid {
		t.Fatal("a forged proof (attacker key claiming the victim's fpr) must make the record invalid")
	}
}

// (B1) A proof whose key does not hash to its claimed fingerprint → Valid=false. The
// signature itself is VALID under the provided key, so only the key→fpr binding
// rejects it (this is what makes the test mutation-sensitive to that guard).
func TestArtifactProofKeyFprMismatch(t *testing.T) {
	alice, _, _ := fixedAuthor(11, "alice")
	_, bobPub, bobPriv := fixedAuthor(12, "bob")
	rec := artifactRecord(t, alice, alice.ID, pid, hash, nonce, "SHA256:agent")

	bad := proofClaiming(pid, hash, nonce, "SHA256:NOTBOBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", bobPub, bobPriv)
	rec.ArtifactApprovals = map[string][]ApprovalProof{pid: {bad}}
	res, _ := Verify(rec)
	if res.Valid {
		t.Fatal("a proof whose key does not match its fingerprint must fail")
	}
}

// (B2) A proof whose signature does not verify over the reconstructed preimage →
// Valid=false.
func TestArtifactProofBadSignature(t *testing.T) {
	alice, _, _ := fixedAuthor(11, "alice")
	_, bobPub, bobPriv := fixedAuthor(12, "bob")
	rec := artifactRecord(t, alice, alice.ID, pid, hash, nonce, "SHA256:agent")

	// Correct key/fpr, but the signature is over the WRONG bytes (different nonce).
	p := proofOver(pid, hash, "WRONG-NONCE", bobPub, bobPriv)
	p.ApproverFpr = Fingerprint(bobPub) // keep the fpr/key consistent so we hit the sig check
	rec.ArtifactApprovals = map[string][]ApprovalProof{pid: {p}}
	res, _ := Verify(rec)
	if res.Valid {
		t.Fatal("a proof whose signature does not verify over the artifact preimage must fail")
	}
}

// (B3) A duplicate proof from the same approver counts once, not twice.
func TestArtifactProofDuplicateCountedOnce(t *testing.T) {
	alice, _, _ := fixedAuthor(11, "alice")
	_, bobPub, bobPriv := fixedAuthor(12, "bob")
	rec := artifactRecord(t, alice, alice.ID, pid, hash, nonce, "SHA256:agent")

	bp := proofOver(pid, hash, nonce, bobPub, bobPriv)
	rec.ArtifactApprovals = map[string][]ApprovalProof{pid: {bp, bp}} // same proof twice
	res, _ := Verify(rec)
	if !res.Valid {
		t.Fatalf("two valid (duplicate) proofs should still verify: %s", res.Reason)
	}
	if got := VerifiedArtifactApprovers(res, pid); len(got) != 1 {
		t.Fatalf("a duplicate approver must collapse to one, got %v", got)
	}
}

// (B4) A proof by the entry author (and one by the proposer) is excluded from the
// surfaced two-person set; only a DISTINCT third party counts.
func TestArtifactProofAuthorAndProposerExcluded(t *testing.T) {
	alice, alicePub, alicePriv := fixedAuthor(11, "alice") // author of the entry
	agent, agentPub, agentPriv := fixedAuthor(99, "agent") // the proposer
	_, bobPub, bobPriv := fixedAuthor(12, "bob")           // the genuine second person
	rec := artifactRecord(t, alice, alice.ID, pid, hash, nonce, agent.ID)

	// All three proofs verify cryptographically; only Bob should be surfaced.
	rec.ArtifactApprovals = map[string][]ApprovalProof{pid: {
		proofOver(pid, hash, nonce, alicePub, alicePriv), // author — excluded
		proofOver(pid, hash, nonce, agentPub, agentPriv), // proposer — excluded (second law)
		proofOver(pid, hash, nonce, bobPub, bobPriv),     // the distinct approver
	}}
	res, _ := Verify(rec)
	if !res.Valid {
		t.Fatalf("all proofs are valid; record should verify: %s", res.Reason)
	}
	got := VerifiedArtifactApprovers(res, pid)
	if len(got) != 1 || got[0] != Fingerprint(bobPub) {
		t.Fatalf("surfaced set must be exactly {bob}, got %v", got)
	}
	if contains(got, alice.ID) {
		t.Fatal("the entry author must not be counted toward two-person")
	}
	if contains(got, agent.ID) {
		t.Fatal("the proposer must not be counted toward two-person (the second law)")
	}
}

// (C) A legitimate two-person record built via the PUBLIC construction path
// (Sealer.AddArtifactApproval) verifies, surfaces the distinct approver, and does
// so through the offline bytes path (VerifyBytes).
func TestArtifactTwoPersonLegitimateOfflineProvable(t *testing.T) {
	alice, alicePub, alicePriv := fixedAuthor(11, "alice") // writer/author + an approver
	agentFpr := "SHA256:agent"
	_, bobPub, bobPriv := fixedAuthor(12, "bob") // the second, distinct approver

	meta := ArtifactMeta{
		Source: "agent", ArtifactRef: "ref", ArtifactHash: hash, ApproverFpr: alice.ID,
		ProposalID: pid, Nonce: nonce, ProposerFpr: agentFpr,
	}
	body, _ := MarshalArtifactBody(meta)
	c := NewChain()
	if _, err := c.Append(alice, EntrySpec{Kind: KindArtifact, Body: body}); err != nil {
		t.Fatalf("append: %v", err)
	}
	s := NewSealer("ops", alice.ID, c.Entries())
	if err := s.Sign(alice); err != nil {
		t.Fatalf("seal: %v", err)
	}
	// Both approvers' real signatures, added through the verifying public path.
	if _, err := s.AddArtifactApproval(pid, alicePub, ed25519.Sign(alicePriv, protocol.ArtifactApprovalSigningBytes(pid, hash, alice.ID, nonce))); err != nil {
		t.Fatalf("add alice approval: %v", err)
	}
	if _, err := s.AddArtifactApproval(pid, bobPub, ed25519.Sign(bobPriv, protocol.ArtifactApprovalSigningBytes(pid, hash, Fingerprint(bobPub), nonce))); err != nil {
		t.Fatalf("add bob approval: %v", err)
	}
	rec, err := s.Finalize()
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if rec.Version != FormatVersionV2 {
		t.Fatalf("proofs-bearing record should be labeled v2, got %q", rec.Version)
	}

	b, err := rec.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	res, err := VerifyBytes(b)
	if err != nil {
		t.Fatalf("verify bytes: %v", err)
	}
	if !res.Valid {
		t.Fatalf("legitimate two-person record must verify: %s", res.Reason)
	}
	got := VerifiedArtifactApprovers(res, pid)
	if len(got) != 1 || got[0] != Fingerprint(bobPub) {
		t.Fatalf("surfaced approver set must be {bob}, got %v", got)
	}
}

// An orphan proof set (no artifact entry with that proposal_id) is malformed and
// must fail closed rather than be silently ignored.
func TestArtifactOrphanProofSetFailsClosed(t *testing.T) {
	alice, _, _ := fixedAuthor(11, "alice")
	_, bobPub, bobPriv := fixedAuthor(12, "bob")
	rec := artifactRecord(t, alice, alice.ID, pid, hash, nonce, "SHA256:agent")

	rec.ArtifactApprovals = map[string][]ApprovalProof{
		"no-such-proposal": {proofOver("no-such-proposal", hash, nonce, bobPub, bobPriv)},
	}
	res, _ := Verify(rec)
	if res.Valid {
		t.Fatal("a proof set that references no artifact entry must fail closed")
	}
}

// Proofs present but the body carries no nonce → the preimage cannot be
// reconstructed → fail closed.
func TestArtifactProofsWithoutNonceFailsClosed(t *testing.T) {
	alice, _, _ := fixedAuthor(11, "alice")
	_, bobPub, bobPriv := fixedAuthor(12, "bob")
	rec := artifactRecord(t, alice, alice.ID, pid, hash, "" /* no nonce */, "SHA256:agent")

	rec.ArtifactApprovals = map[string][]ApprovalProof{pid: {proofOver(pid, hash, "", bobPub, bobPriv)}}
	res, _ := Verify(rec)
	if res.Valid {
		t.Fatal("approval proofs with no nonce to verify against must fail closed")
	}
}

// (D) An OLD-format artifact record (no proofs, no proposal_id/nonce/proposer_fpr)
// verifies BYTE-IDENTICALLY through a marshal/parse/marshal round-trip (the new
// omitempty fields stay absent) and is reported as NOT offline-provable two-person.
func TestOldArtifactRecordByteIdenticalNotTwoPerson(t *testing.T) {
	pub, priv, fpr := fixedKey(20)
	author := Author{ID: fpr, Name: "alice", Key: pub, Sign: func(b []byte) ([]byte, error) { return ed25519.Sign(priv, b), nil }}

	// Old body: ONLY the original six fields (no proposal_id/nonce/proposer_fpr).
	old := ArtifactMeta{Source: "agent", ArtifactRef: "ref", ArtifactHash: hash, ApproverFpr: fpr, ProposedAt: "2026-06-01T00:00:00Z", ApprovedAt: "2026-06-01T00:01:00Z"}
	body, _ := MarshalArtifactBody(old)
	c := NewChain()
	if _, err := c.Append(author, EntrySpec{Kind: KindArtifact, Body: body}); err != nil {
		t.Fatalf("append: %v", err)
	}
	s := NewSealer("ops", fpr, c.Entries())
	if err := s.Sign(author); err != nil {
		t.Fatalf("seal: %v", err)
	}
	rec, _ := s.Finalize()

	b1, err := rec.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// The new top-level field must be omitted entirely on an old record.
	for _, banned := range []string{"artifact_approvals", "proposal_id", "nonce", "proposer_fpr"} {
		if bytes.Contains(b1, []byte(banned)) {
			t.Fatalf("old record leaked new field %q via omitempty failure", banned)
		}
	}
	parsed, err := Parse(b1)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	b2, _ := parsed.Marshal()
	if !bytes.Equal(b1, b2) {
		t.Fatalf("old record did not round-trip byte-identically:\n%s\n---\n%s", b1, b2)
	}
	res, err := Verify(parsed)
	if err != nil || !res.Valid {
		t.Fatalf("old artifact record must still verify: err=%v reason=%q", err, res.Reason)
	}
	if len(res.ArtifactApprovers) != 0 {
		t.Fatal("an old record must be reported as NOT offline-provable two-person (empty approver set)")
	}
}

// (E) Non-artifact and endorsement-bearing records are unaffected: they verify and
// surface no artifact approvers.
func TestNonArtifactAndEndorsementUnaffected(t *testing.T) {
	// Non-artifact record.
	a, _, _ := fixedAuthor(30, "alice")
	c := NewChain()
	if _, err := c.AppendNew(a, KindDecision, "", "ship it"); err != nil {
		t.Fatal(err)
	}
	s := NewSealer("ops", a.ID, c.Entries())
	if err := s.Sign(a); err != nil {
		t.Fatal(err)
	}
	rec, _ := s.Finalize()
	if res, _ := Verify(rec); !res.Valid || len(res.ArtifactApprovers) != 0 {
		t.Fatalf("non-artifact record regressed: valid=%v approvers=%v", res.Valid, res.ArtifactApprovers)
	}

	// Endorsement-bearing record.
	a2, _, _ := fixedAuthor(31, "bob")
	c2 := NewChain()
	if _, err := c2.AppendNew(a2, KindDecision, "", "approve the change"); err != nil {
		t.Fatal(err)
	}
	s2 := NewSealer("ops", a2.ID, c2.Entries())
	if err := s2.SignAs(a2, MeaningApproved); err != nil {
		t.Fatal(err)
	}
	rec2, _ := s2.Finalize()
	if res, _ := Verify(rec2); !res.Valid || len(res.ArtifactApprovers) != 0 {
		t.Fatalf("endorsement record regressed: valid=%v approvers=%v", res.Valid, res.ArtifactApprovers)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// --- Pass B: role-typed artifact-approval/v2 ---------------------------------

// roleProofOver builds a v2 (role-typed) ApprovalProof: pub/priv sign the v2 approval
// preimage for (proposalID, hash, Fingerprint(pub), nonce, role), and the proof carries
// the declared role so the verifier dispatches to the v2 path.
func roleProofOver(proposalID, hash, nonce, role string, pub ed25519.PublicKey, priv ed25519.PrivateKey) ApprovalProof {
	sig := ed25519.Sign(priv, protocol.ArtifactApprovalSigningBytesV2(proposalID, hash, Fingerprint(pub), nonce, role))
	return ApprovalProof{
		ApproverFpr: Fingerprint(pub),
		ApproverKey: base64.StdEncoding.EncodeToString(pub),
		Sig:         base64.StdEncoding.EncodeToString(sig),
		Role:        role,
	}
}

// contains2 reports whether any surfaced (fpr, role) pair has the given fingerprint.
func contains2(rs []VerifiedApprover, fpr string) bool {
	for _, r := range rs {
		if r.Fingerprint == fpr {
			return true
		}
	}
	return false
}

// (V1) A single role-typed proof verifies, surfaces exactly one (fpr, role) pair, and
// the approver's fingerprint ALSO appears in the role-agnostic ArtifactApprovers set.
func TestArtifactRoleTypedHappyPath(t *testing.T) {
	alice, _, _ := fixedAuthor(11, "alice")
	_, bobPub, bobPriv := fixedAuthor(12, "bob")
	rec := artifactRecord(t, alice, alice.ID, pid, hash, nonce, "SHA256:agent")
	rec.ArtifactApprovals = map[string][]ApprovalProof{pid: {roleProofOver(pid, hash, nonce, "qa", bobPub, bobPriv)}}

	res, _ := Verify(rec)
	if !res.Valid {
		t.Fatalf("role-typed record should verify: %s", res.Reason)
	}
	roles := VerifiedArtifactApproverRoles(res, pid)
	if len(roles) != 1 || roles[0].Fingerprint != Fingerprint(bobPub) || roles[0].Role != "qa" {
		t.Fatalf("role surface must be {bob, qa}, got %v", roles)
	}
	if got := VerifiedArtifactApprovers(res, pid); len(got) != 1 || got[0] != Fingerprint(bobPub) {
		t.Fatalf("a v2 approver must also appear in ArtifactApprovers, got %v", got)
	}
}

// (V2) A proposal may carry both a v1 (roleless) and a v2 (role) proof: both verify; only
// the v2 one is in the role map; both fingerprints are in ArtifactApprovers.
func TestArtifactMixedV1V2Bag(t *testing.T) {
	alice, _, _ := fixedAuthor(11, "alice")
	_, bobPub, bobPriv := fixedAuthor(12, "bob")       // v2 role approver
	_, carolPub, carolPriv := fixedAuthor(13, "carol") // v1 roleless approver
	rec := artifactRecord(t, alice, alice.ID, pid, hash, nonce, "SHA256:agent")
	rec.ArtifactApprovals = map[string][]ApprovalProof{pid: {
		roleProofOver(pid, hash, nonce, "qa", bobPub, bobPriv),
		proofOver(pid, hash, nonce, carolPub, carolPriv),
	}}

	res, _ := Verify(rec)
	if !res.Valid {
		t.Fatalf("mixed v1/v2 bag should verify: %s", res.Reason)
	}
	roles := VerifiedArtifactApproverRoles(res, pid)
	if len(roles) != 1 || roles[0].Fingerprint != Fingerprint(bobPub) || roles[0].Role != "qa" {
		t.Fatalf("only the v2 proof belongs in the role map, got %v", roles)
	}
	approvers := VerifiedArtifactApprovers(res, pid)
	if len(approvers) != 2 || !contains(approvers, Fingerprint(bobPub)) || !contains(approvers, Fingerprint(carolPub)) {
		t.Fatalf("both v1 and v2 approvers must be in ArtifactApprovers, got %v", approvers)
	}
}

// (V3) The same fingerprint signing two DISTINCT roles surfaces BOTH pairs (per-(fpr,role)
// dedup), while collapsing to one entry in the role-agnostic ArtifactApprovers set.
func TestArtifactSameFprTwoRoles(t *testing.T) {
	alice, _, _ := fixedAuthor(11, "alice")
	_, bobPub, bobPriv := fixedAuthor(12, "bob")
	rec := artifactRecord(t, alice, alice.ID, pid, hash, nonce, "SHA256:agent")
	rec.ArtifactApprovals = map[string][]ApprovalProof{pid: {
		roleProofOver(pid, hash, nonce, "qa", bobPub, bobPriv),
		roleProofOver(pid, hash, nonce, "technical", bobPub, bobPriv),
	}}

	res, _ := Verify(rec)
	if !res.Valid {
		t.Fatalf("two-role record should verify: %s", res.Reason)
	}
	roles := VerifiedArtifactApproverRoles(res, pid)
	if len(roles) != 2 || roles[0].Role != "qa" || roles[1].Role != "technical" {
		t.Fatalf("per-(fpr,role) dedup must surface both roles sorted, got %v", roles)
	}
	if got := VerifiedArtifactApprovers(res, pid); len(got) != 1 {
		t.Fatalf("one fpr collapses to one entry in ArtifactApprovers, got %v", got)
	}
}

// (V4) An identical (fpr, role) pair repeated collapses to one.
func TestArtifactDuplicateRolePairCollapses(t *testing.T) {
	alice, _, _ := fixedAuthor(11, "alice")
	_, bobPub, bobPriv := fixedAuthor(12, "bob")
	rec := artifactRecord(t, alice, alice.ID, pid, hash, nonce, "SHA256:agent")
	rp := roleProofOver(pid, hash, nonce, "qa", bobPub, bobPriv)
	rec.ArtifactApprovals = map[string][]ApprovalProof{pid: {rp, rp}}

	res, _ := Verify(rec)
	if !res.Valid {
		t.Fatalf("duplicate role pair should still verify: %s", res.Reason)
	}
	if roles := VerifiedArtifactApproverRoles(res, pid); len(roles) != 1 {
		t.Fatalf("identical (fpr, role) pair must collapse to one, got %v", roles)
	}
}

// (V5) Role-typed proofs by the entry author and the proposer are excluded from the role
// map (the second law), exactly like the roleless set; only a distinct third party shows.
func TestArtifactRoleAuthorProposerExcluded(t *testing.T) {
	alice, alicePub, alicePriv := fixedAuthor(11, "alice") // entry author
	agent, agentPub, agentPriv := fixedAuthor(99, "agent") // proposer
	_, bobPub, bobPriv := fixedAuthor(12, "bob")           // genuine distinct approver
	rec := artifactRecord(t, alice, alice.ID, pid, hash, nonce, agent.ID)
	rec.ArtifactApprovals = map[string][]ApprovalProof{pid: {
		roleProofOver(pid, hash, nonce, "qa", alicePub, alicePriv),        // author — excluded
		roleProofOver(pid, hash, nonce, "technical", agentPub, agentPriv), // proposer — excluded
		roleProofOver(pid, hash, nonce, "system-owner", bobPub, bobPriv),  // surfaced
	}}

	res, _ := Verify(rec)
	if !res.Valid {
		t.Fatalf("all proofs valid; should verify: %s", res.Reason)
	}
	roles := VerifiedArtifactApproverRoles(res, pid)
	if len(roles) != 1 || roles[0].Fingerprint != Fingerprint(bobPub) || roles[0].Role != "system-owner" {
		t.Fatalf("role map must be exactly {bob, system-owner}, got %v", roles)
	}
	if contains2(roles, alice.ID) || contains2(roles, agent.ID) {
		t.Fatal("author/proposer must not appear in the role map")
	}
}

// (V6 / I2′) A record carrying only v1 (roleless) proofs serializes with NO role key and
// round-trips byte-identically after the Role field was added (omitempty). This pins the
// property the read found previously untested.
func TestV1ArtifactProofByteIdenticalWithRoleField(t *testing.T) {
	alice, _, _ := fixedAuthor(11, "alice")
	_, bobPub, bobPriv := fixedAuthor(12, "bob")

	meta := ArtifactMeta{Source: "agent", ArtifactRef: "ref", ArtifactHash: hash, ApproverFpr: Fingerprint(bobPub), ProposalID: pid, Nonce: nonce, ProposerFpr: "SHA256:agent"}
	body, _ := MarshalArtifactBody(meta)
	c := NewChain()
	if _, err := c.Append(alice, EntrySpec{Kind: KindArtifact, Body: body}); err != nil {
		t.Fatal(err)
	}
	s := NewSealer("ops", alice.ID, c.Entries())
	if err := s.Sign(alice); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddArtifactApproval(pid, bobPub, ed25519.Sign(bobPriv, protocol.ArtifactApprovalSigningBytes(pid, hash, Fingerprint(bobPub), nonce))); err != nil {
		t.Fatal(err)
	}
	rec, _ := s.Finalize()

	b1, err := rec.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b1, []byte(`"role"`)) {
		t.Fatal("a v1 proof must not serialize a role key (omitempty)")
	}
	parsed, err := Parse(b1)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := parsed.Marshal()
	if !bytes.Equal(b1, b2) {
		t.Fatalf("v1-proof record not byte-identical after adding Role:\n%s\n---\n%s", b1, b2)
	}
	if res, _ := Verify(parsed); !res.Valid {
		t.Fatalf("v1-proof record must verify: %s", res.Reason)
	}
}

// (V7) A v2 proof whose role is relabeled AFTER signing fails closed (preimage mismatch).
func TestArtifactV2RoleTamperFailsClosed(t *testing.T) {
	alice, _, _ := fixedAuthor(11, "alice")
	_, bobPub, bobPriv := fixedAuthor(12, "bob")
	rec := artifactRecord(t, alice, alice.ID, pid, hash, nonce, "SHA256:agent")
	p := roleProofOver(pid, hash, nonce, "qa", bobPub, bobPriv)
	p.Role = "system-owner" // relabel after signing
	rec.ArtifactApprovals = map[string][]ApprovalProof{pid: {p}}

	if res, _ := Verify(rec); res.Valid {
		t.Fatal("a v2 proof whose role was relabeled after signing must fail closed")
	}
}

// (V8) A v1-signed proof with a role ADDED to the JSON flips dispatch to v2 and fails
// closed (the signature covers the v1 preimage, not the v2 one).
func TestArtifactRoleAddedToV1ProofFailsClosed(t *testing.T) {
	alice, _, _ := fixedAuthor(11, "alice")
	_, bobPub, bobPriv := fixedAuthor(12, "bob")
	rec := artifactRecord(t, alice, alice.ID, pid, hash, nonce, "SHA256:agent")
	p := proofOver(pid, hash, nonce, bobPub, bobPriv) // signed over the v1 preimage
	p.Role = "qa"                                     // add a role → dispatch flips to v2
	rec.ArtifactApprovals = map[string][]ApprovalProof{pid: {p}}

	if res, _ := Verify(rec); res.Valid {
		t.Fatal("a v1-signed proof with a role added to the JSON must fail closed")
	}
}

// (V9) A v2 proof whose key does not hash to its claimed fingerprint fails closed.
func TestArtifactV2KeyFprMismatchFailsClosed(t *testing.T) {
	alice, _, _ := fixedAuthor(11, "alice")
	_, bobPub, bobPriv := fixedAuthor(12, "bob")
	rec := artifactRecord(t, alice, alice.ID, pid, hash, nonce, "SHA256:agent")
	p := roleProofOver(pid, hash, nonce, "qa", bobPub, bobPriv)
	p.ApproverFpr = "SHA256:NOTBOBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	rec.ArtifactApprovals = map[string][]ApprovalProof{pid: {p}}

	if res, _ := Verify(rec); res.Valid {
		t.Fatal("a v2 proof whose key does not match its fingerprint must fail closed")
	}
}

// (V10) The PUBLIC v2 construction path (Sealer.AddArtifactApprovalV2 + the preimage
// exposer) produces a record that verifies offline via VerifyBytes and surfaces the role.
func TestArtifactV2OfflineProvableViaSealer(t *testing.T) {
	alice, _, _ := fixedAuthor(11, "alice")
	_, bobPub, bobPriv := fixedAuthor(12, "bob")

	meta := ArtifactMeta{Source: "agent", ArtifactRef: "ref", ArtifactHash: hash, ApproverFpr: Fingerprint(bobPub), ProposalID: pid, Nonce: nonce, ProposerFpr: "SHA256:agent"}
	body, _ := MarshalArtifactBody(meta)
	c := NewChain()
	if _, err := c.Append(alice, EntrySpec{Kind: KindArtifact, Body: body}); err != nil {
		t.Fatal(err)
	}
	s := NewSealer("ops", alice.ID, c.Entries())
	if err := s.Sign(alice); err != nil {
		t.Fatal(err)
	}
	preimage, err := s.ArtifactApprovalSigningBytesV2(pid, "qa", bobPub)
	if err != nil {
		t.Fatalf("exposer: %v", err)
	}
	if _, err := s.AddArtifactApprovalV2(pid, "qa", bobPub, ed25519.Sign(bobPriv, preimage)); err != nil {
		t.Fatalf("add v2 approval: %v", err)
	}
	rec, _ := s.Finalize()
	if rec.Version != FormatVersionV2 {
		t.Fatalf("proofs-bearing record should be v2, got %q", rec.Version)
	}

	b, err := rec.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	res, err := VerifyBytes(b)
	if err != nil {
		t.Fatalf("verify bytes: %v", err)
	}
	if !res.Valid {
		t.Fatalf("v2 record must verify: %s", res.Reason)
	}
	roles := VerifiedArtifactApproverRoles(res, pid)
	if len(roles) != 1 || roles[0].Role != "qa" || roles[0].Fingerprint != Fingerprint(bobPub) {
		t.Fatalf("surface must be {bob, qa}, got %v", roles)
	}
}

// (V11) The v2 exposer and AddArtifactApprovalV2 reject an empty role (an empty role is
// the v1 form, not a valid v2 approval).
func TestArtifactV2RejectsEmptyRole(t *testing.T) {
	alice, _, _ := fixedAuthor(11, "alice")
	_, bobPub, bobPriv := fixedAuthor(12, "bob")

	meta := ArtifactMeta{Source: "agent", ArtifactRef: "ref", ArtifactHash: hash, ApproverFpr: Fingerprint(bobPub), ProposalID: pid, Nonce: nonce, ProposerFpr: "SHA256:agent"}
	body, _ := MarshalArtifactBody(meta)
	c := NewChain()
	if _, err := c.Append(alice, EntrySpec{Kind: KindArtifact, Body: body}); err != nil {
		t.Fatal(err)
	}
	s := NewSealer("ops", alice.ID, c.Entries())
	if err := s.Sign(alice); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ArtifactApprovalSigningBytesV2(pid, "", bobPub); err == nil {
		t.Fatal("the v2 exposer must reject an empty role")
	}
	if _, err := s.AddArtifactApprovalV2(pid, "", bobPub, ed25519.Sign(bobPriv, []byte("x"))); err == nil {
		t.Fatal("AddArtifactApprovalV2 must reject an empty role")
	}
}
