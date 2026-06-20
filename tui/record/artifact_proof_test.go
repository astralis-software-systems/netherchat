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
