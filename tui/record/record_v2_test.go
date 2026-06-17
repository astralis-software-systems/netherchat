package record

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/salehkreiner/netherchat/protocol"
)

// fixedKey returns a deterministic identity from a one-byte seed, so a record
// built from it has reproducible signatures (no randomness, no time.Now).
func fixedKey(seed byte) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	s := make([]byte, ed25519.SeedSize)
	s[0] = seed
	priv := ed25519.NewKeyFromSeed(s)
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv, Fingerprint(pub)
}

// deterministicV1Record hand-builds a v1 record exactly as the pre-v2 code would
// have: a single non-extended decision entry signed with the v1 canonical bytes,
// co-sealed with a bare v1 head signature, fixed timestamps. It stands in for "a
// record produced by the current (pre-change) version".
func deterministicV1Record(t *testing.T) *SealedRecord {
	t.Helper()
	pub, priv, fpr := fixedKey(1)
	const room = "inc-001"

	e := Entry{
		Seq: 0, TS: 1700000000, AuthorID: fpr, AuthorName: "alice", AuthorKey: pub,
		Kind: KindDecision, Body: "rolled back to v2.3.1 at 03:47 UTC", PrevHash: zeroHash(),
	}
	if e.extended() {
		t.Fatal("the baseline entry must NOT be extended (would change v1 bytes)")
	}
	e.Sig = ed25519.Sign(priv, e.canonical())
	head := e.Hash()
	sealSig := ed25519.Sign(priv, protocol.SealSigningBytes(room, head[:]))

	return &SealedRecord{
		Version: FormatVersion, Room: room, SealedAt: "2023-11-14T22:13:20Z", SealedBy: fpr,
		Entries: []Entry{e}, HeadHash: hex.EncodeToString(head[:]),
		Signatures: map[string]string{fpr: base64.StdEncoding.EncodeToString(sealSig)},
		SignerKeys: map[string]string{fpr: base64.StdEncoding.EncodeToString(pub)},
	}
}

// TestVerifyOldFormatRecordStillValid is the headline backward-compat guarantee:
// a record produced before the v2 changes (v1 entry bytes, v1 seal signature, no
// schema/links/endorsements) must still verify VALID, unchanged.
func TestVerifyOldFormatRecordStillValid(t *testing.T) {
	rec := deterministicV1Record(t)

	res, err := Verify(rec)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if !res.Valid {
		t.Fatalf("old-format v1 record did not verify VALID: %s", res.Reason)
	}
	if rec.Version != FormatVersion {
		t.Fatalf("baseline record version = %q, want %q", rec.Version, FormatVersion)
	}
	if rec.Endorsements != nil {
		t.Fatal("a v1 record must carry no endorsements")
	}

	// And it survives a marshal/parse round-trip through the on-disk form.
	b, err := rec.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	res2, err := VerifyBytes(b)
	if err != nil || !res2.Valid {
		t.Fatalf("round-tripped v1 record failed: err=%v result=%+v", err, res2)
	}
}

// TestV1EntryWithInjectedV2FieldFails proves the downgrade/field-injection guard:
// adding a v2 field (a schema tag) to a signed v1 entry flips its canonical layout
// to v2, so the original v1 signature no longer verifies — the field cannot be
// smuggled in without detection.
func TestV1EntryWithInjectedV2FieldFails(t *testing.T) {
	rec := deterministicV1Record(t)
	rec.Entries[0].Schema = "smuggled" // not re-signed
	res, _ := Verify(rec)
	if res.Valid {
		t.Fatal("a v1 entry with an injected schema tag verified as VALID")
	}
}

// TestTypedKindRoundTrips proves a consumer-defined typed entry (KindTyped + an
// opaque schema tag/version) builds, seals, and verifies, and that the record is
// labeled v2. The library never interprets the tag.
func TestTypedKindRoundTrips(t *testing.T) {
	pub, priv, fpr := fixedKey(2)
	author := Author{ID: fpr, Name: "alice", Key: pub, Sign: func(b []byte) ([]byte, error) { return ed25519.Sign(priv, b), nil }}

	c := NewChain()
	e, err := c.Append(author, EntrySpec{Kind: KindTyped, Schema: "transcript", SchemaVer: "1", Body: "raw transcript hash 0xabc"})
	if err != nil {
		t.Fatalf("append typed: %v", err)
	}
	if !e.extended() {
		t.Fatal("typed entry should be extended (v2 bytes)")
	}

	sealer := NewSealer("room", fpr, c.Entries())
	if err := sealer.Sign(author); err != nil {
		t.Fatalf("seal: %v", err)
	}
	rec, err := sealer.Finalize()
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if rec.Version != FormatVersionV2 {
		t.Fatalf("typed record version = %q, want %q", rec.Version, FormatVersionV2)
	}
	res, _ := Verify(rec)
	if !res.Valid {
		t.Fatalf("typed record did not verify: %s", res.Reason)
	}
	if got := rec.Entries[0]; got.Schema != "transcript" || got.SchemaVer != "1" {
		t.Fatalf("typed tag not preserved: %+v", got)
	}

	// A typed entry with an empty schema tag is rejected.
	bad := rec.Entries[0]
	bad.Schema = ""
	if err := VerifyEntry(bad); err == nil {
		t.Fatal("typed entry with empty schema tag must be rejected")
	}
}

// TestTraceabilityLinkRoundTrips proves cross-record links are part of the signed
// payload: a derived record links to a parent's hash, verifies VALID, and any
// tampering with a link is detected.
func TestTraceabilityLinkRoundTrips(t *testing.T) {
	// A parent record, whose head_hash the child will reference.
	parent := deterministicV1Record(t)

	pub, priv, fpr := fixedKey(3)
	author := Author{ID: fpr, Name: "bob", Key: pub, Sign: func(b []byte) ([]byte, error) { return ed25519.Sign(priv, b), nil }}

	c := NewChain()
	if _, err := c.Append(author, EntrySpec{
		Kind: KindDecision, Body: "ratified the parent's findings",
		Links: []Link{{Hash: parent.HeadHash, Relation: "derived-from"}},
	}); err != nil {
		t.Fatalf("append linked: %v", err)
	}
	sealer := NewSealer("child", fpr, c.Entries())
	if err := sealer.Sign(author); err != nil {
		t.Fatalf("seal: %v", err)
	}
	rec, _ := sealer.Finalize()
	if rec.Version != FormatVersionV2 {
		t.Fatalf("linked record version = %q, want %q", rec.Version, FormatVersionV2)
	}
	res, _ := Verify(rec)
	if !res.Valid {
		t.Fatalf("linked record did not verify: %s", res.Reason)
	}

	// The link references the parent's actual head — verifiable lineage.
	if got := rec.Entries[0].Links[0].Hash; got != parent.HeadHash {
		t.Fatalf("link hash = %q, want parent head %q", got, parent.HeadHash)
	}

	// Tampering with the link relation breaks the entry signature.
	rec.Entries[0].Links[0].Relation = "supersedes"
	if res2, _ := Verify(rec); res2.Valid {
		t.Fatal("tampered link relation verified as VALID")
	}
}

// TestSealMeaningRoundTrips proves a declared signature meaning (item 2) is part
// of the signed seal payload: the meaning/name/timestamp verify, and altering the
// meaning after the fact breaks verification.
func TestSealMeaningRoundTrips(t *testing.T) {
	pub, priv, fpr := fixedKey(4)
	author := Author{ID: fpr, Name: "Dr. Alice Example", Key: pub, Sign: func(b []byte) ([]byte, error) { return ed25519.Sign(priv, b), nil }}

	c := NewChain()
	if _, err := c.AppendNew(author, KindDecision, "", "approve the change"); err != nil {
		t.Fatalf("append: %v", err)
	}
	sealer := NewSealer("room", fpr, c.Entries())
	if err := sealer.SignAs(author, MeaningApproved); err != nil {
		t.Fatalf("sign as: %v", err)
	}
	rec, _ := sealer.Finalize()

	if rec.Version != FormatVersionV2 {
		t.Fatalf("endorsed record version = %q, want %q", rec.Version, FormatVersionV2)
	}
	end, ok := rec.Endorsements[fpr]
	if !ok {
		t.Fatal("endorsement not recorded for signer")
	}
	if end.Meaning != MeaningApproved || end.Name != "Dr. Alice Example" || end.SignedAt == "" {
		t.Fatalf("endorsement fields wrong: %+v", end)
	}
	if res, _ := Verify(rec); !res.Valid {
		t.Fatalf("endorsed record did not verify: %s", res.Reason)
	}

	// Tampering with the declared meaning breaks that signer's signature.
	e := rec.Endorsements[fpr]
	e.Meaning = MeaningRejected
	rec.Endorsements[fpr] = e
	if res, _ := Verify(rec); res.Valid {
		t.Fatal("altered endorsement meaning verified as VALID")
	}
}

// TestSealMeaningMixedWithBareCosign proves a record may mix a meaning-bearing
// co-signature with a bare one, and both verify.
func TestSealMeaningMixedWithBareCosign(t *testing.T) {
	pubA, privA, fprA := fixedKey(5)
	pubB, privB, fprB := fixedKey(6)
	alice := Author{ID: fprA, Name: "alice", Key: pubA, Sign: func(b []byte) ([]byte, error) { return ed25519.Sign(privA, b), nil }}
	bob := Author{ID: fprB, Name: "bob", Key: pubB, Sign: func(b []byte) ([]byte, error) { return ed25519.Sign(privB, b), nil }}

	c := NewChain()
	if _, err := c.AppendNew(alice, KindDecision, "", "ship release 5"); err != nil {
		t.Fatalf("append: %v", err)
	}
	sealer := NewSealer("room", fprA, c.Entries())
	if err := sealer.SignAs(alice, MeaningApproved); err != nil { // v2
		t.Fatalf("alice sign as: %v", err)
	}
	if err := sealer.Sign(bob); err != nil { // v1 bare
		t.Fatalf("bob sign: %v", err)
	}
	rec, _ := sealer.Finalize()

	res, _ := Verify(rec)
	if !res.Valid {
		t.Fatalf("mixed record did not verify: %s", res.Reason)
	}
	if len(res.Signers) != 2 {
		t.Fatalf("verified %d signers, want 2", len(res.Signers))
	}
	if _, ok := rec.Endorsements[fprA]; !ok {
		t.Fatal("alice's endorsement should be recorded")
	}
	if _, ok := rec.Endorsements[fprB]; ok {
		t.Fatal("bob's bare co-signature must not have an endorsement")
	}
}
