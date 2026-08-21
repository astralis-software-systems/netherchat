package record

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

func mkIdentity(t *testing.T) *crypto.Identity {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id
}

func authorOf(id *crypto.Identity, name string) Author {
	return Author{ID: id.Fingerprint(), Name: name, Key: id.SignPub, Sign: id.Sign}
}

// sealRecord builds a SealedRecord from a finished chain, co-signed by each of
// sealers (the first is recorded as sealed_by).
func sealRecord(t *testing.T, room string, c *Chain, sealers []*crypto.Identity) *SealedRecord {
	t.Helper()
	head := c.Head()
	sigs := map[string][]byte{}
	keys := map[string][]byte{}
	for _, s := range sealers {
		sig, err := s.Sign(protocol.SealSigningBytes(room, head))
		if err != nil {
			t.Fatalf("seal sign: %v", err)
		}
		sigs[s.Fingerprint()] = sig
		keys[s.Fingerprint()] = s.SignPub
	}
	return NewSealedRecord(room, sealers[0].Fingerprint(), c.Entries(), head, sigs, keys)
}

// buildValid returns a 2-entry chain co-signed by alice and bob.
func buildValid(t *testing.T) (*SealedRecord, *crypto.Identity, *crypto.Identity) {
	alice, bob := mkIdentity(t), mkIdentity(t)
	c := NewChain()
	if _, err := c.AppendNew(authorOf(alice, "alice"), KindDecision, "", "rolled back to v2.3.1 at 03:47 UTC"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AppendNew(authorOf(alice, "alice"), KindAction, "bob", "write post-mortem by Friday"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AppendNew(authorOf(bob, "bob"), KindNote, "", "confirmed all nodes healthy"); err != nil {
		t.Fatal(err)
	}
	return sealRecord(t, "inc-3f9a2b71", c, []*crypto.Identity{alice, bob}), alice, bob
}

func TestVerifyValid(t *testing.T) {
	rec, _, _ := buildValid(t)
	res, err := Verify(rec)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if !res.Valid {
		t.Fatalf("expected VALID, got reason: %s", res.Reason)
	}
	if res.Entries != 3 || len(res.Signers) != 2 {
		t.Errorf("entries=%d signers=%d, want 3 and 2", res.Entries, len(res.Signers))
	}
}

func TestVerifyDetectsTamperedBody(t *testing.T) {
	rec, _, _ := buildValid(t)
	rec.Entries[0].Body = "rolled forward to a broken build"
	res, _ := Verify(rec)
	if res.Valid {
		t.Fatal("tampered body verified as VALID")
	}
}

func TestVerifyDetectsTamperedPrevHash(t *testing.T) {
	rec, _, _ := buildValid(t)
	// Flip a byte in the second entry's link to its predecessor.
	rec.Entries[1].PrevHash[0] ^= 0xff
	res, _ := Verify(rec)
	if res.Valid {
		t.Fatal("broken prev_hash link verified as VALID")
	}
}

func TestVerifyDetectsInvalidSealSignature(t *testing.T) {
	rec, _, _ := buildValid(t)
	for fpr := range rec.Signatures {
		// Corrupt one signature (base64 of a flipped byte set).
		rec.Signatures[fpr] = "AAAA" + rec.Signatures[fpr][4:]
		break
	}
	res, _ := Verify(rec)
	if res.Valid {
		t.Fatal("corrupted seal signature verified as VALID")
	}
}

func TestVerifyDetectsMissingSigner(t *testing.T) {
	rec, _, _ := buildValid(t)
	// Remove the public key for one signer: its signature can no longer be checked.
	for fpr := range rec.SignerKeys {
		delete(rec.SignerKeys, fpr)
		break
	}
	res, _ := Verify(rec)
	if res.Valid {
		t.Fatal("record with a missing signer key verified as VALID")
	}
}

func TestVerifyDetectsForeignSignerKey(t *testing.T) {
	rec, _, _ := buildValid(t)
	// Replace a signer's key with a different valid key whose fingerprint no longer
	// matches the map entry — the fingerprint binding must catch it.
	mallory := mkIdentity(t)
	for fpr := range rec.SignerKeys {
		rec.SignerKeys[fpr] = b64(mallory.SignPub)
		break
	}
	res, _ := Verify(rec)
	if res.Valid {
		t.Fatal("substituted signer key verified as VALID (fingerprint binding missing)")
	}
}

func TestRoundTripDisallowUnknownFields(t *testing.T) {
	rec, _, _ := buildValid(t)
	b, err := rec.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parsed, err := Parse(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	res, _ := Verify(parsed)
	if !res.Valid {
		t.Fatalf("round-tripped record failed to verify: %s", res.Reason)
	}

	// An unknown field must be rejected, not silently ignored.
	withExtra := strings.Replace(string(b), "\"room\":", "\"surprise\": 1,\n  \"room\":", 1)
	if _, err := Parse([]byte(withExtra)); err == nil {
		t.Fatal("Parse accepted an unknown field (DisallowUnknownFields not enforced)")
	}
}

func TestRenderMinutes(t *testing.T) {
	rec, _, _ := buildValid(t)
	md := RenderMinutes(rec)
	for _, want := range []string{
		"# Incident Record — inc-3f9a2b71",
		"## Decisions",
		"**alice**: rolled back to v2.3.1",
		"## Actions",
		"- [ ] **bob**: write post-mortem by Friday (assigned by alice)",
		"## Notes",
		"netherchat verify record.json",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("minutes missing %q\n---\n%s", want, md)
		}
	}
}

func b64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// TestParseRejectsUnknownFieldInProof pins the NESTED forward-incompat boundary: an
// unknown field inside an ApprovalProof inside a record makes Parse reject the WHOLE
// record (DisallowUnknownFields applies recursively, not just at the top level). This is
// the mechanism that guarantees a pre-v2 verifier rejects a record carrying a v2 `role`
// field outright rather than silently ignoring it. (The read found only the top-level
// case was previously tested.)
func TestParseRejectsUnknownFieldInProof(t *testing.T) {
	alice, _, _ := fixedAuthor(11, "alice")
	_, bobPub, bobPriv := fixedAuthor(12, "bob")
	rec := artifactRecord(t, alice, alice.ID, pid, hash, nonce, "SHA256:agent")
	rec.ArtifactApprovals = map[string][]ApprovalProof{pid: {proofOver(pid, hash, nonce, bobPub, bobPriv)}}
	b, err := rec.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Inject an unknown key inside the proof object (before its approver_fpr field).
	withBogus := strings.Replace(string(b), `"approver_fpr"`, `"bogus": 1, "approver_fpr"`, 1)
	if withBogus == string(b) {
		t.Fatal("precondition: injection did not change the JSON")
	}
	if _, err := Parse([]byte(withBogus)); err == nil {
		t.Fatal("Parse must reject an unknown field nested inside a proof (DisallowUnknownFields)")
	}
}

// MINUTES ARE THE HUMAN-READABLE HALF OF A SEALED RECORD, AND THEY WERE SILENT
// ABOUT A WHOLE CLASS OF ENTRY.
//
// RenderMinutes switched on four kinds and dropped everything else, so a record
// carrying an issuer-signed credential produced a minutes.md that did not mention
// it — a gap between two views of one artifact, where record.json says a name was
// bound to a key and minutes.md says nothing was. The minutes already print
// unauthenticated author names in the Participants line; the one place the record
// holds a SIGNED name was the one place they were quiet.
//
// It also cannot verify: RenderMinutes takes no VerifyResult, exactly as the
// artifact block already says of an approval. So what it must print is the CLAIM,
// marked as a claim, with the key it is about — never a verdict.
func TestMinutesSayWhatTheRecordCarries(t *testing.T) {
	is := mkIssuer(t)
	rec, alice, att := buildAttestedRecord(t, is)
	md := RenderMinutes(rec)

	for _, want := range []string{
		"## Identity attestations",
		"rosa.alvarez@acme.example",
		att.Subject,
		is.fpr,
		"acme-0001",
		"◇",
		"netherchat verify",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("minutes.md does not carry %q — the record says it and the minutes do not:\n%s", want, md)
		}
	}
	// A claim, never a verdict: nothing here checked an issuer signature.
	for _, forbidden := range []string{"◆", "issuer-attested", "verified by"} {
		if strings.Contains(md, forbidden) {
			t.Errorf("minutes.md claims %q about a credential it cannot check:\n%s", forbidden, md)
		}
	}
	if !strings.Contains(md, "not verified here") {
		t.Errorf("minutes.md prints an issuer's words without saying nobody here checked them:\n%s", md)
	}
	// Filing is not vouching. Anyone may carry anyone's credential — the elected
	// writer files every approver's — so a reader who takes "filed by alice" as
	// alice's endorsement has been misled by the layout.
	if !strings.Contains(md, "filed by alice") {
		t.Errorf("minutes.md does not say who filed the credential:\n%s", md)
	}
	if !strings.Contains(md, alice.Fingerprint()) && !strings.Contains(md, "alice") {
		t.Errorf("minutes.md does not say who filed the credential:\n%s", md)
	}
}

// TestMinutesAccountForEveryEntry is the general form of the defect above, so the
// minutes cannot go quiet again about a kind nobody thought of. Every entry in the
// record must be represented; a typed entry of a schema this build does not
// interpret is represented by saying it is there and naming its tag, which is the
// most a library that never interprets a consumer's schema may say about it.
func TestMinutesAccountForEveryEntry(t *testing.T) {
	is := mkIssuer(t)
	alice := mkIdentity(t)
	c := NewChain()
	if _, err := c.AppendNew(authorOf(alice, "alice"), KindDecision, "", "rolled back to v2.3.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AppendIdentity(authorOf(alice, "alice"),
		attestationFor(t, is, alice.Fingerprint(), "rosa.alvarez@acme.example", "acme-0001")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Append(authorOf(alice, "alice"),
		EntrySpec{Kind: KindTyped, Schema: "acme.change-ticket/v3", Body: `{"ticket":"CHG-4471"}`}); err != nil {
		t.Fatal(err)
	}
	rec := sealRecord(t, "inc-3f9a2b71", c, []*crypto.Identity{alice})
	md := RenderMinutes(rec)

	if !strings.Contains(md, "acme.change-ticket/v3") {
		t.Errorf("a typed entry of an unknown schema is in the record and absent from the minutes:\n%s", md)
	}
	if strings.Contains(md, `{"ticket":"CHG-4471"}`) {
		t.Errorf("the minutes rendered an opaque consumer body it cannot interpret:\n%s", md)
	}
	// The property, stated over the record rather than over a heading: every entry
	// is represented by something a reader can tie back to it. A count in the
	// header would have said less and would have moved the bytes of every minutes
	// file ever produced, including those of records that carry nothing new.
	for _, e := range rec.Entries {
		token := e.Body
		if IsIdentityEntry(e) {
			att, perr := attest.ParseIdentity([]byte(e.Body))
			if perr != nil {
				t.Fatal(perr)
			}
			token = att.Subject
		} else if e.Kind == KindTyped {
			token = e.Schema
		}
		if !strings.Contains(md, token) {
			t.Errorf("entry %d (kind %q schema %q) is in the record and unrepresented in the "+
				"minutes; nothing identifying it (%q) appears:\n%s", e.Seq, e.Kind, e.Schema, token, md)
		}
	}
}

// deterministicRecord returns a record whose minutes are byte-stable: fixed room,
// fixed seal time, fixed entry timestamps and fixed author fingerprints.
//
// The values are overwritten AFTER the chain is built, which is sound here and
// nowhere else: RenderMinutes does not verify, so nothing in this fixture depends
// on the signatures still matching the bytes. A verification test must never do
// this, and none does.
func deterministicRecord(t *testing.T, withIdentity bool) *SealedRecord {
	t.Helper()
	is := mkIssuer(t)
	alice := mkIdentity(t)
	c := NewChain()
	if _, err := c.AppendNew(authorOf(alice, "alice"), KindDecision, "", "rolled back to v2.3.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AppendNew(authorOf(alice, "alice"), KindAction, "bob", "write the post-mortem"); err != nil {
		t.Fatal(err)
	}
	if withIdentity {
		if _, err := c.AppendIdentity(authorOf(alice, "alice"),
			attestationFor(t, is, alice.Fingerprint(), "rosa.alvarez@acme.example", "acme-0001")); err != nil {
			t.Fatal(err)
		}
	}
	rec := sealRecord(t, "inc-3f9a2b71", c, []*crypto.Identity{alice})
	rec.SealedAt = "2026-06-01T14:40:00Z"
	const fixedFpr = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	for i := range rec.Entries {
		rec.Entries[i].TS = 1780000000 + int64(i)*60
		rec.Entries[i].AuthorID = fixedFpr
	}
	sigs := map[string][]byte{}
	for _, v := range rec.Signatures {
		sigs[fixedFpr] = []byte(v)
	}
	rec.Signatures = map[string]string{fixedFpr: "x"}
	return rec
}

// TestMinutesAreInertForARecordWithoutAnAttestation is the standalone-inert guard
// for minutes.md, against bytes captured from a pristine `git archive 8624c11`
// extraction rather than re-derived. A record that carries no credential produces
// the file it produced before this change, to the byte.
func TestMinutesAreInertForARecordWithoutAnAttestation(t *testing.T) {
	got := RenderMinutes(deterministicRecord(t, false))
	want, err := os.ReadFile(filepath.Join("testdata", "minutes_pre3c.txt"))
	if err != nil {
		t.Fatalf("golden: %v", err)
	}
	if got != string(want) {
		t.Errorf("minutes.md moved for a record that carries no attestation.\n"+
			"--- captured at 8624c11 (testdata/minutes_pre3c.txt) ---\n%s\n--- now ---\n%s", want, got)
	}
}

// The anti-vacuity half: the same fixture with one credential in it must move,
// or the guard above is watching a file that cannot change.
func TestMinutesMoveWhenTheRecordCarriesACredential(t *testing.T) {
	if RenderMinutes(deterministicRecord(t, true)) == RenderMinutes(deterministicRecord(t, false)) {
		t.Fatal("a filed credential changed nothing in the minutes")
	}
}
