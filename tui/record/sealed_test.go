package record

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/salehkreiner/netherchat/protocol"
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
