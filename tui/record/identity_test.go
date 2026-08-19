package record

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// issuer is a test authority.
type issuer struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	fpr  string
}

func mkIssuer(t *testing.T) issuer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return issuer{pub: pub, priv: priv, fpr: crypto.Fingerprint(pub)}
}

// attestationFor builds a signed attestation about subject, valid for a day.
func attestationFor(t *testing.T, is issuer, subject, principal, serial string, roles ...string) *attest.IdentityAttestation {
	t.Helper()
	if len(roles) == 0 {
		roles = []string{"technical"}
	}
	unsigned := attest.NewIdentityAttestation(attest.IdentitySpec{
		Serial:        serial,
		Subject:       subject,
		Principal:     principal,
		PrincipalType: "person",
		Roles:         roles,
		ExpiresAt:     time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
		Algorithm:     attest.AlgorithmEd25519,
		Issuer:        is.fpr,
	}, nil, nil)
	sig := ed25519.Sign(is.priv, attest.IdentitySigningBytes(unsigned))
	return unsigned.WithSignatures(
		map[string][]byte{is.fpr: sig},
		map[string][]byte{is.fpr: is.pub},
	)
}

// buildAttestedRecord builds a record whose chain is [decision, identity], the
// attestation appended after the entry it is evidence about.
func buildAttestedRecord(t *testing.T, is issuer) (*SealedRecord, *crypto.Identity, *attest.IdentityAttestation) {
	t.Helper()
	alice := mkIdentity(t)
	c := NewChain()
	if _, err := c.AppendNew(authorOf(alice, "alice"), KindDecision, "", "rolled back to v2.3.1"); err != nil {
		t.Fatal(err)
	}
	att := attestationFor(t, is, alice.Fingerprint(), "rosa.alvarez@acme.example", "acme-0001", "qa", "technical")
	e, err := c.AppendIdentity(authorOf(alice, "alice"), att)
	if err != nil {
		t.Fatal(err)
	}
	if e.Kind != KindTyped || e.Schema != attest.IdentitySchema {
		t.Fatalf("identity entry is kind=%q schema=%q", e.Kind, e.Schema)
	}
	return sealRecord(t, "inc-3f9a2b71", c, []*crypto.Identity{alice}), alice, att
}

// TestAppendIdentityProducesAnOrdinaryTypedEntry proves the carrier needs no new
// kind, no new record-level field, and no new format version: it is an ordinary
// typed entry, and the record is labelled v2 for the reason any typed-entry
// record already is.
func TestAppendIdentityProducesAnOrdinaryTypedEntry(t *testing.T) {
	is := mkIssuer(t)
	rec, _, att := buildAttestedRecord(t, is)

	if rec.Version != FormatVersionV2 {
		t.Errorf("record version = %q, want %q", rec.Version, FormatVersionV2)
	}
	e := rec.Entries[1]
	if !IsIdentityEntry(e) {
		t.Fatal("entry 1 must be an identity entry")
	}
	if err := VerifyEntry(e); err != nil {
		t.Fatalf("an identity entry must verify as an ordinary entry: %v", err)
	}

	// The body is byte-identical to the standalone artifact, so an operator can
	// compare the file they were handed with the entry that carries it.
	standalone, err := att.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if e.Body != string(standalone) {
		t.Error("the entry body must be exactly the standalone artifact's bytes")
	}

	// And the record still parses through the strict parser: no record-level key
	// was added, so an older build reads this file too.
	b, err := rec.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(b); err != nil {
		t.Fatalf("a record carrying attestations must parse strictly: %v", err)
	}
}

// TestVerifyWithIdentitySurfacesBindings proves the third map: with a pinned
// issuer and a time, a verified binding appears keyed by SUBJECT fingerprint,
// which is what lets a consumer join it to an approver with a map lookup.
func TestVerifyWithIdentitySurfacesBindings(t *testing.T) {
	is := mkIssuer(t)
	rec, alice, att := buildAttestedRecord(t, is)

	res, err := VerifyWithIdentity(rec, attest.IdentityOptions{
		IssuerKeys: []ed25519.PublicKey{is.pub},
		At:         time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("record should be sound: %s", res.Reason)
	}
	bindings := VerifiedIdentitiesOf(res, alice.Fingerprint())
	if len(bindings) != 1 {
		t.Fatalf("want one binding for %s, got %d", alice.Fingerprint(), len(bindings))
	}
	b := bindings[0]
	if b.Principal != att.Principal || b.Serial != att.Serial {
		t.Errorf("binding = %+v, want the artifact's principal and serial", b)
	}
	if len(b.Roles) != 2 || b.Roles[0] != "qa" {
		t.Errorf("roles = %v, want the issuer's sorted list", b.Roles)
	}
	if len(res.IdentityOutcomes) != 1 || !res.IdentityOutcomes[0].Valid {
		t.Errorf("outcomes = %+v", res.IdentityOutcomes)
	}
	if res.IdentityOutcomes[0].Seq != 1 {
		t.Errorf("the outcome must name the entry that carried it, got seq %d", res.IdentityOutcomes[0].Seq)
	}
}

// TestVerifyWithIdentityIsInertWithNoPin is the standalone-inert row for the
// record surface, asserted the strictest way available: the RESULT IS
// BYTE-IDENTICAL to what plain Verify produces. No third map, no outcomes, no
// difference a consumer could observe.
//
// It also proves the ordering that makes that true — the no-pin check precedes
// the opts.At check — by passing a zero time, which is an error on the pinned
// path and must be no such thing here.
func TestVerifyWithIdentityIsInertWithNoPin(t *testing.T) {
	is := mkIssuer(t)
	rec, _, _ := buildAttestedRecord(t, is)

	plain, err := Verify(rec)
	if err != nil {
		t.Fatal(err)
	}
	withID, err := VerifyWithIdentity(rec, attest.IdentityOptions{}) // no keys, zero At
	if err != nil {
		t.Fatalf("no pin and no time is a legal call: %v", err)
	}
	if withID.IdentityBindings != nil || withID.IdentityOutcomes != nil {
		t.Fatal("with no issuer pinned there must be no identity surface at all")
	}
	pj, _ := json.Marshal(plain)
	wj, _ := json.Marshal(withID)
	if string(pj) != string(wj) {
		t.Fatalf("with no issuer pinned the result must be byte-identical to Verify:\n plain: %s\n ident: %s", pj, wj)
	}
}

// TestVerifyWithIdentityNeverChangesValid is the deliberate asymmetry with the
// approvals block, and the property the whole inertness guarantee rests on: a
// failing attestation is REPORTED, never fatal. Letting it flip Valid would make
// record validity depend on the verifier's configuration, and "VALID" would mean
// different things on different machines.
func TestVerifyWithIdentityNeverChangesValid(t *testing.T) {
	is, stranger := mkIssuer(t), mkIssuer(t)
	rec, _, _ := buildAttestedRecord(t, is)

	cases := []struct {
		name   string
		opts   attest.IdentityOptions
		reason attest.IdentityReason
		class  attest.IdentityReasonClass
	}{
		{
			name:   "an authority we never pinned",
			opts:   attest.IdentityOptions{IssuerKeys: []ed25519.PublicKey{stranger.pub}, At: time.Now().UTC()},
			reason: attest.ReasonNoPinnedIssuerVerified,
			class:  attest.ClassUnanchored,
		},
		{
			name:   "evaluated long after the window closed",
			opts:   attest.IdentityOptions{IssuerKeys: []ed25519.PublicKey{is.pub}, At: time.Now().UTC().Add(10 * 365 * 24 * time.Hour)},
			reason: attest.ReasonExpired,
			class:  attest.ClassLifecycle,
		},
	}
	for _, tc := range cases {
		res, err := VerifyWithIdentity(rec, tc.opts)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !res.Valid {
			t.Errorf("%s: the RECORD is still cryptographically sound; a failing attestation must not invalidate it", tc.name)
		}
		if len(res.IdentityBindings) != 0 {
			t.Errorf("%s: nothing verified, so nothing is bound", tc.name)
		}
		if len(res.IdentityOutcomes) != 1 {
			t.Fatalf("%s: the failure must be visible, not silently missing: %+v", tc.name, res.IdentityOutcomes)
		}
		o := res.IdentityOutcomes[0]
		if o.Valid || o.Reason != tc.reason || o.ReasonClass != tc.class {
			t.Errorf("%s: outcome = %+v, want reason %q class %q", tc.name, o, tc.reason, tc.class)
		}
	}
}

// TestVerifyWithIdentityZeroAtOnThePinnedPathIsAnError proves the other half of
// step 3: once a caller HAS pinned an issuer, it has asked for the identity path
// and must supply the time that path is defined in terms of. Silently invalid
// bindings would be the worst available answer.
func TestVerifyWithIdentityZeroAtOnThePinnedPathIsAnError(t *testing.T) {
	is := mkIssuer(t)
	rec, _, _ := buildAttestedRecord(t, is)

	res, err := VerifyWithIdentity(rec, attest.IdentityOptions{IssuerKeys: []ed25519.PublicKey{is.pub}})
	if err == nil {
		t.Fatalf("a pinned issuer with no evaluation time must be an error, got %+v", res)
	}
	if res != nil {
		t.Error("an error must carry a nil result")
	}
}

// TestVerifyWithIdentityUnsoundRecordIsUntouched proves step 1: bindings are not
// surfaced for a record that is not cryptographically sound. There is nothing to
// say about a credential inside a record that contradicts itself.
func TestVerifyWithIdentityUnsoundRecordIsUntouched(t *testing.T) {
	is := mkIssuer(t)
	rec, _, _ := buildAttestedRecord(t, is)
	rec.Entries[0].Body = "tampered"

	res, err := VerifyWithIdentity(rec, attest.IdentityOptions{
		IssuerKeys: []ed25519.PublicKey{is.pub},
		At:         time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid {
		t.Fatal("a tampered record must not verify")
	}
	if res.IdentityBindings != nil || res.IdentityOutcomes != nil {
		t.Error("an unsound record surfaces no identity at all")
	}
}

// TestVerifyWithIdentityDedupesAndSurfacesRivals covers the two halves of §4.4's
// duplicate rule: the SAME attestation carried twice collapses to one binding,
// while two DIFFERENT serials for one subject are both surfaced, because
// adjudicating between an old and a renewed credential is consumer policy.
func TestVerifyWithIdentityDedupesAndSurfacesRivals(t *testing.T) {
	is := mkIssuer(t)
	alice := mkIdentity(t)
	same := attestationFor(t, is, alice.Fingerprint(), "rosa.alvarez@acme.example", "acme-0001")
	renewed := attestationFor(t, is, alice.Fingerprint(), "rosa.alvarez@acme.example", "acme-0002")

	c := NewChain()
	for _, att := range []*attest.IdentityAttestation{same, same, renewed} {
		if _, err := c.AppendIdentity(authorOf(alice, "alice"), att); err != nil {
			t.Fatal(err)
		}
	}
	rec := sealRecord(t, "inc-3f9a2b71", c, []*crypto.Identity{alice})

	res, err := VerifyWithIdentity(rec, attest.IdentityOptions{
		IssuerKeys: []ed25519.PublicKey{is.pub},
		At:         time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	bindings := VerifiedIdentitiesOf(res, alice.Fingerprint())
	if len(bindings) != 2 {
		t.Fatalf("want 2 bindings (the duplicate collapsed, the rival kept), got %d: %+v", len(bindings), bindings)
	}
	if bindings[0].Serial != "acme-0001" || bindings[1].Serial != "acme-0002" {
		t.Errorf("bindings must be sorted by issuer then serial, got %s then %s", bindings[0].Serial, bindings[1].Serial)
	}
	// Every ENTRY still gets an outcome, including the duplicate: the outcomes
	// slice reports what was in the record, not what survived dedup.
	if len(res.IdentityOutcomes) != 3 {
		t.Errorf("want one outcome per entry, got %d", len(res.IdentityOutcomes))
	}
}

// TestVerifyWithIdentityMalformedBodyIsVisible proves an entry whose body is not
// an identity artifact at all is reported rather than skipped. A silently
// dropped attestation is indistinguishable from one that was never there, and
// silent drops are the failure mode this tree has already learned about once.
func TestVerifyWithIdentityMalformedBodyIsVisible(t *testing.T) {
	is := mkIssuer(t)
	alice := mkIdentity(t)
	c := NewChain()
	if _, err := c.Append(authorOf(alice, "alice"), EntrySpec{
		Kind:   KindTyped,
		Schema: attest.IdentitySchema,
		Body:   `{"netherchat_identity":"v1","this_key_does_not_exist":true}`,
	}); err != nil {
		t.Fatal(err)
	}
	rec := sealRecord(t, "inc-3f9a2b71", c, []*crypto.Identity{alice})

	res, err := VerifyWithIdentity(rec, attest.IdentityOptions{
		IssuerKeys: []ed25519.PublicKey{is.pub},
		At:         time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Error("a malformed attestation body must not invalidate the record")
	}
	if len(res.IdentityOutcomes) != 1 {
		t.Fatalf("the entry must produce an outcome: %+v", res.IdentityOutcomes)
	}
	o := res.IdentityOutcomes[0]
	if o.Reason != ReasonMalformedArtifact || o.ReasonClass != attest.ClassMalformed {
		t.Errorf("outcome = %+v, want %q/%q", o, ReasonMalformedArtifact, attest.ClassMalformed)
	}
}

// TestIdentityEntrySpecIsTheSingleDefinition proves the live client and an
// offline chain builder produce the same entry: both go through
// IdentityEntrySpec, so there is one definition of what an identity entry is
// rather than two that can drift.
func TestIdentityEntrySpecIsTheSingleDefinition(t *testing.T) {
	is := mkIssuer(t)
	alice := mkIdentity(t)
	att := attestationFor(t, is, alice.Fingerprint(), "p@acme.example", "acme-0001")

	spec, err := IdentityEntrySpec(att)
	if err != nil {
		t.Fatal(err)
	}
	c1, c2 := NewChain(), NewChain()
	viaSpec, err := c1.Append(authorOf(alice, "alice"), spec)
	if err != nil {
		t.Fatal(err)
	}
	viaHelper, err := c2.AppendIdentity(authorOf(alice, "alice"), att)
	if err != nil {
		t.Fatal(err)
	}
	if viaSpec.Kind != viaHelper.Kind || viaSpec.Schema != viaHelper.Schema || viaSpec.Body != viaHelper.Body {
		t.Fatal("the two producer paths must build the same entry")
	}
	if _, err := IdentityEntrySpec(nil); err == nil {
		t.Error("a nil attestation has no entry")
	}
}

// TestVerifyBytesWithIdentityRoundTrip proves the on-disk entry point: a record
// written to bytes, read back by something that was never in the room, and
// verified with an issuer key and a time supplied from outside.
func TestVerifyBytesWithIdentityRoundTrip(t *testing.T) {
	is := mkIssuer(t)
	rec, alice, _ := buildAttestedRecord(t, is)
	b, err := rec.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	res, err := VerifyBytesWithIdentity(b, attest.IdentityOptions{
		IssuerKeys: []ed25519.PublicKey{is.pub},
		At:         time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid || len(VerifiedIdentitiesOf(res, alice.Fingerprint())) != 1 {
		t.Fatalf("offline verification must surface the binding: valid=%v bindings=%+v", res.Valid, res.IdentityBindings)
	}

	// And the result is still clean JSON, so the --json contract holds with the
	// two new fields present.
	j, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	var back VerifyResult
	if err := json.Unmarshal(j, &back); err != nil {
		t.Fatalf("verify result does not round-trip: %v", err)
	}
	if len(back.IdentityBindings) != 1 {
		t.Error("identity_bindings must survive the JSON round trip")
	}
}

// TestVerifiedIdentitiesOfIsNilSafe pins the accessor's contract.
func TestVerifiedIdentitiesOfIsNilSafe(t *testing.T) {
	if VerifiedIdentitiesOf(nil, "SHA256:whatever") != nil {
		t.Error("a nil result yields nil")
	}
	if VerifiedIdentitiesOf(&VerifyResult{}, "SHA256:whatever") != nil {
		t.Error("an absent subject yields nil")
	}
}
