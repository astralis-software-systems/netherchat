package attest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

// This file holds the display_name half of identity/v2 and the version decision
// that came with it. The helpers it shares with identity_test.go — newIssuer,
// subjectFpr, signBy, makeIdentity, atNow — live there.

// makeNamedIdentity builds a valid attestation that carries a display name, with
// deliberate case and padding: the point is that verification hands back what the
// issuer signed, not a tidied version of it.
func makeNamedIdentity(t *testing.T, is issuerKey, display string) *IdentityAttestation {
	t.Helper()
	spec := IdentitySpec{
		Serial:        "acme-0002",
		Subject:       subjectFpr(t),
		Principal:     "rosa.alvarez@acme.example",
		DisplayName:   display,
		PrincipalType: "person",
		Roles:         []string{"qa"},
		ExpiresAt:     time.Now().UTC().Add(90 * 24 * time.Hour).Format(time.RFC3339),
		Algorithm:     AlgorithmEd25519,
		Issuer:        is.fpr,
	}
	return signBy(NewIdentityAttestation(spec, nil, nil), is)
}

// TestVerifyIdentitySurfacesTheSignedDisplayName proves the field survives the
// round trip an operator actually makes — issue, marshal to identity.json, hand
// it over, parse, verify — and that it arrives byte-for-byte. The padding and the
// mixed case are the assertion: nothing here trims or folds, because the value is
// inside a signature and a normalized copy is a value no authority signed.
func TestVerifyIdentitySurfacesTheSignedDisplayName(t *testing.T) {
	is := newIssuer(t)
	const display = " Rosa  ÁLVAREZ " // padded, multibyte, and mixed case on purpose
	a := makeNamedIdentity(t, is, display)

	b, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "display_name") {
		t.Fatalf("a display name an issuer set must appear in the artifact:\n%s", b)
	}
	parsed, err := ParseIdentity(b)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.DisplayName != display {
		t.Errorf("display_name round-tripped as %q, want %q", parsed.DisplayName, display)
	}

	res, err := VerifyIdentity(parsed, IdentityOptions{IssuerKeys: []ed25519.PublicKey{is.pub}, At: atNow()})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("an attestation carrying a display name must verify: %s / %s", res.Reason, res.Detail)
	}
	if res.DisplayName != display {
		t.Errorf("IdentityResult.DisplayName = %q, want the signed bytes %q", res.DisplayName, display)
	}
	if res.Principal != "rosa.alvarez@acme.example" {
		t.Errorf("the principal must survive alongside the display name: %q", res.Principal)
	}
}

// TestVerifyIdentityDisplayNameIsSigned is the tamper proof, and it is the same
// proof role order already has: edit the name, keep the signature, watch it fail.
// Without it "signed display name" is a claim in a doc comment. A display name
// that could be edited in transit would be worse than no display name at all,
// because a surface would render an attacker's string under an authority's badge.
func TestVerifyIdentityDisplayNameIsSigned(t *testing.T) {
	is := newIssuer(t)
	a := makeNamedIdentity(t, is, "Rosa Alvarez")

	tampered := *a
	tampered.DisplayName = "Rosa Alvarez (Acme CA)"

	res, err := VerifyIdentity(&tampered, IdentityOptions{IssuerKeys: []ed25519.PublicKey{is.pub}, At: atNow()})
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid {
		t.Fatal("editing display_name and keeping the signature must NOT verify — the field is inside the preimage")
	}
	if res.Reason != ReasonSignatureInvalid || res.ReasonClass != ClassForged {
		t.Errorf("reason = %q (%s), want %q (%s): a pinned issuer's signature that does not cover the bytes is the outcome that means stop",
			res.Reason, res.ReasonClass, ReasonSignatureInvalid, ClassForged)
	}

	// And deleting it is the same event: absent is a value, not a hole.
	stripped := *a
	stripped.DisplayName = ""
	res2, err := VerifyIdentity(&stripped, IdentityOptions{IssuerKeys: []ed25519.PublicKey{is.pub}, At: atNow()})
	if err != nil {
		t.Fatal(err)
	}
	if res2.Valid {
		t.Fatal("deleting a signed display_name must break the signature too")
	}
}

// TestIdentityDisplayNameAbsentAndEmptyAreOneState pins the encoding decision. An
// issuer that names no display name and an issuer that names an empty one are the
// same issuer saying the same thing: the artifact omits the key, the preimage
// writes field(""), and the two derive identical bytes. That is what keeps absent
// and empty from being confusable — there is one state, so there is nothing to
// confuse — and it is what makes the marshal/parse round trip safe, because a key
// JSON omits has to come back as bytes the signature still covers.
func TestIdentityDisplayNameAbsentAndEmptyAreOneState(t *testing.T) {
	is := newIssuer(t)
	a := makeIdentity(t, is) // built from a spec with no DisplayName at all

	b, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "display_name") {
		t.Errorf("an attestation with no display name must not carry the key:\n%s", b)
	}

	explicit := *a
	explicit.DisplayName = "" // the same state, spelled the other way
	if !bytes.Equal(IdentitySigningBytes(a), IdentitySigningBytes(&explicit)) {
		t.Error("absent and empty must derive the same preimage, or one artifact would have two signatures")
	}

	parsed, err := ParseIdentity(b)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.DisplayName != "" {
		t.Errorf("a missing display_name must parse as empty, got %q", parsed.DisplayName)
	}
	res, err := VerifyIdentity(parsed, IdentityOptions{IssuerKeys: []ed25519.PublicKey{is.pub}, At: atNow()})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("an attestation with no display name must still verify: %s / %s", res.Reason, res.Detail)
	}
	if res.DisplayName != "" {
		t.Errorf("DisplayName = %q, want empty", res.DisplayName)
	}
}

// v1Preimage rebuilds the identity/v1 signing bytes — the layout this format had
// before display_name existed. It is frozen here as a copy because protocol no
// longer produces it, and it is what an attestation issued on the morning of this
// change was signed over.
func v1Preimage(serial, subject, principal, principalType string, roles []string,
	issuedAt, expiresAt, algorithm, issuer string) []byte {
	var buf bytes.Buffer
	field := func(s string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		buf.Write(n[:])
		buf.WriteString(s)
	}
	field("netherchat/identity/v1")
	field(serial)
	field(subject)
	field(principal)
	field(principalType)
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(roles)))
	buf.Write(n[:])
	for _, r := range roles {
		field(r)
	}
	field(issuedAt)
	field(expiresAt)
	field(algorithm)
	field(issuer)
	return buf.Bytes()
}

// TestVerifyIdentityRejectsAPriorVersionArtifact is the version decision, held as
// a test rather than as a paragraph.
//
// Adding display_name changed the bytes an issuer signs, so an artifact issued
// under v1 cannot verify under this build. The only open question was what it
// should be TOLD. Leaving the tag at v1 would send a credential this authority
// really issued all the way to the signature check it was always going to fail,
// and hand back signature_invalid — class FORGED, the one outcome the format
// reserves for a security event. Moving the tag stops it at the version, where
// the answer is unsupported_version — class MALFORMED, whose operator instruction
// is "replace the file; check the issuer tool and the version", which is exactly
// what happened.
//
// So this test asserts the class as hard as it asserts the code: a stale
// credential must never be reported as an attack.
func TestVerifyIdentityRejectsAPriorVersionArtifact(t *testing.T) {
	is := newIssuer(t)
	old := &IdentityAttestation{
		Version:       "v1",
		Serial:        "acme-0001",
		Subject:       subjectFpr(t),
		Principal:     "rosa.alvarez@acme.example",
		PrincipalType: "person",
		Roles:         []string{"qa"},
		IssuedAt:      time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:     time.Now().UTC().Add(90 * 24 * time.Hour).Format(time.RFC3339),
		Algorithm:     AlgorithmEd25519,
		Issuer:        is.fpr,
	}
	sig := ed25519.Sign(is.priv, v1Preimage(old.Serial, old.Subject, old.Principal, old.PrincipalType,
		old.Roles, old.IssuedAt, old.ExpiresAt, old.Algorithm, old.Issuer))
	old = old.WithSignatures(map[string][]byte{is.fpr: sig}, map[string][]byte{is.fpr: is.pub})

	res, err := VerifyIdentity(old, IdentityOptions{IssuerKeys: []ed25519.PublicKey{is.pub}, At: atNow()})
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid {
		t.Fatal("a v1 artifact must not verify under v2 — the preimage changed")
	}
	if res.ReasonClass == ClassForged {
		t.Fatalf("a v1 artifact reported as %q (%s): a credential this authority really issued is being called an attack, which is what moving the version tag exists to prevent",
			res.Reason, res.ReasonClass)
	}
	if res.Reason != ReasonUnsupportedVersion || res.ReasonClass != ClassMalformed {
		t.Fatalf("reason = %q (%s), want %q (%s)", res.Reason, res.ReasonClass, ReasonUnsupportedVersion, ClassMalformed)
	}
	if !strings.Contains(res.Detail, "v1") || !strings.Contains(res.Detail, IdentityVersion) {
		t.Errorf("the detail must name both versions so an operator knows which file to replace: %q", res.Detail)
	}
}
