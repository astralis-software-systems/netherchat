package attest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// issuerKey is a test authority: a key plus its fingerprint.
type issuerKey struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	fpr  string
}

func newIssuer(t *testing.T) issuerKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return issuerKey{pub: pub, priv: priv, fpr: crypto.Fingerprint(pub)}
}

// subjectFpr mints a fresh key and returns only its fingerprint — the subject
// key never has to exist for an attestation to be about it.
func subjectFpr(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return crypto.Fingerprint(pub)
}

// signBy signs an unsigned attestation with each issuer and attaches the maps.
func signBy(a *IdentityAttestation, issuers ...issuerKey) *IdentityAttestation {
	sigs := map[string][]byte{}
	keys := map[string][]byte{}
	pre := IdentitySigningBytes(a)
	for _, is := range issuers {
		sigs[is.fpr] = ed25519.Sign(is.priv, pre)
		keys[is.fpr] = is.pub
	}
	return a.WithSignatures(sigs, keys)
}

// makeIdentity builds a valid attestation signed by one issuer, with a window
// that contains `now` by a wide margin.
func makeIdentity(t *testing.T, is issuerKey) *IdentityAttestation {
	t.Helper()
	spec := IdentitySpec{
		Serial:        "acme-0001",
		Subject:       subjectFpr(t),
		Principal:     "rosa.alvarez@acme.example",
		PrincipalType: "person",
		Roles:         []string{"technical", "qa"},
		ExpiresAt:     time.Now().UTC().Add(90 * 24 * time.Hour).Format(time.RFC3339),
		Algorithm:     AlgorithmEd25519,
		Issuer:        is.fpr,
	}
	return signBy(NewIdentityAttestation(spec, nil, nil), is)
}

func atNow() time.Time { return time.Now().UTC() }

// TestVerifyIdentityValid proves the happy path and that the result echoes the
// inputs a reader needs to re-derive the verdict.
func TestVerifyIdentityValid(t *testing.T) {
	is := newIssuer(t)
	a := makeIdentity(t, is)

	res, err := VerifyIdentity(a, IdentityOptions{IssuerKeys: []ed25519.PublicKey{is.pub}, At: atNow()})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("should verify: %s / %s", res.Reason, res.Detail)
	}
	if res.Reason != "" || res.ReasonClass != "" {
		t.Errorf("Reason/ReasonClass must be empty when Valid: %q / %q", res.Reason, res.ReasonClass)
	}
	if len(res.VerifiedBy) != 1 || res.VerifiedBy[0] != is.fpr {
		t.Errorf("VerifiedBy = %v, want [%s]", res.VerifiedBy, is.fpr)
	}
	if res.EvaluatedAt == "" {
		t.Error("EvaluatedAt must echo opts.At so a result is self-describing")
	}
	if res.Principal != a.Principal || res.Serial != a.Serial {
		t.Error("result must carry the artifact's own fields")
	}
}

// TestVerifyIdentityRolesAreSortedAndSigned proves the constructor sorts roles
// and that reordering a parsed artifact breaks the signature rather than quietly
// verifying — role ORDER is signed, and nothing re-sorts on the verify side.
func TestVerifyIdentityRolesAreSortedAndSigned(t *testing.T) {
	is := newIssuer(t)
	a := makeIdentity(t, is)
	if a.Roles[0] != "qa" || a.Roles[1] != "technical" {
		t.Fatalf("constructor must sort roles, got %v", a.Roles)
	}

	a.Roles[0], a.Roles[1] = a.Roles[1], a.Roles[0]
	res, err := VerifyIdentity(a, IdentityOptions{IssuerKeys: []ed25519.PublicKey{is.pub}, At: atNow()})
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid {
		t.Fatal("a reordered role list must not verify")
	}
	if res.Reason != ReasonSignatureInvalid || res.ReasonClass != ClassForged {
		t.Errorf("Reason=%q class=%q, want %q/%q", res.Reason, res.ReasonClass, ReasonSignatureInvalid, ClassForged)
	}
}

// TestVerifyIdentityNoIssuerPinnedIsInert is the standalone-inert row: with no
// key supplied the answer is a legible outcome about the CALLER's setup, never
// an error and never a verdict about the subject.
func TestVerifyIdentityNoIssuerPinnedIsInert(t *testing.T) {
	is := newIssuer(t)
	a := makeIdentity(t, is)

	res, err := VerifyIdentity(a, IdentityOptions{At: atNow()})
	if err != nil {
		t.Fatalf("no pin is a legal call, not an error: %v", err)
	}
	if res.Valid {
		t.Fatal("nothing was checked, so nothing is valid")
	}
	if res.Reason != ReasonNoIssuerPinned {
		t.Errorf("Reason = %q, want %q", res.Reason, ReasonNoIssuerPinned)
	}
	if res.ReasonClass != ClassUnconfigured {
		t.Errorf("ReasonClass = %q, want %q — an unconfigured verifier must never render as a credential failure",
			res.ReasonClass, ClassUnconfigured)
	}
}

// TestVerifyIdentityZeroAtIsAnError pins the err/Reason rule at the one place it
// is easiest to get wrong. A caller who omits At has made a broken CALL;
// answering "not yet valid" would put a sentence in the issuer's mouth and would
// look identical on screen to a genuinely premature credential.
func TestVerifyIdentityZeroAtIsAnError(t *testing.T) {
	is := newIssuer(t)
	a := makeIdentity(t, is)

	res, err := VerifyIdentity(a, IdentityOptions{IssuerKeys: []ed25519.PublicKey{is.pub}})
	if err == nil {
		t.Fatalf("a zero At must be an error, got result %+v", res)
	}
	if res != nil {
		t.Error("an error must carry a nil result, so a caller cannot read a verdict off it")
	}
	if !strings.Contains(err.Error(), "opts.At") {
		t.Errorf("the error must name the parameter: %v", err)
	}
	// And it is checked FIRST, before anything about the artifact is read: a nil
	// attestation with a zero At is still an error, not a nil dereference.
	if _, err := VerifyIdentity(nil, IdentityOptions{}); err == nil {
		t.Error("a nil attestation must be an error")
	}
}

// TestVerifyIdentityWindowContainment proves verification asks whether the
// window CONTAINED the evaluation time, in both directions — and that a
// credential which has since expired still verifies for a time it covered, which
// is what makes an old record re-verifiable forever.
func TestVerifyIdentityWindowContainment(t *testing.T) {
	is := newIssuer(t)
	a := makeIdentity(t, is)
	notBefore, err := time.Parse(time.RFC3339, a.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	notAfter, err := time.Parse(time.RFC3339, a.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	keys := []ed25519.PublicKey{is.pub}

	cases := []struct {
		name   string
		at     time.Time
		valid  bool
		reason IdentityReason
	}{
		{"before the window", notBefore.Add(-time.Hour), false, ReasonNotYetValid},
		{"on the opening edge", notBefore, true, ""},
		{"inside", notBefore.Add(24 * time.Hour), true, ""},
		{"on the closing edge", notAfter, true, ""},
		{"after the window", notAfter.Add(time.Second), false, ReasonExpired},
		{"long after — a record made while it was live", notAfter.Add(5 * 365 * 24 * time.Hour), false, ReasonExpired},
	}
	for _, tc := range cases {
		res, err := VerifyIdentity(a, IdentityOptions{IssuerKeys: keys, At: tc.at})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if res.Valid != tc.valid {
			t.Errorf("%s: Valid = %v, want %v (%s)", tc.name, res.Valid, tc.valid, res.Reason)
		}
		if res.Reason != tc.reason {
			t.Errorf("%s: Reason = %q, want %q", tc.name, res.Reason, tc.reason)
		}
		if tc.reason != "" && res.ReasonClass != ClassLifecycle {
			t.Errorf("%s: class = %q, want %q", tc.name, res.ReasonClass, ClassLifecycle)
		}
	}
}

// TestVerifyIdentityRotationIsOrderIndependent is the reason the signature loop
// collects instead of short-circuiting.
//
// An attestation carries signatures from an outgoing and an incoming authority,
// and the outgoing one is corrupt — a truncated copy, a bad transfer, an issuer
// tool bug. It must verify whichever order the caller lists their pinned keys
// in. A short-circuiting loop verified it one way round and rejected it the
// other, which broke exactly the feature the plural signature maps exist for.
func TestVerifyIdentityRotationIsOrderIndependent(t *testing.T) {
	oldIs, newIs := newIssuer(t), newIssuer(t)
	spec := IdentitySpec{
		Serial:        "acme-0002",
		Subject:       subjectFpr(t),
		Principal:     "rosa.alvarez@acme.example",
		PrincipalType: "person",
		Roles:         []string{"qa"},
		ExpiresAt:     time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339),
		Algorithm:     AlgorithmEd25519,
		Issuer:        newIs.fpr,
	}
	a := signBy(NewIdentityAttestation(spec, nil, nil), oldIs, newIs)

	// Corrupt the OUTGOING authority's signature only.
	raw, err := base64.StdEncoding.DecodeString(a.Signatures[oldIs.fpr])
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 0xff
	a.Signatures[oldIs.fpr] = base64.StdEncoding.EncodeToString(raw)

	orders := [][]ed25519.PublicKey{
		{oldIs.pub, newIs.pub},
		{newIs.pub, oldIs.pub},
	}
	for i, keys := range orders {
		res, err := VerifyIdentity(a, IdentityOptions{IssuerKeys: keys, At: atNow()})
		if err != nil {
			t.Fatal(err)
		}
		if !res.Valid {
			t.Fatalf("order %d: rotation must verify on the good signature regardless of pin order: %s / %s",
				i, res.Reason, res.Detail)
		}
		if len(res.VerifiedBy) != 1 || res.VerifiedBy[0] != newIs.fpr {
			t.Errorf("order %d: VerifiedBy = %v, want only the incoming authority %s", i, res.VerifiedBy, newIs.fpr)
		}
		if !strings.Contains(res.Detail, string(ReasonSignatureInvalid)) {
			t.Errorf("order %d: the per-key failure must still be reported in Detail, got %q", i, res.Detail)
		}
	}
}

// TestVerifyIdentityFailurePrecedenceIsDeterministic proves the reported reason
// is the most severe outcome and not whichever key came first. signature_invalid
// wins because it is the only outcome classed forged.
func TestVerifyIdentityFailurePrecedenceIsDeterministic(t *testing.T) {
	forged, unreadable := newIssuer(t), newIssuer(t)
	spec := IdentitySpec{
		Serial:        "acme-0003",
		Subject:       subjectFpr(t),
		Principal:     "svc-deploy@acme.example",
		PrincipalType: "service",
		Roles:         []string{"deploy"},
		ExpiresAt:     time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
		Algorithm:     AlgorithmEd25519,
		Issuer:        forged.fpr,
	}
	a := signBy(NewIdentityAttestation(spec, nil, nil), forged, unreadable)

	// One signature that does not verify, one that is not even base64.
	raw, err := base64.StdEncoding.DecodeString(a.Signatures[forged.fpr])
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 0xff
	a.Signatures[forged.fpr] = base64.StdEncoding.EncodeToString(raw)
	a.Signatures[unreadable.fpr] = "not base64 at all!!"

	for i, keys := range [][]ed25519.PublicKey{
		{forged.pub, unreadable.pub},
		{unreadable.pub, forged.pub},
	} {
		res, err := VerifyIdentity(a, IdentityOptions{IssuerKeys: keys, At: atNow()})
		if err != nil {
			t.Fatal(err)
		}
		if res.Reason != ReasonSignatureInvalid || res.ReasonClass != ClassForged {
			t.Errorf("order %d: Reason=%q class=%q, want %q/%q — the forged outcome outranks the unreadable one",
				i, res.Reason, res.ReasonClass, ReasonSignatureInvalid, ClassForged)
		}
		if !strings.Contains(res.Detail, string(ReasonSignatureMalformed)) {
			t.Errorf("order %d: Detail must report every per-key outcome, got %q", i, res.Detail)
		}
	}
}

// TestVerifyIdentityUnanchoredIsNotAFailure proves that an attestation from an
// authority this verifier has not pinned is classed unanchored, not forged. It
// is a statement about the trust relationship, not about the subject, and a
// screen that renders it red is making a claim about a person nobody checked.
func TestVerifyIdentityUnanchoredIsNotAFailure(t *testing.T) {
	is, stranger := newIssuer(t), newIssuer(t)
	a := makeIdentity(t, is)

	res, err := VerifyIdentity(a, IdentityOptions{IssuerKeys: []ed25519.PublicKey{stranger.pub}, At: atNow()})
	if err != nil {
		t.Fatal(err)
	}
	if res.Reason != ReasonNoPinnedIssuerVerified || res.ReasonClass != ClassUnanchored {
		t.Errorf("Reason=%q class=%q, want %q/%q", res.Reason, res.ReasonClass, ReasonNoPinnedIssuerVerified, ClassUnanchored)
	}
}

// TestVerifyIdentityEmbeddedKeyIsCheckedNeverTrusted proves the two halves of
// the SignerKeys contract: a self-signed artifact whose issuer the caller has
// not pinned never verifies, and an embedded key that does not hash to its own
// fingerprint is reported loudly while changing no verdict on its own.
func TestVerifyIdentityEmbeddedKeyIsCheckedNeverTrusted(t *testing.T) {
	is := newIssuer(t)
	a := makeIdentity(t, is)

	// Half one: the artifact carries a perfectly good key and signature. With no
	// pin it is still not valid — the embedded key is never a trust anchor.
	res, err := VerifyIdentity(a, IdentityOptions{At: atNow()})
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid {
		t.Fatal("an artifact must never verify on the key it carries")
	}

	// Half two: swap the embedded key for a different one under the same
	// fingerprint. The caller's pinned key still verifies the signature, but the
	// artifact is internally inconsistent and that is worth saying.
	other := newIssuer(t)
	a.SignerKeys[is.fpr] = base64.StdEncoding.EncodeToString(other.pub)
	res, err = VerifyIdentity(a, IdentityOptions{IssuerKeys: []ed25519.PublicKey{is.pub}, At: atNow()})
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid {
		t.Fatal("a mismatched embedded key must be reported, not passed over")
	}
	if res.Reason != ReasonSignerKeyMismatch {
		t.Errorf("Reason = %q, want %q", res.Reason, ReasonSignerKeyMismatch)
	}
	if res.ReasonClass != ClassMalformed {
		t.Errorf("class = %q, want %q — it changes no verdict, so it is not the class that means stop",
			res.ReasonClass, ClassMalformed)
	}
}

// TestVerifyIdentityStructuralReasons walks every malformed_* outcome, so each
// constant is reachable and each is classed malformed.
func TestVerifyIdentityStructuralReasons(t *testing.T) {
	is := newIssuer(t)
	keys := []ed25519.PublicKey{is.pub}

	cases := []struct {
		name   string
		mutate func(a *IdentityAttestation)
		reason IdentityReason
		class  IdentityReasonClass
	}{
		{"version", func(a *IdentityAttestation) { a.Version = "v2" }, ReasonUnsupportedVersion, ClassMalformed},
		{"algorithm", func(a *IdentityAttestation) { a.Algorithm = "p256" }, ReasonUnsupportedAlgorithm, ClassMalformed},
		{"serial", func(a *IdentityAttestation) { a.Serial = "" }, ReasonMalformedSerial, ClassMalformed},
		{"subject empty", func(a *IdentityAttestation) { a.Subject = "" }, ReasonMalformedSubject, ClassMalformed},
		{"subject dialect", func(a *IdentityAttestation) { a.Subject = "MD5:ab:cd" }, ReasonMalformedSubject, ClassMalformed},
		{"subject truncated", func(a *IdentityAttestation) { a.Subject = "SHA256:short" }, ReasonMalformedSubject, ClassMalformed},
		{"principal", func(a *IdentityAttestation) { a.Principal = "" }, ReasonMalformedPrincipal, ClassMalformed},
		{"principal type", func(a *IdentityAttestation) { a.PrincipalType = "" }, ReasonMalformedPrincipalType, ClassMalformed},
		{"roles empty", func(a *IdentityAttestation) { a.Roles = nil }, ReasonMalformedRoles, ClassMalformed},
		{"role empty", func(a *IdentityAttestation) { a.Roles = []string{"qa", ""} }, ReasonMalformedRoles, ClassMalformed},
		{"role duplicated", func(a *IdentityAttestation) { a.Roles = []string{"qa", "qa"} }, ReasonMalformedRoles, ClassMalformed},
		{"issuer", func(a *IdentityAttestation) { a.Issuer = "acme-ca" }, ReasonMalformedIssuer, ClassMalformed},
		{"issued_at", func(a *IdentityAttestation) { a.IssuedAt = "yesterday" }, ReasonMalformedTime, ClassMalformed},
		{"expires_at", func(a *IdentityAttestation) { a.ExpiresAt = "soon" }, ReasonMalformedTime, ClassMalformed},
		{"inverted window", func(a *IdentityAttestation) {
			a.ExpiresAt = "2020-01-01T00:00:00Z"
		}, ReasonInvertedWindow, ClassMalformed},
		{"issuer did not sign", func(a *IdentityAttestation) {
			delete(a.Signatures, a.Issuer)
		}, ReasonIssuerDidNotSign, ClassMalformed},
		{"signer key malformed", func(a *IdentityAttestation) {
			for fpr := range a.SignerKeys {
				a.SignerKeys[fpr] = "%%%"
			}
		}, ReasonSignerKeyMalformed, ClassMalformed},
		{"signature malformed", func(a *IdentityAttestation) {
			for fpr := range a.Signatures {
				a.Signatures[fpr] = "%%%"
			}
		}, ReasonSignatureMalformed, ClassMalformed},
	}

	for _, tc := range cases {
		a := makeIdentity(t, is)
		tc.mutate(a)
		res, err := VerifyIdentity(a, IdentityOptions{IssuerKeys: keys, At: atNow()})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if res.Valid {
			t.Errorf("%s: must not verify", tc.name)
			continue
		}
		if res.Reason != tc.reason {
			t.Errorf("%s: Reason = %q, want %q", tc.name, res.Reason, tc.reason)
		}
		if res.ReasonClass != tc.class {
			t.Errorf("%s: class = %q, want %q", tc.name, res.ReasonClass, tc.class)
		}
	}
}

// TestIdentityRoundTripStrict proves the artifact round-trips through the strict
// parser and that the verify result is itself clean JSON.
func TestIdentityRoundTripStrict(t *testing.T) {
	is := newIssuer(t)
	a := makeIdentity(t, is)

	b, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseIdentity(b)
	if err != nil {
		t.Fatalf("round-trip parse failed: %v", err)
	}
	rb, err := back.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, rb) {
		t.Error("marshal must be stable across a parse round trip: the record carrier stores these exact bytes")
	}

	res, _ := VerifyIdentity(a, IdentityOptions{IssuerKeys: []ed25519.PublicKey{is.pub}, At: atNow()})
	j, _ := json.Marshal(res)
	dec := json.NewDecoder(bytes.NewReader(j))
	dec.DisallowUnknownFields()
	var decoded IdentityResult
	if err := dec.Decode(&decoded); err != nil {
		t.Fatalf("verify result does not decode strictly: %v", err)
	}
}

// TestParseIdentityRejectsUnknownAndTrailing proves both halves of the strict
// parser: an extra key and a second JSON document after the first.
func TestParseIdentityRejectsUnknownAndTrailing(t *testing.T) {
	if _, err := ParseIdentity([]byte(`{"netherchat_identity":"v1","surprise":true}`)); err == nil {
		t.Error("ParseIdentity must reject unknown fields")
	}
	if _, err := ParseIdentity([]byte(`{"netherchat_identity":"v1"}{"netherchat_identity":"v1"}`)); err == nil {
		t.Error("ParseIdentity must reject trailing data")
	}
}

// TestIdentitySigningBytesWrapperDelegates proves the attest wrapper writes no
// bytes of its own: it is a delegation to the protocol layout, so an external
// issuer tool reaching the preimage through the façade gets the same bytes a
// verifier reconstructs.
func TestIdentitySigningBytesWrapperDelegates(t *testing.T) {
	is := newIssuer(t)
	a := makeIdentity(t, is)
	want := protocol.IdentitySigningBytes(a.Serial, a.Subject, a.Principal, a.PrincipalType,
		a.Roles, a.IssuedAt, a.ExpiresAt, a.Algorithm, a.Issuer)
	if !bytes.Equal(IdentitySigningBytes(a), want) {
		t.Fatal("the attest wrapper must produce exactly the protocol layout")
	}
	if IdentitySigningBytes(nil) != nil {
		t.Error("a nil attestation has no preimage")
	}
}

// TestNewIdentityAttestationIsTheOnlyClock proves the constructor stamps
// issued_at and that WithSignatures leaves it alone — signing a preimage built
// from one moment and shipping an artifact stamped with another would produce a
// file that never verifies.
func TestNewIdentityAttestationIsTheOnlyClock(t *testing.T) {
	is := newIssuer(t)
	unsigned := NewIdentityAttestation(IdentitySpec{
		Serial: "s", Subject: subjectFpr(t), Principal: "p", PrincipalType: "person",
		Roles: []string{"qa"}, ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		Algorithm: AlgorithmEd25519, Issuer: is.fpr,
	}, nil, nil)
	if unsigned.IssuedAt == "" {
		t.Fatal("the constructor must stamp issued_at")
	}
	signed := signBy(unsigned, is)
	if signed.IssuedAt != unsigned.IssuedAt {
		t.Fatal("WithSignatures must not move issued_at — it is inside the signed bytes")
	}
	res, err := VerifyIdentity(signed, IdentityOptions{IssuerKeys: []ed25519.PublicKey{is.pub}, At: atNow()})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("the two-step signing flow must produce a verifying artifact: %s", res.Reason)
	}
}

// TestVerifyIdentityRejectsWrongSizedPinnedKey proves a bad pinned key is a call
// error rather than a verdict, so a consumer never has to tell "bad attestation"
// from "bad call" by reading a message.
func TestVerifyIdentityRejectsWrongSizedPinnedKey(t *testing.T) {
	is := newIssuer(t)
	a := makeIdentity(t, is)
	_, err := VerifyIdentity(a, IdentityOptions{
		IssuerKeys: []ed25519.PublicKey{is.pub, make([]byte, 7)},
		At:         atNow(),
	})
	if err == nil {
		t.Fatal("a pinned key of the wrong size must be an error")
	}
}

// TestClassOfIsTotal proves every outcome code maps to a class, and that the
// empty code maps to the empty class so "empty exactly when Valid" holds for
// both fields together.
func TestClassOfIsTotal(t *testing.T) {
	all := []IdentityReason{
		ReasonNoIssuerPinned, ReasonNoPinnedIssuerVerified, ReasonNotYetValid, ReasonExpired,
		ReasonRevoked, ReasonUnsupportedVersion, ReasonUnsupportedAlgorithm, ReasonMalformedSerial,
		ReasonMalformedSubject, ReasonMalformedPrincipal, ReasonMalformedPrincipalType,
		ReasonMalformedRoles, ReasonMalformedIssuer, ReasonMalformedTime, ReasonInvertedWindow,
		ReasonIssuerDidNotSign, ReasonSignerKeyMalformed, ReasonSignerKeyMismatch,
		ReasonSignatureMalformed, ReasonSignatureInvalid, ReasonRevocationUnverifiable,
	}
	if len(all) != 21 {
		t.Fatalf("the outcome set has %d codes; update this test when it changes", len(all))
	}
	for _, r := range all {
		if ClassOf(r) == "" {
			t.Errorf("%q has no class", r)
		}
	}
	if ClassOf("") != "" {
		t.Error("the empty code must map to the empty class")
	}
	if ClassOf("something-this-build-does-not-know") != ClassMalformed {
		t.Error("an unrecognized code must class as malformed, which is the safe default")
	}
}
