package attest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"
)

// makeRevocation builds a statement withdrawing the given serials, signed by is.
func makeRevocation(t *testing.T, is issuerKey, statementID string, number uint64, nextUpdate string, serials ...string) *RevocationStatement {
	t.Helper()
	revoked := make([]RevokedSerial, len(serials))
	for i, s := range serials {
		revoked[i] = RevokedSerial{Serial: s, RevokedAt: time.Now().UTC().Format(time.RFC3339), Reason: "key rotation"}
	}
	unsigned := NewRevocation(RevocationSpec{
		Issuer: is.fpr, StatementID: statementID, Number: number,
		NextUpdate: nextUpdate, Revoked: revoked,
	}, nil, nil)
	sig := ed25519.Sign(is.priv, RevocationSigningBytes(unsigned))
	return unsigned.WithSignatures(
		map[string][]byte{is.fpr: sig},
		map[string][]byte{is.fpr: is.pub},
	)
}

// TestVerifyRevocationValid proves the happy path and the strict round trip.
func TestVerifyRevocationValid(t *testing.T) {
	is := newIssuer(t)
	s := makeRevocation(t, is, "acme-2026-08-19", 41, "", "acme-0001")

	res, err := VerifyRevocation(s, []ed25519.PublicKey{is.pub})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("should verify: %s / %s", res.Reason, res.Detail)
	}
	if res.Serials != 1 || len(res.VerifiedBy) != 1 {
		t.Errorf("serials=%d verifiedBy=%v", res.Serials, res.VerifiedBy)
	}

	b, err := s.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseRevocation(b)
	if err != nil {
		t.Fatal(err)
	}
	rb, _ := back.Marshal()
	if !bytes.Equal(b, rb) {
		t.Error("a revocation statement must round-trip byte-for-byte")
	}
	if _, err := ParseRevocation([]byte(`{"netherchat_revocation":"v1","surprise":1}`)); err == nil {
		t.Error("ParseRevocation must reject unknown fields")
	}
}

// TestVerifyRevocationEntryOrderIsSigned proves the revoked list is covered by
// the signature in the order it is listed: reordering it breaks verification
// rather than quietly passing.
func TestVerifyRevocationEntryOrderIsSigned(t *testing.T) {
	is := newIssuer(t)
	s := makeRevocation(t, is, "acme-2026-08-19", 41, "", "acme-0001", "acme-0002")
	s.Revoked[0], s.Revoked[1] = s.Revoked[1], s.Revoked[0]

	res, err := VerifyRevocation(s, []ed25519.PublicKey{is.pub})
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid {
		t.Fatal("a reordered revocation list must not verify")
	}
	if res.Reason != ReasonSignatureInvalid {
		t.Errorf("Reason = %q, want %q", res.Reason, ReasonSignatureInvalid)
	}
}

// TestIdentityRevokedByCoveringStatement proves the end-to-end revocation path
// inside VerifyIdentity: a covering, verified statement that lists the serial
// makes the attestation invalid, classed lifecycle rather than forged.
func TestIdentityRevokedByCoveringStatement(t *testing.T) {
	is := newIssuer(t)
	a := makeIdentity(t, is)
	s := makeRevocation(t, is, "acme-2026-08-19", 41, "", a.Serial)

	res, err := VerifyIdentity(a, IdentityOptions{
		IssuerKeys:  []ed25519.PublicKey{is.pub},
		At:          atNow(),
		Revocations: []*RevocationStatement{s},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid {
		t.Fatal("a revoked serial must not verify")
	}
	if res.Reason != ReasonRevoked || res.ReasonClass != ClassLifecycle {
		t.Errorf("Reason=%q class=%q, want %q/%q", res.Reason, res.ReasonClass, ReasonRevoked, ClassLifecycle)
	}
	if len(res.Revocation) != 1 || !res.Revocation[0].Listed || !res.Revocation[0].CoversIssuer {
		t.Errorf("the check must be reported: %+v", res.Revocation)
	}
}

// TestIdentityRevocationFromAnotherAuthoritySaysNothing is the CoversIssuer
// rule. A statement from a different authority is not evidence about this
// serial, and must not clear it OR condemn it — it is recorded as consulted and
// not covering, which is the fact.
func TestIdentityRevocationFromAnotherAuthoritySaysNothing(t *testing.T) {
	is, other := newIssuer(t), newIssuer(t)
	a := makeIdentity(t, is)
	// The OTHER authority lists the same serial string. Serial uniqueness is
	// per-issuer, so this collision is legal and must not revoke anything.
	s := makeRevocation(t, other, "other-ca-7", 3, "", a.Serial)

	res, err := VerifyIdentity(a, IdentityOptions{
		IssuerKeys:  []ed25519.PublicKey{is.pub, other.pub},
		At:          atNow(),
		Revocations: []*RevocationStatement{s},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("a statement from another authority must not revoke this binding: %s", res.Reason)
	}
	if len(res.Revocation) != 1 {
		t.Fatalf("the statement must still be recorded as consulted: %+v", res.Revocation)
	}
	if res.Revocation[0].CoversIssuer || res.Revocation[0].Listed {
		t.Errorf("covers_issuer/listed = %v/%v, want false/false", res.Revocation[0].CoversIssuer, res.Revocation[0].Listed)
	}
}

// TestIdentityRevocationStaleIsReportedNotEnforced proves Stale is a fact and
// nothing more: whether a statement is fresh enough to act on is policy, and
// policy lives on the consumer side of this seam.
func TestIdentityRevocationStaleIsReportedNotEnforced(t *testing.T) {
	is := newIssuer(t)
	a := makeIdentity(t, is)
	past := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	s := makeRevocation(t, is, "acme-2026-08-01", 40, past, "some-other-serial")

	res, err := VerifyIdentity(a, IdentityOptions{
		IssuerKeys:  []ed25519.PublicKey{is.pub},
		At:          atNow(),
		Revocations: []*RevocationStatement{s},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("a stale statement must not change the verdict: %s", res.Reason)
	}
	if len(res.Revocation) != 1 || !res.Revocation[0].Stale {
		t.Errorf("stale must be reported: %+v", res.Revocation)
	}
}

// TestIdentityUnverifiableRevocationIsLoud proves that evidence which does not
// itself verify is a failure and not a shrug. A statement was handed to the
// verifier as a claim about an authority's intent; if it does not verify, saying
// nothing would be worse than saying no.
func TestIdentityUnverifiableRevocationIsLoud(t *testing.T) {
	is := newIssuer(t)
	a := makeIdentity(t, is)
	s := makeRevocation(t, is, "acme-2026-08-19", 41, "", "unrelated-serial")

	raw, err := base64.StdEncoding.DecodeString(s.Signatures[is.fpr])
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 0xff
	s.Signatures[is.fpr] = base64.StdEncoding.EncodeToString(raw)

	res, err := VerifyIdentity(a, IdentityOptions{
		IssuerKeys:  []ed25519.PublicKey{is.pub},
		At:          atNow(),
		Revocations: []*RevocationStatement{s},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid {
		t.Fatal("an unverifiable revocation statement must not be passed over")
	}
	if res.Reason != ReasonRevocationUnverifiable || res.ReasonClass != ClassForged {
		t.Errorf("Reason=%q class=%q, want %q/%q", res.Reason, res.ReasonClass, ReasonRevocationUnverifiable, ClassForged)
	}
}

// TestIdentityNoRevocationSuppliedIsNotACleanBill proves the shape that makes
// the difference visible: an empty Revocation slice means nothing was supplied,
// and a consumer that reads it as "not revoked" has made a policy decision that
// its own code will show.
func TestIdentityNoRevocationSuppliedIsNotACleanBill(t *testing.T) {
	is := newIssuer(t)
	a := makeIdentity(t, is)

	res, err := VerifyIdentity(a, IdentityOptions{IssuerKeys: []ed25519.PublicKey{is.pub}, At: atNow()})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("should verify: %s", res.Reason)
	}
	if len(res.Revocation) != 0 {
		t.Errorf("no statement was supplied, so no check was made: %+v", res.Revocation)
	}
}
