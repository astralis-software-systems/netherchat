package attest

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// displaySubject is the fingerprint every fixture below is about, so the join
// IdentityDisplayFor makes has something to succeed against. The mismatch case
// is its own test.
const displaySubject = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// D-I HAS THREE VERIFIED PATHS AND THE THIRD IS THE ONE THAT GETS COLLAPSED.
//
// An issuer may sign a binding and name no display name. DisplayName is
// optional and empty is a legal, signed value (§1.1, §2.1: an absent and an
// empty name are one state and sign as eight zero bytes). Falling back to the
// principal there is not "we could not verify this" — the credential verified;
// the authority simply named no name. Rendering it like the unattested case
// would erase the difference between "an authority signed this identifier" and
// "the sender typed this string", which is the whole of what D-I exists to
// keep apart.

func displayIssuer(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("issuer key: %v", err)
	}
	return pub, priv, crypto.Fingerprint(pub)
}

// signedBinding builds a valid attestation about subject with the given display
// name (which may be empty).
func signedBinding(t *testing.T, principal, displayName string) (*IdentityAttestation, ed25519.PublicKey) {
	t.Helper()
	pub, priv, fpr := displayIssuer(t)
	unsigned := NewIdentityAttestation(IdentitySpec{
		Serial:        "acme-0007",
		Subject:       "SHA256:" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Principal:     principal,
		DisplayName:   displayName,
		PrincipalType: "person",
		Roles:         []string{"incident-commander"},
		ExpiresAt:     time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
		Algorithm:     AlgorithmEd25519,
		Issuer:        fpr,
	}, nil, nil)
	return unsigned.WithSignatures(
		map[string][]byte{fpr: ed25519.Sign(priv, IdentitySigningBytes(unsigned))},
		map[string][]byte{fpr: pub},
	), pub
}

func verifyNow(t *testing.T, a *IdentityAttestation, keys ...ed25519.PublicKey) *IdentityResult {
	t.Helper()
	res, err := VerifyIdentity(a, IdentityOptions{IssuerKeys: keys, At: time.Now().UTC()})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return res
}

// TestIdentityDisplayThreePaths walks D-I's rows on the credential axis, with
// the third one asserted as the VERIFIED state it is.
func TestIdentityDisplayThreePaths(t *testing.T) {
	named, namedKey := signedBinding(t, "rosa.alvarez@acme.example", "Rosa Alvarez")
	unnamed, unnamedKey := signedBinding(t, "svc-deploybot@acme.example", "")

	for _, tc := range []struct {
		what      string
		asserted  string
		carried   *IdentityAttestation
		res       *IdentityResult
		wantState IdentityDisplayState
		wantName  string
		wantMark  string
	}{
		{
			what:      "issuer-attested, with a display name",
			asserted:  "rosa",
			carried:   named,
			res:       verifyNow(t, named, namedKey),
			wantState: IdentityDisplayVerifiedNamed,
			wantName:  "Rosa Alvarez",
			wantMark:  "◆",
		},
		{
			what:      "issuer-attested, no display name — the third verified path",
			asserted:  "deploybot",
			carried:   unnamed,
			res:       verifyNow(t, unnamed, unnamedKey),
			wantState: IdentityDisplayVerifiedUnnamed,
			wantName:  "svc-deploybot@acme.example",
			wantMark:  "◆",
		},
		{
			what:      "a credential arrived and nothing checked it",
			asserted:  "rosa",
			carried:   named,
			res:       nil,
			wantState: IdentityDisplayCarried,
			wantName:  "rosa",
			wantMark:  "◇",
		},
		{
			what:      "no credential at all",
			asserted:  "rosa",
			carried:   nil,
			res:       nil,
			wantState: IdentityDisplayAsserted,
			wantName:  "rosa",
			wantMark:  "",
		},
	} {
		got := IdentityDisplayFor(tc.asserted, displaySubject, tc.carried, tc.res)
		if got.State != tc.wantState {
			t.Errorf("%s: state = %q, want %q", tc.what, got.State, tc.wantState)
		}
		if got.Name != tc.wantName {
			t.Errorf("%s: name = %q, want %q", tc.what, got.Name, tc.wantName)
		}
		if mark := IdentityDisplayMark(got.State); mark != tc.wantMark {
			t.Errorf("%s: mark = %q, want %q", tc.what, mark, tc.wantMark)
		}
	}
}

// TestIdentityDisplayNeverPromotesAnUncheckedClaim is the guard the whole
// decision rests on: a credential a surface could not check must not put its
// display name where the person's name goes, however well-formed it is. A
// self-issued artifact naming "Chief Executive" renders the handle the sender
// chose, with the ◇ that says there is a claim nobody checked.
func TestIdentityDisplayNeverPromotesAnUncheckedClaim(t *testing.T) {
	forged, realKey := signedBinding(t, "ceo@acme.example", "Chief Executive")
	otherKey, _, _ := displayIssuer(t)

	for _, tc := range []struct {
		what string
		res  *IdentityResult
	}{
		{"nobody pinned an issuer", nil},
		{"no issuer pinned, stated", verifyNow(t, forged)},
		{"a pinned issuer that did not sign it", verifyNow(t, forged, otherKey)},
	} {
		got := IdentityDisplayFor("mallory", displaySubject, forged, tc.res)
		if got.Name != "mallory" {
			t.Errorf("%s: rendered %q where the asserted name belongs", tc.what, got.Name)
		}
		if got.State != IdentityDisplayCarried {
			t.Errorf("%s: state = %q, want %q", tc.what, got.State, IdentityDisplayCarried)
		}
		if IdentityDisplayMark(got.State) == IdentityDisplayMark(IdentityDisplayVerifiedNamed) {
			t.Errorf("%s: drew the verified mark", tc.what)
		}
	}

	// The control: the same artifact against the key that DID sign it.
	ok := IdentityDisplayFor("mallory", displaySubject, forged, verifyNow(t, forged, realKey))
	if ok.State != IdentityDisplayVerifiedNamed || ok.Name != "Chief Executive" {
		t.Fatalf("with the signing key pinned the binding must verify; got %+v", ok)
	}
}

// TestIdentityDisplayLifecycleIsNotVerified: an expired or revoked credential is
// a lifecycle outcome, not a verified one. It carries; it does not name.
func TestIdentityDisplayLifecycleIsNotVerified(t *testing.T) {
	pub, priv, fpr := displayIssuer(t)
	unsigned := NewIdentityAttestation(IdentitySpec{
		Serial:        "acme-0008",
		Subject:       "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Principal:     "rosa.alvarez@acme.example",
		DisplayName:   "Rosa Alvarez",
		PrincipalType: "person",
		Roles:         []string{"incident-commander"},
		ExpiresAt:     time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		Algorithm:     AlgorithmEd25519,
		Issuer:        fpr,
	}, nil, nil)
	lapsed := unsigned.WithSignatures(
		map[string][]byte{fpr: ed25519.Sign(priv, IdentitySigningBytes(unsigned))},
		map[string][]byte{fpr: pub},
	)
	res := verifyNow(t, lapsed, pub)
	if res.Valid {
		t.Fatal("the fixture is not expired; this test would prove nothing")
	}
	got := IdentityDisplayFor("rosa", displaySubject, lapsed, res)
	if got.State != IdentityDisplayCarried || got.Name != "rosa" {
		t.Errorf("an expired credential rendered as %+v, want the asserted name and the carried state", got)
	}
}

// TestIdentityDisplayDetailNamesTheAbsence: the reason a surface has nothing
// verified to show is available to a detail line, without being dressed as a
// finding about the person (ClassOf's rendering rule).
func TestIdentityDisplayDetailNamesTheAbsence(t *testing.T) {
	named, key := signedBinding(t, "rosa.alvarez@acme.example", "Rosa Alvarez")

	nothingPinned := IdentityDisplayFor("rosa", displaySubject, named, verifyNow(t, named))
	if nothingPinned.Reason != ReasonNoIssuerPinned || nothingPinned.ReasonClass != ClassUnconfigured {
		t.Errorf("with no issuer pinned: reason %q/%q, want %q/%q",
			nothingPinned.Reason, nothingPinned.ReasonClass, ReasonNoIssuerPinned, ClassUnconfigured)
	}
	if nothingPinned.Principal != "rosa.alvarez@acme.example" {
		t.Errorf("the carried principal is unavailable to a detail line: %+v", nothingPinned)
	}
	if nothingPinned.Issuer == "" {
		t.Errorf("the named issuer is unavailable to a detail line: %+v", nothingPinned)
	}

	verified := IdentityDisplayFor("rosa", displaySubject, named, verifyNow(t, named, key))
	if verified.Reason != "" || verified.ReasonClass != "" {
		t.Errorf("a verified binding carries a reason: %+v", verified)
	}
}

// TestIdentityDisplayHandlesAnUnparsedCarrier: a surface holding bytes it could
// not parse is in the carried state, not the asserted one — something arrived,
// and saying otherwise would hide it.
func TestIdentityDisplayHandlesAnUnparsedCarrier(t *testing.T) {
	got := IdentityDisplayForBytes("rosa", displaySubject, []byte("{not json"), nil)
	if got.State != IdentityDisplayCarried {
		t.Errorf("unparseable carrier: state = %q, want %q", got.State, IdentityDisplayCarried)
	}
	if got.Name != "rosa" {
		t.Errorf("unparseable carrier: name = %q, want the asserted name", got.Name)
	}
	if got.Detail == "" {
		t.Error("unparseable carrier: no detail explaining why nothing could be read")
	}
	if none := IdentityDisplayForBytes("rosa", displaySubject, nil, nil); none.State != IdentityDisplayAsserted {
		t.Errorf("nil carrier: state = %q, want %q", none.State, IdentityDisplayAsserted)
	}
}

// AN ATTESTATION IS NOT A SECRET, SO POSSESSION OF ONE PROVES NOTHING.
//
// §2.3 says it in as many words: the artifact grants nothing and is safe to
// hand around. Which means anyone who has ever seen Rosa's identity.json can
// attach it to their own key — a hostile relay rewriting a Member, a peer
// building their own Hello. VerifyIdentity answers "did this issuer sign this
// statement about subject X"; it does not and cannot answer "is X the key in
// front of me". Nothing joins the two but the caller.
//
// Without that join, the strongest state in the vocabulary is forgeable by
// copying a public file, which would make ◆ worth less than the ✓ it was
// carefully distinguished from.
func TestIdentityDisplayRefusesACredentialAboutAnotherKey(t *testing.T) {
	const rosaKey = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	const mallorysKey = "SHA256:MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM"

	rosa, key := signedBinding(t, "rosa.alvarez@acme.example", "Rosa Alvarez")
	if rosa.Subject != rosaKey && rosaKey != displaySubject {
		t.Fatalf("fixture subject = %q, want %q", rosa.Subject, rosaKey)
	}
	res := verifyNow(t, rosa, key)
	if !res.Valid {
		t.Fatal("the fixture does not verify; this test would prove nothing")
	}

	// The control: attached to the key it is about, it is the verified state.
	ok := IdentityDisplayFor("rosa", rosaKey, rosa, res)
	if ok.State != IdentityDisplayVerifiedNamed || ok.Name != "Rosa Alvarez" {
		t.Fatalf("rosa's own credential on rosa's own key rendered as %+v", ok)
	}

	// Replayed onto another key, with the SAME valid verification result.
	stolen := IdentityDisplayFor("mallory", mallorysKey, rosa, res)
	if stolen.State != IdentityDisplayCarried {
		t.Errorf("a credential about another key rendered as %q", stolen.State)
	}
	if stolen.Name != "mallory" {
		t.Errorf("a credential about another key put %q where the name goes", stolen.Name)
	}
	if stolen.Reason != ReasonSubjectMismatch {
		t.Errorf("reason = %q, want %q — a consumer has to be able to branch on this",
			stolen.Reason, ReasonSubjectMismatch)
	}
	if stolen.Detail == "" || !containsBoth(stolen.Detail, rosaKey, mallorysKey) {
		t.Errorf("the detail does not name both keys, so nobody can act on it: %q", stolen.Detail)
	}
}

// TestIdentityDisplayWithNoKeyToBindToCannotVerify: a caller that does not say
// which key it is rendering has not made the join, and an unjoined credential
// cannot be the verified state however well it verified.
func TestIdentityDisplayWithNoKeyToBindToCannotVerify(t *testing.T) {
	rosa, key := signedBinding(t, "rosa.alvarez@acme.example", "Rosa Alvarez")
	got := IdentityDisplayFor("rosa", "", rosa, verifyNow(t, rosa, key))
	if got.State != IdentityDisplayCarried {
		t.Errorf("state = %q with no subject fingerprint supplied, want %q", got.State, IdentityDisplayCarried)
	}
	if got.Reason != ReasonSubjectMismatch {
		t.Errorf("reason = %q, want %q", got.Reason, ReasonSubjectMismatch)
	}
}

func containsBoth(s, a, b string) bool {
	return len(s) > 0 && indexOf(s, a) >= 0 && indexOf(s, b) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
