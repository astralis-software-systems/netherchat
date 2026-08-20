package app

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

// WHAT AN OPERATOR TYPES WHEN THE RENDERED NAME AND THE ADDRESSABLE HANDLE
// DIFFER (D-L, L5).
//
// Before the pin the question could not arise: the D-I name was always the name
// the sender chose, so there was one string and it was both. A verified row
// renders a name an ISSUER signed, and now there are two — "Rosa Alvarez" on the
// screen, "rosa" on the wire.
//
// A rendered name that cannot be typed is a worse surface than an unrendered
// one, so both work. Which one is CANONICAL is a different question and it has a
// different answer per lookup, because the three lookups are not the same kind
// of thing:
//
//	the wire            always the sender's handle. It is the address, and the
//	                    relay routes on it
//	/verify, /whois     either name — these report what THIS client knows about
//	                    a participant, and a person points at what they can see
//	[[trust]]           the sender's handle only. A pin is the operator's own
//	                    configuration; letting an issuer's choice of display name
//	                    select which pin applies would hand that choice away
//	the record          the sender's handle only, and not by resolution at all —
//	                    see TestTheRecordPathTakesTheWireHandleOnly

func rosaRoom(t *testing.T) (*Model, *room) {
	t.Helper()
	priv, pub, ifpr := issuerFixture(11)
	nb, na := wideOpen()
	m := attributionModel(t)
	m.usePin(IssuerPin{Keys: []ed25519.PublicKey{pub}, Source: "acme-ca.pub"})
	r := m.activeRoom()
	cred := signedBy(t, priv, pub, ifpr, fprRosa, "rosa.alvarez@acme.example", "Rosa Alvarez",
		nb, na, "incident-commander")
	m.admitMember(r, "id-r", "rosa", fprRosa, uiCredentialBytes(t, cred), midWindow())
	return m, r
}

// TestBothNamesAddressTheSameParticipant: /verify @rosa and /verify @"Rosa
// Alvarez" reach one person. The quoted form has to parse, because a signed
// name contains a space and the panel is where a reader learned it.
func TestBothNamesAddressTheSameParticipant(t *testing.T) {
	m, r := rosaRoom(t)
	// Through cutHandle, because that is the peeling /verify and /whois do before
	// they resolve — a test that pre-peeled by hand would prove the resolver
	// works on input the commands never hand it.
	for _, typed := range []string{"@rosa", `@"Rosa Alvarez"`, "@ROSA", `@"rosa alvarez"`} {
		h, _ := cutHandle(typed)
		mem, err := m.resolveHandle(r, h)
		if err != nil {
			t.Errorf("%s did not resolve: %v", typed, err)
			continue
		}
		if mem.name != "rosa" {
			t.Errorf("%s resolved to %q, want the wire handle rosa", typed, mem.name)
		}
	}
	if _, err := m.resolveHandle(r, "nobody"); err == nil {
		t.Error("an unknown handle resolved")
	}
}

// cutHandle has to peel a quoted handle off the front of an argument and leave
// the rest, because /verify @"Rosa Alvarez" ok is the marking form.
func TestAQuotedHandleLeavesTheRestOfTheCommand(t *testing.T) {
	for _, tc := range []struct{ in, handle, rest string }{
		{`@rosa ok`, "rosa", "ok"},
		{`@"Rosa Alvarez" ok`, "Rosa Alvarez", "ok"},
		{`"Rosa Alvarez"`, "Rosa Alvarez", ""},
		{`rosa`, "rosa", ""},
		{``, "", ""},
		{`@"unterminated`, `"unterminated`, ""},
	} {
		h, rest := cutHandle(tc.in)
		if h != tc.handle || rest != tc.rest {
			t.Errorf("cutHandle(%q) = (%q, %q), want (%q, %q)", tc.in, h, rest, tc.handle, tc.rest)
		}
	}
}

// A TYPED NAME THAT FITS TWO PEOPLE IS REFUSED, NOT RESOLVED.
//
// Rendering a signed name creates a collision the wire never had: mallory can
// set her handle to the string an issuer signed for somebody else, and then two
// rows on one screen read the same. Picking the first match would be picking
// silently, and the one the operator meant is the one they were pointing at.
func TestATypedNameThatFitsTwoParticipantsIsRefused(t *testing.T) {
	m, r := rosaRoom(t)
	const mallory = "SHA256:MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM"
	m.admitMember(r, "id-m", "Rosa Alvarez", mallory, nil, midWindow())

	_, err := m.resolveHandle(r, "Rosa Alvarez")
	if err == nil {
		t.Fatal("a name that fits two participants resolved to one of them silently")
	}
	msg := err.Error()
	for _, want := range []string{shortFpr(fprRosa), shortFpr(mallory)} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not name the candidates by fingerprint (%q missing):\n%s", want, msg)
		}
	}
	// The unambiguous handle still works, which is what makes the refusal
	// actionable rather than a dead end.
	if mem, err := m.resolveHandle(r, "rosa"); err != nil || mem.name != "rosa" {
		t.Errorf("the wire handle stopped working once a collision existed: %v", err)
	}
}

// A [[trust]] PIN KEYS ON THE WIRE HANDLE.
//
// The operator wrote that handle in their own netherchat.toml beside a
// fingerprint they compared. If the signed name selected the entry, an issuer
// would decide which of the operator's pins applies to whom — configuration by
// somebody else.
func TestATrustPinKeysOnTheWireHandleOnly(t *testing.T) {
	m, _ := rosaRoom(t)
	m.trust = []TrustEntry{{Handle: "Rosa Alvarez", Fpr: fprRosa}}
	if m.isPinned("rosa", fprRosa) {
		t.Error("a [[trust]] entry named after the SIGNED name pinned the wire handle")
	}
	m.trust = []TrustEntry{{Handle: "rosa", Fpr: fprRosa}}
	if !m.isPinned("rosa", fprRosa) {
		t.Error("a [[trust]] entry named after the wire handle stopped pinning it")
	}
}

// THE VERIFIED NAME IS SHOWN WHERE THE ADDRESS IS SHOWN.
//
// The panel has 22 columns and shows the D-I name. /verify is the surface whose
// next line is a command, so it leads with the address and names the signed name
// beside the mark — one line, both strings, no second vocabulary.
func TestVerifyNamesBothTheAddressAndTheSignedName(t *testing.T) {
	m, _ := rosaRoom(t)
	status := m.verifyStatusText()
	if !strings.Contains(status, "@rosa") {
		t.Errorf("/verify does not show the handle an operator types:\n%s", status)
	}
	if !strings.Contains(status, `◆ issuer-attested as "Rosa Alvarez"`) {
		t.Errorf("/verify does not name the signed name beside the mark:\n%s", status)
	}
	if pane := m.membersView(); !strings.Contains(pane, "Rosa Alvarez") {
		t.Errorf("the participants panel does not render the signed name:\n%s", pane)
	}
}
