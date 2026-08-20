package app

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// THE READ-SIDE ISSUER PIN (D-L).
//
// A record's verification happens at its reader, with the reader's own key, and
// nothing a live surface renders enters any record. So an issuer key may reach
// a screen. What it must never reach is a path that produces evidence, and the
// tests here are the two halves of that: ◆ is reachable when this client pinned
// a key, and everything about what this client SENDS is unchanged either way.
//
// The evaluation time is the second half of the question and it has no signed
// answer on a live surface (a record has two; presence has none). It is the
// instant the check ran, supplied by the caller, never read inside the
// decision — which is why every function here takes an `at`.

// issuerFixture is a deterministic issuer: one Ed25519 key from a fixed seed, so
// a golden captured on one tree compares against a rendering on another.
func issuerFixture(seed byte) (ed25519.PrivateKey, ed25519.PublicKey, string) {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed + byte(i)
	}
	priv := ed25519.NewKeyFromSeed(s)
	pub := priv.Public().(ed25519.PublicKey)
	return priv, pub, crypto.Fingerprint(pub)
}

// signedBy mints a credential about subject, signed by the given issuer, with an
// explicit window. The window is explicit because every lifecycle test below
// turns on it, and a fixture that stamped "now" would make those tests a
// statement about how fast the machine is.
func signedBy(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey, fpr,
	subject, principal, displayName string, notBefore, notAfter time.Time, roles ...string,
) *attest.IdentityAttestation {
	t.Helper()
	unsigned := attest.NewIdentityAttestation(attest.IdentitySpec{
		Serial:        "acme-0100",
		Subject:       subject,
		Principal:     principal,
		DisplayName:   displayName,
		PrincipalType: "person",
		Roles:         roles,
		ExpiresAt:     notAfter.UTC().Format(time.RFC3339),
		Algorithm:     attest.AlgorithmEd25519,
		Issuer:        fpr,
	}, nil, nil)
	unsigned.IssuedAt = notBefore.UTC().Format(time.RFC3339)
	return unsigned.WithSignatures(
		map[string][]byte{fpr: ed25519.Sign(priv, attest.IdentitySigningBytes(unsigned))},
		map[string][]byte{fpr: pub},
	)
}

// wideOpen is the window every test that is not ABOUT the window uses.
func wideOpen() (time.Time, time.Time) {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
}

// midWindow is an evaluation time inside wideOpen.
func midWindow() time.Time { return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) }

// A STOLEN CREDENTIAL IS THE CASE THAT MATTERS MOST NOW, NOT LEAST.
//
// Before the pin, §7's finding cost a hollow diamond: nothing could verify, so
// nothing could verify wrongly. With a pin, a credential replayed onto another
// key is one subject comparison away from rendering an executive's signed name
// beside a stranger — and every signature in it would check out.
func TestAPinnedIssuerStillRefusesACredentialAboutAnotherKey(t *testing.T) {
	priv, pub, ifpr := issuerFixture(11)
	nb, na := wideOpen()
	at := midWindow()

	m := attributionModel(t)
	m.usePin(IssuerPin{Keys: []ed25519.PublicKey{pub}, Source: "acme-ca.pub"})
	r := m.activeRoom()

	stolen := signedBy(t, priv, pub, ifpr, fprAlice, "ceo@acme.example", "Chief Executive", nb, na, "approver")
	const mallory = "SHA256:MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM"
	m.admitMember(r, "id-m", "mallory", mallory, uiCredentialBytes(t, stolen), at)

	row := paneRowFor(t, m, "mallory")
	if strings.Contains(row, "◆") {
		t.Fatalf("a credential replayed onto another key reached the verified mark under a pin: %q", row)
	}
	if !strings.Contains(row, "◇✗") {
		t.Errorf("mallory's row does not mark the failed join: %q", row)
	}
	if pane := m.membersView(); strings.Contains(pane, "Chief Executive") {
		t.Errorf("an executive's signed name rendered beside a key it says nothing about:\n%s", pane)
	}
}

// AN AUTHORITY THIS CLIENT DID NOT PIN IS NOT A FINDING ABOUT THE PERSON.
// ClassOf's rendering rule is normative and a pin is exactly when it starts
// being possible to break: with keys configured, "none of them signed this" is
// tempting to render as a failure. It is a statement about the trust
// relationship, and the surface says so or says nothing.
func TestACredentialFromAnUnpinnedAuthorityStaysACarriedClaim(t *testing.T) {
	otherPriv, otherPub, otherFpr := issuerFixture(31)
	_, pinned, _ := issuerFixture(11)
	nb, na := wideOpen()
	at := midWindow()

	m := attributionModel(t)
	m.usePin(IssuerPin{Keys: []ed25519.PublicKey{pinned}, Source: "acme-ca.pub"})
	r := m.activeRoom()

	cred := signedBy(t, otherPriv, otherPub, otherFpr, fprBob, "sam.okafor@other.example", "Sam Okafor", nb, na, "qa")
	m.admitMember(r, "id-b2", "bob2", fprBob, uiCredentialBytes(t, cred), at)

	mem := m.memberByHandle(r, "bob2")
	if mem.identity.State != attest.IdentityDisplayCarried {
		t.Fatalf("state = %q, want carried", mem.identity.State)
	}
	if mem.identity.Reason != attest.ReasonNoPinnedIssuerVerified {
		t.Errorf("reason = %q, want %q", mem.identity.Reason, attest.ReasonNoPinnedIssuerVerified)
	}
	if mem.identity.ReasonClass != attest.ClassUnanchored {
		t.Errorf("class = %q, want %q", mem.identity.ReasonClass, attest.ClassUnanchored)
	}
	text := m.whoisCredentialText(r, "bob2")
	for _, forbidden := range []string{"invalid", "forged", "failed"} {
		if strings.Contains(strings.ToLower(text), forbidden) {
			t.Errorf("/whois dresses an unpinned authority as a finding about bob2 (%q):\n%s", forbidden, text)
		}
	}
}

// PRESENCE IS NOW, AND "NOW" MOVES.
//
// A record carries signed timestamps to evaluate against. A participants panel
// carries none, so the evaluation time is the instant the check ran — and a
// check that ran at 14:00 is not an answer at 15:00. The panel changes on a
// CLOCK event and on nothing else: not on a message, not on a keystroke, not on
// a redraw. This is that event.
func TestACredentialThatExpiresMidSessionStopsRenderingVerified(t *testing.T) {
	priv, pub, ifpr := issuerFixture(11)
	opens := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	closes := time.Date(2026, 6, 1, 1, 0, 0, 0, time.UTC)
	joined := opens.Add(30 * time.Minute)

	m := attributionModel(t)
	m.usePin(IssuerPin{Keys: []ed25519.PublicKey{pub}, Source: "acme-ca.pub"})
	r := m.activeRoom()
	cred := signedBy(t, priv, pub, ifpr, fprRosa, "rosa.alvarez@acme.example", "Rosa Alvarez",
		opens, closes, "incident-commander")
	m.admitMember(r, "id-r", "rosa", fprRosa, uiCredentialBytes(t, cred), joined)

	if got := paneRowFor(t, m, "Rosa Alvarez"); !strings.Contains(got, "◆") {
		t.Fatalf("a credential inside its window did not render verified at join: %q", got)
	}

	// A tick still inside the window changes nothing.
	m.recheckIdentities(closes.Add(-time.Minute))
	if got := paneRowFor(t, m, "Rosa Alvarez"); !strings.Contains(got, "◆") {
		t.Fatalf("a tick inside the window dropped the verified mark: %q", got)
	}

	// The first tick after the window closed does.
	m.recheckIdentities(closes.Add(time.Second))
	row := paneRowFor(t, m, "rosa")
	if strings.Contains(row, "◆") {
		t.Fatalf("an expired credential still renders as checked: %q", row)
	}
	mem := m.memberByHandle(r, "rosa")
	if mem.identity.Reason != attest.ReasonExpired {
		t.Errorf("reason after expiry = %q, want %q", mem.identity.Reason, attest.ReasonExpired)
	}
	if mem.identity.Name != "rosa" {
		t.Errorf("the signed name outlived the window it was signed for: name = %q, want the wire name", mem.identity.Name)
	}
	if got := m.verifyStatusText(); !strings.Contains(got, "expired") {
		t.Errorf("/verify does not say why the mark went away:\n%s", got)
	}
}

// The same mechanism running the other way, which is the half a "re-check on
// expiry" implementation forgets: a credential whose window has not opened yet
// becomes verified on the clock, without anybody rejoining.
func TestACredentialNotYetValidBecomesVerifiedOnTheClock(t *testing.T) {
	priv, pub, ifpr := issuerFixture(11)
	opens := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	closes := opens.Add(24 * time.Hour)

	m := attributionModel(t)
	m.usePin(IssuerPin{Keys: []ed25519.PublicKey{pub}, Source: "acme-ca.pub"})
	r := m.activeRoom()
	cred := signedBy(t, priv, pub, ifpr, fprRosa, "rosa.alvarez@acme.example", "Rosa Alvarez",
		opens, closes, "incident-commander")
	m.admitMember(r, "id-r", "rosa", fprRosa, uiCredentialBytes(t, cred), opens.Add(-time.Hour))

	if mem := m.memberByHandle(r, "rosa"); mem.identity.Reason != attest.ReasonNotYetValid {
		t.Fatalf("reason before the window opened = %q, want %q", mem.identity.Reason, attest.ReasonNotYetValid)
	}
	m.recheckIdentities(opens.Add(time.Second))
	if got := paneRowFor(t, m, "Rosa Alvarez"); !strings.Contains(got, "◆") {
		t.Fatalf("the window opened and nothing on screen noticed: %q", got)
	}
}

// A row nothing on the clock can change must not be re-checked, and a settled
// row must survive a tick a decade later untouched. Without this, "re-check
// everything every tick" passes the two tests above while re-verifying every
// signature in the room fifteen times a minute.
func TestOnlyAWindowBoundaryScheduleAReCheck(t *testing.T) {
	priv, pub, ifpr := issuerFixture(11)
	nb, na := wideOpen()
	at := midWindow()

	m := attributionModel(t)
	m.usePin(IssuerPin{Keys: []ed25519.PublicKey{pub}, Source: "acme-ca.pub"})
	r := m.activeRoom()

	stolen := signedBy(t, priv, pub, ifpr, fprAlice, "ceo@acme.example", "Chief Executive", nb, na, "approver")
	m.admitMember(r, "id-m", "mallory", "SHA256:MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM",
		uiCredentialBytes(t, stolen), at)
	m.admitMember(r, "id-p", "plain", fprBob, nil, at)

	for _, handle := range []string{"mallory", "plain"} {
		if ra := m.memberByHandle(r, handle).recheckAt; !ra.IsZero() {
			t.Errorf("%s is scheduled for a re-check at %s; no clock event can change that row", handle, ra)
		}
	}
	before := m.membersView()
	if m.recheckIdentities(at.Add(20 * 365 * 24 * time.Hour)) {
		t.Error("a tick twenty years on reported a change where no window exists")
	}
	if after := m.membersView(); after != before {
		t.Errorf("a settled row moved on a tick:\n--- before ---\n%s\n--- after ---\n%s", before, after)
	}
}

// AN OPERATOR SEES THEIR OWN CREDENTIAL CHECKED BEFORE THEY ACT.
// /whoami is where an expired credential should be noticed — before somebody
// reads the record, not after.
func TestWhoamiChecksYourOwnCredentialAgainstThePinnedIssuer(t *testing.T) {
	priv, pub, ifpr := issuerFixture(11)
	nb, na := wideOpen()
	at := midWindow()

	m := attributionModel(t)
	m.usePin(IssuerPin{Keys: []ed25519.PublicKey{pub}, Source: "acme-ca.pub"})
	cred := signedBy(t, priv, pub, ifpr, m.fingerprint, "rosa.alvarez@acme.example", "Rosa Alvarez",
		nb, na, "incident-commander")
	m.useCredential(cred, at)

	text := m.whoamiText(m.activeRoom())
	if !strings.Contains(text, "◆") {
		t.Fatalf("/whoami does not check the operator's own credential against the pinned key:\n%s", text)
	}
	if strings.Contains(text, "not checked here") {
		t.Errorf("/whoami still says nobody checked it after checking it:\n%s", text)
	}
	if !strings.Contains(text, ifpr) {
		t.Errorf("/whoami does not name the issuer it checked against:\n%s", text)
	}
}

// WHAT ◆ RESTS ON MUST BE ASKABLE.
//
// The strongest mark in the vocabulary now depends on reader-side configuration
// that is nowhere on the screen. /issuer is where a person asks "against what,
// and as of when" — and it can only ANSWER, because a second place to configure
// a trust anchor is a second place to get it wrong.
func TestIssuerReportsThePinAndCannotSetOne(t *testing.T) {
	_, pub, ifpr := issuerFixture(11)

	m := attributionModel(t)
	unpinned := m.issuerText()
	for _, want := range []string{"none", "◆"} {
		if !strings.Contains(unpinned, want) {
			t.Errorf("unpinned /issuer does not carry %q:\n%s", want, unpinned)
		}
	}

	m.usePin(IssuerPin{Keys: []ed25519.PublicKey{pub}, Source: "acme-ca.pub"})
	m.lastCheckedAt = midWindow()
	pinned := m.issuerText()
	for _, want := range []string{"acme-ca.pub", ifpr, "2026-06-01T00:00:00Z", "clock"} {
		if !strings.Contains(pinned, want) {
			t.Errorf("pinned /issuer does not carry %q:\n%s", want, pinned)
		}
	}

	m.runIssuer("acme-ca.pub")
	last := lastLineOf(t, m)
	if !strings.Contains(last, "--issuer") {
		t.Errorf("/issuer with an argument does not name the flag that pins one: %q", last)
	}
	if m.issuerSource != "acme-ca.pub" || len(m.pinnedIssuerKeys) != 1 {
		t.Fatal("/issuer with an argument changed the pin; it is a report, not a second way to configure one")
	}
}

// lastLineOf returns the last line the model appended to the active room.
func lastLineOf(t *testing.T, m *Model) string {
	t.Helper()
	r := m.activeRoom()
	if len(r.lines) == 0 {
		t.Fatal("nothing was appended to the room")
	}
	return r.lines[len(r.lines)-1].text
}
