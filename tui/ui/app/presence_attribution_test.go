package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// WHAT A LIVE ROOM CAN AND CANNOT SAY ABOUT A CARRIED CREDENTIAL.
//
// A credential rides on Member/Hello, so a participant list holds one. Whether
// it can CHECK one is now a property of how this client was started, not of the
// program: with `connect --issuer <file>` a room reaches D-I's verified rows,
// and with no such flag it reaches none of them (D-L). The two halves are
// TestTheVerifiedMarkIsReachableOnlyWithAnIssuerPinned below, and they replaced
// a single test that asserted the second half was unconditional.
//
// Everything in the unpinned half is unchanged and that is the point: the name
// the sender chose, a hollow mark saying a claim arrived, and the claim itself
// on a detail surface. The tempting shortcut — render the credential's
// display_name because it is right there and looks official — is the exact
// failure D-I exists to prevent, and it is no more available with a pin than
// without one, because what renders is the VERIFIED name or the sender's, never
// an unchecked artifact's.

func uiCredential(t *testing.T, subject, principal, displayName string, roles ...string) *attest.IdentityAttestation {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("issuer key: %v", err)
	}
	fpr := crypto.Fingerprint(pub)
	unsigned := attest.NewIdentityAttestation(attest.IdentitySpec{
		Serial:        "acme-0100",
		Subject:       subject,
		Principal:     principal,
		DisplayName:   displayName,
		PrincipalType: "person",
		Roles:         roles,
		ExpiresAt:     time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
		Algorithm:     attest.AlgorithmEd25519,
		Issuer:        fpr,
	}, nil, nil)
	return unsigned.WithSignatures(
		map[string][]byte{fpr: ed25519.Sign(priv, attest.IdentitySigningBytes(unsigned))},
		map[string][]byte{fpr: pub},
	)
}

func uiCredentialBytes(t *testing.T, a *attest.IdentityAttestation) []byte {
	t.Helper()
	b, err := a.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// TestCarriedCredentialNeverBecomesTheNameOnScreen is the guard the D-I decision
// rests on in a live room. dave carries a credential asserting "Chief
// Executive"; the participants panel draws "dave".
func TestCarriedCredentialNeverBecomesTheNameOnScreen(t *testing.T) {
	m := attributionModel(t)
	r := m.activeRoom()
	cred := uiCredential(t, "SHA256:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
		"ceo@acme.example", "Chief Executive", "approver")
	m.admitMember(r, "id-d", "dave", "SHA256:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", uiCredentialBytes(t, cred), midWindow())

	pane := m.membersView()
	if !strings.Contains(pane, "dave") {
		t.Fatalf("the participants panel lost dave entirely:\n%s", pane)
	}
	for _, forbidden := range []string{"Chief Executive", "ceo@acme.example"} {
		if strings.Contains(pane, forbidden) {
			t.Errorf("the participants panel rendered %q from an unchecked credential:\n%s", forbidden, pane)
		}
	}
	row := paneRowFor(t, m, "dave")
	if !strings.Contains(row, "◇") {
		t.Errorf("dave's row does not say a credential arrived: %q", row)
	}
	if strings.Contains(row, "◆") || strings.Contains(row, "✓") {
		t.Errorf("dave's row claims a check nobody performed: %q", row)
	}
}

// THE REVERSED GUARD (D-L). Its predecessor,
// TestTheVerifiedMarkIsUnreachableFromTheWire, asserted the second half below
// unconditionally, and that assertion was true because roadmap §6 rule 1
// forbade the pin. The rule was too broad for its own justification — it exists
// so a PRODUCER cannot make evidence a function of its own configuration, and a
// rendered name is not evidence — so it now reads "no issuer configuration on
// any path that produces evidence", and the guard reads with it.
//
// Both halves run the SAME room through the same admission with the same bytes.
// The only difference between them is whether this client was started with a
// key, which is the whole claim: what a screen can say is a property of the
// reader, and the wire is identical either way.

// presenceUnderPin admits both verified rows' inputs — a credential with a
// signed display name and one without — and returns the model. pin decides
// whether this client can check them.
func presenceUnderPin(t *testing.T, pin IssuerPin, issuerPriv ed25519.PrivateKey,
	issuerPub ed25519.PublicKey, issuerFpr string, at time.Time,
) *Model {
	t.Helper()
	m := attributionModel(t)
	m.usePin(pin)
	r := m.activeRoom()
	nb, na := wideOpen()
	for i, tc := range []struct{ handle, principal, displayName string }{
		{"peer1", "rosa.alvarez@acme.example", "Rosa Alvarez"},
		{"peer2", "svc-deploybot@acme.example", ""},
	} {
		fpr := "SHA256:EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE" + string(rune('A'+i))
		cred := signedBy(t, issuerPriv, issuerPub, issuerFpr, fpr, tc.principal, tc.displayName,
			nb, na, "incident-commander")
		m.admitMember(r, "id-e"+string(rune('a'+i)), tc.handle, fpr, uiCredentialBytes(t, cred), at)
	}
	return m
}

// TestTheVerifiedMarkIsReachableOnlyWithAnIssuerPinned — the half that is new.
// Both of D-I's verified rows are reachable, and they are peers: a signed
// display name renders as that name, and a credential whose issuer named no
// name renders as the principal. Neither is a fallback for the other.
func TestTheVerifiedMarkIsReachableOnlyWithAnIssuerPinned(t *testing.T) {
	priv, pub, ifpr := issuerFixture(11)
	m := presenceUnderPin(t, IssuerPin{Keys: []ed25519.PublicKey{pub}, Source: "acme-ca.pub"},
		priv, pub, ifpr, midWindow())

	pane := m.membersView()
	if !strings.Contains(pane, "◆") {
		t.Fatalf("a pinned issuer key reached no row; ◆ is still unreachable:\n%s", pane)
	}
	if !strings.Contains(pane, "Rosa Alvarez") {
		t.Errorf("verified_named did not render the SIGNED name:\n%s", pane)
	}
	// The pane's name column was sized for handles and a principal is routinely
	// wider, so the row carries as much of it as fits and the surfaces with room
	// carry all of it. What must NOT happen is the third verified path collapsing
	// into the sender's handle, which would make it a fallback rather than a peer.
	if !strings.Contains(pane, "svc-deploybot@") {
		t.Errorf("verified_unnamed did not render the principal; the third verified path "+
			"collapsed into the sender's handle:\n%s", pane)
	}
	for _, handle := range []string{"peer1", "peer2"} {
		if strings.Contains(pane, " "+handle) {
			t.Errorf("%s still renders under the name the sender chose beside a checked credential:\n%s", handle, pane)
		}
	}
	roster := m.rosterText(m.activeRoom())
	if !strings.Contains(roster, "svc-deploybot@acme.example") {
		t.Errorf("the full principal is nowhere a reader can get it — the pane clipped it and "+
			"/roster does not carry it:\n%s", roster)
	}
}

// TestTheVerifiedMarkStaysUnreachableWithNoIssuerPinned — the half that was the
// whole of the old test. Same credentials, same admission, no key: ◆ is not a
// state any row reaches, and — the part a naive implementation breaks — nothing
// was ATTEMPTED. A client that called the verifier with an empty key set would
// pass the first assertion and fail the second, because a result carries a
// reason and a detail that this surface has never had.
func TestTheVerifiedMarkStaysUnreachableWithNoIssuerPinned(t *testing.T) {
	priv, pub, ifpr := issuerFixture(11)
	m := presenceUnderPin(t, IssuerPin{}, priv, pub, ifpr, midWindow())

	if pane := m.membersView(); strings.Contains(pane, "◆") {
		t.Fatalf("a wire-carried credential produced the verified mark with no key pinned:\n%s", pane)
	}
	r := m.activeRoom()
	for _, handle := range []string{"peer1", "peer2"} {
		got := m.memberByHandle(r, handle).identity
		if got.State != attest.IdentityDisplayCarried {
			t.Errorf("%s: state = %q, want carried", handle, got.State)
		}
		if got.Name != handle {
			t.Errorf("%s: name = %q, want the name the sender chose", handle, got.Name)
		}
		if got.Reason != "" || got.ReasonClass != "" {
			t.Errorf("%s: an unpinned client produced an outcome code (%q/%q). Nothing was checked, "+
				"so there is nothing to report a reason for — this is the verifier having been "+
				"called with an empty key set instead of not called at all",
				handle, got.Reason, got.ReasonClass)
		}
		if got.Detail != "a credential accompanied this key and nothing here checked it" {
			t.Errorf("%s: detail = %q, which is not the sentence an unpinned surface has always shown", handle, got.Detail)
		}
	}
}

// TestWhoisShowsTheCarriedClaimAndSaysNobodyCheckedIt: the claim is available
// where there is room for a sentence, and the sentence is about the reader's
// configuration rather than about the peer (ClassOf's rendering rule).
func TestWhoisShowsTheCarriedClaimAndSaysNobodyCheckedIt(t *testing.T) {
	m := attributionModel(t)
	r := m.activeRoom()
	cred := uiCredential(t, fprBob, "sam.okafor@acme.example", "Sam Okafor", "qa", "approver")
	m.admitMember(r, "id-b", "bob", fprBob, uiCredentialBytes(t, cred), midWindow())

	text := m.whoisCredentialText(r, "bob")
	for _, want := range []string{"sam.okafor@acme.example", "Sam Okafor", "qa", cred.Issuer, "not checked here"} {
		if !strings.Contains(text, want) {
			t.Errorf("/whois @bob does not carry %q:\n%s", want, text)
		}
	}
	for _, forbidden := range []string{"invalid", "could not be verified", "failed"} {
		if strings.Contains(strings.ToLower(text), forbidden) {
			t.Errorf("/whois @bob dresses an unconfigured reader as a finding about bob (%q):\n%s", forbidden, text)
		}
	}
	if got := m.whoisCredentialText(r, "alice"); got != "" {
		t.Errorf("a peer carrying nothing produced a credential block:\n%s", got)
	}
}

// TestWhoamiShowsYourOwnCredential: an operator can see what they are carrying
// before they act, which is the whole reason /whoami exists. With none carried
// the block is absent — a bare "credential:" would read as an issuer having
// signed a blank, and it would move a surface that must not move (§9.3, and
// TestPresenceInertWithoutAttestation).
func TestWhoamiShowsYourOwnCredential(t *testing.T) {
	m := attributionModel(t)
	if strings.Contains(m.whoamiText(m.activeRoom()), "credential") {
		t.Fatalf("/whoami mentions a credential when none is carried:\n%s", m.whoamiText(m.activeRoom()))
	}

	m.useCredential(uiCredential(t, m.fingerprint, "rosa.alvarez@acme.example", "Rosa Alvarez", "incident-commander"), midWindow())
	text := m.whoamiText(m.activeRoom())
	for _, want := range []string{
		"credential:", "rosa.alvarez@acme.example", "Rosa Alvarez",
		"incident-commander", m.credential.Issuer, "not checked here",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("/whoami does not carry %q:\n%s", want, text)
		}
	}
}

// TestWhoamiPrintsThePrincipalWhenTheIssuerNamedNoName is D-I's third path on
// the surface where it is most likely to be collapsed by accident: a service
// credential with no display_name must still show WHAT it names, and must not
// fall silently back to the local handle as though nothing had been signed.
func TestWhoamiPrintsThePrincipalWhenTheIssuerNamedNoName(t *testing.T) {
	m := attributionModel(t)
	m.useCredential(uiCredential(t, m.fingerprint, "svc-deploybot@acme.example", "", "deployer"), midWindow())
	text := m.whoamiText(m.activeRoom())
	if !strings.Contains(text, "svc-deploybot@acme.example") {
		t.Errorf("/whoami dropped the principal of a credential that named no display name:\n%s", text)
	}
	if strings.Contains(text, "display name:") {
		t.Errorf("/whoami printed an empty display-name line, which reads as an issuer signing a blank:\n%s", text)
	}
}

// A CREDENTIAL ABOUT SOMEONE ELSE'S KEY IS NOT "UNCHECKED". IT IS WRONG.
//
// The subject join is the ONE thing a live surface can establish about a carried
// credential — it needs no issuer key and no clock — so burying its result in a
// parenthetical under "not checked here" throws away the only check this client
// performed. mallory carries Rosa's real, valid credential on her own key; dave
// carries his own. They must not look the same.
func TestASubjectMismatchIsLouderThanAnUncheckedClaim(t *testing.T) {
	m := attributionModel(t)
	r := m.activeRoom()

	own := uiCredential(t, fprBob, "sam.okafor@acme.example", "Sam Okafor", "qa")
	m.admitMember(r, "id-b", "bob", fprBob, uiCredentialBytes(t, own), midWindow())
	stolen := uiCredential(t, fprAlice, "ceo@acme.example", "Chief Executive", "approver")
	const mallory = "SHA256:MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM"
	m.admitMember(r, "id-m", "mallory", mallory, uiCredentialBytes(t, stolen), midWindow())

	bobRow, mallRow := paneRowFor(t, m, "bob"), paneRowFor(t, m, "mallory")
	if bobRow == mallRow {
		t.Errorf("the participants panel draws a stolen credential exactly like an honest one: %q", bobRow)
	}
	if !strings.Contains(mallRow, "◇✗") {
		t.Errorf("mallory's row does not mark the failed check: %q", mallRow)
	}
	if strings.Contains(bobRow, "✗") {
		t.Errorf("bob's row marks a failure that did not happen: %q", bobRow)
	}

	// /verify has room for words, so it uses them.
	status := m.verifyStatusText()
	if !strings.Contains(status, "◇✗ credential is about a different key") {
		t.Errorf("/verify does not distinguish the mismatch:\n%s", status)
	}

	// /whois leads with the finding rather than trailing it.
	whois := m.whoisCredentialText(r, "mallory")
	first := strings.TrimSpace(strings.Split(strings.TrimSpace(whois), "\n")[0])
	if !strings.Contains(strings.ToLower(first), "different key") {
		t.Errorf("/whois @mallory buries the one thing this client established; its first line is %q\n%s",
			first, whois)
	}
	if !strings.Contains(whois, mallory) || !strings.Contains(whois, fprAlice) {
		t.Errorf("/whois @mallory does not name both keys:\n%s", whois)
	}
}

// TestWhoamiSaysTheUncheckedThingOnce: with nothing to add, the block does not
// restate its own last line in parentheses.
func TestWhoamiSaysTheUncheckedThingOnce(t *testing.T) {
	m := attributionModel(t)
	m.useCredential(uiCredential(t, m.fingerprint, "rosa.alvarez@acme.example", "Rosa Alvarez", "incident-commander"), midWindow())
	text := m.whoamiText(m.activeRoom())
	if n := strings.Count(text, "nothing here checked it"); n != 0 {
		t.Errorf("/whoami repeats what the line above it already said (%d time(s)):\n%s", n, text)
	}
	if !strings.Contains(text, "not checked here") {
		t.Errorf("/whoami stopped saying the credential is unchecked:\n%s", text)
	}
}
