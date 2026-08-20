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
// A credential now rides on Member/Hello, so a participant list holds one. It
// cannot check it: verification takes an issuer key and an evaluation time, and
// roadmap §6 rule 1 and identity spec §9.4 both put issuer keys outside this
// program — "no --issuer flag on connect, no default key, no reader of an
// issuer-named file". So every carried credential in a room is
// no_issuer_pinned / unconfigured, and D-I's three VERIFIED rows are not states
// a live room reaches.
//
// The rendering that follows is therefore the honest one and not a compromise:
// the name the sender chose, a hollow mark saying a claim arrived, and the claim
// itself on a detail surface. The tests below fix that in place, because the
// tempting shortcut — render the credential's display_name because it is right
// there and looks official — is the exact failure D-I exists to prevent.

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
	r.addMemberWithCredential("id-d", "dave", "SHA256:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", uiCredentialBytes(t, cred))

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

// TestTheVerifiedMarkIsUnreachableFromTheWire states the consequence in one
// assertion: no credential arriving on Member/Hello, however well formed, can
// produce ◆ on a live surface. It is not that this configuration was not tried —
// it is that the configuration does not exist.
func TestTheVerifiedMarkIsUnreachableFromTheWire(t *testing.T) {
	m := attributionModel(t)
	r := m.activeRoom()
	for i, dn := range []string{"Rosa Alvarez", ""} { // both verified rows, if they were reachable
		fpr := "SHA256:EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE" + string(rune('A'+i))
		cred := uiCredential(t, fpr, "rosa.alvarez@acme.example", dn, "incident-commander")
		r.addMemberWithCredential("id-e"+string(rune('a'+i)), "peer"+string(rune('1'+i)), fpr, uiCredentialBytes(t, cred))
	}
	if pane := m.membersView(); strings.Contains(pane, "◆") {
		t.Fatalf("a wire-carried credential produced the verified mark; nothing in a room holds an "+
			"issuer key to have earned it:\n%s", pane)
	}
}

// TestWhoisShowsTheCarriedClaimAndSaysNobodyCheckedIt: the claim is available
// where there is room for a sentence, and the sentence is about the reader's
// configuration rather than about the peer (ClassOf's rendering rule).
func TestWhoisShowsTheCarriedClaimAndSaysNobodyCheckedIt(t *testing.T) {
	m := attributionModel(t)
	r := m.activeRoom()
	cred := uiCredential(t, fprBob, "sam.okafor@acme.example", "Sam Okafor", "qa", "approver")
	r.members["id-b"] = memberView{name: "bob", fpr: fprBob, identity: parseCarried("bob", fprBob, uiCredentialBytes(t, cred))}

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

	m.credential = uiCredential(t, m.fingerprint, "rosa.alvarez@acme.example", "Rosa Alvarez", "incident-commander")
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
	m.credential = uiCredential(t, m.fingerprint, "svc-deploybot@acme.example", "", "deployer")
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
	r.addMemberWithCredential("id-b", "bob", fprBob, uiCredentialBytes(t, own))
	stolen := uiCredential(t, fprAlice, "ceo@acme.example", "Chief Executive", "approver")
	const mallory = "SHA256:MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM"
	r.addMemberWithCredential("id-m", "mallory", mallory, uiCredentialBytes(t, stolen))

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
	m.credential = uiCredential(t, m.fingerprint, "rosa.alvarez@acme.example", "Rosa Alvarez", "incident-commander")
	text := m.whoamiText(m.activeRoom())
	if n := strings.Count(text, "nothing here checked it"); n != 0 {
		t.Errorf("/whoami repeats what the line above it already said (%d time(s)):\n%s", n, text)
	}
	if !strings.Contains(text, "not checked here") {
		t.Errorf("/whoami stopped saying the credential is unchecked:\n%s", text)
	}
}
