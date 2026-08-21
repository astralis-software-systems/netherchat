package app

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/client"
)

// THE ROOM VIEW — the fifth surface, and the one the demo actually points at.
//
// Until this change an identity attestation landed in the message pane as the
// artifact's own indented JSON: twenty-two lines beginning "📌 typed alice: {",
// captured byte-for-byte in testdata/room_identity_pre3c_json.txt from a pristine
// `git archive 8624c11` extraction. TestTheRoomViewDoesNotPrintAnAttestationAsJSON
// is that defect, and it is written so it compiles against the tree that had it.
//
// Everything below drives a real client.EvRecordEntry — the event a record frame
// becomes — rather than assembling a line by hand, because a test that starts
// below the surface a user touches is how the dropped --issuer flag survived
// green CI (roadmap §8).

// roomIdentityEntry is the entry the designated writer files when an approval
// completes: the writer's own name on the entry, somebody else's credential in
// the body. author ≠ subject is the NORMAL case here, not a finding.
func roomIdentityEntry(t *testing.T, authorName, authorFpr string, att *attest.IdentityAttestation,
	seq uint64, at time.Time,
) client.EvRecordEntry {
	t.Helper()
	return client.EvRecordEntry{
		Seq: seq, Kind: "typed", Schema: "netherchat.identity/v1",
		AuthorName: authorName, AuthorFpr: authorFpr,
		Body: string(uiCredentialBytes(t, att)), Self: true, At: at,
	}
}

// rosaCredential is the demo's credential: an issuer whose key a test can pin,
// a signed display name, and a window a test chooses.
func rosaCredential(t *testing.T, subject string, notBefore, notAfter time.Time) (*attest.IdentityAttestation, ed25519.PublicKey, string) {
	t.Helper()
	priv, pub, ifpr := issuerFixture(1)
	return signedBy(t, priv, pub, ifpr, subject, "rosa.alvarez@acme.example", "Rosa Alvarez",
		notBefore, notAfter, "incident-commander"), pub, ifpr
}

// TestTheRoomViewDoesNotPrintAnAttestationAsJSON is the defect, above the surface
// a user touches: a record frame arrives at handleRoomEvent and the operator
// reads the message pane.
//
// It deliberately uses nothing this change added, so it compiles — and fails — on
// the tree that had the defect. The window is wide open around any real clock
// because handleRoomEvent reads one; nothing here asserts a timestamp.
func TestTheRoomViewDoesNotPrintAnAttestationAsJSON(t *testing.T) {
	m := attributionModel(t)
	r := m.activeRoom()
	att, _, ifpr := rosaCredential(t, fprRosa,
		time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC))
	m.admitMember(r, "id-r", "rosa", fprRosa, nil, midWindow())
	m.handleRoomEvent("ops", roomIdentityEntry(t, "alice", fprAlice, att, 6, time.Now()))

	pane := m.renderLines(r)
	for _, jsonLeak := range []string{`"netherchat_identity"`, `"signer_keys"`, `"signatures"`, `"algorithm"`} {
		if strings.Contains(pane, jsonLeak) {
			t.Errorf("the room view printed the artifact's raw JSON (%s):\n%s", jsonLeak, pane)
		}
	}
	if n := strings.Count(pane, "\n"); n > 12 {
		t.Errorf("one filed credential produced %d lines in the message pane:\n%s", n+1, pane)
	}
	// What it must say instead: the claim, whose key it is about, and who filed it.
	for _, want := range []string{
		"alice", "filed a credential for", "rosa.alvarez@acme.example",
		"incident-commander", fprRosa, ifpr, "◇",
	} {
		if !strings.Contains(pane, want) {
			t.Errorf("the room view does not carry %q:\n%s", want, pane)
		}
	}
	// And it must not promote a name nobody checked.
	if strings.Contains(pane, "filed a credential for Rosa Alvarez") {
		t.Errorf("an unchecked credential's signed name became the name on screen:\n%s", pane)
	}
}

// --- the goldens ------------------------------------------------------------
//
// testdata/room_record_pre3c.txt and testdata/room_identity_pre3c_json.txt were
// captured from a pristine `git archive 8624c11` extraction — the post-D-L,
// pre-3c tree — by a throwaway harness that was then deleted, so nothing this
// session did could have contaminated them. They are comparisons against captured
// bytes; a test that re-derives its own expectation cannot fail.
//
// room_identity_unpinned.txt is the one golden that could NOT come from the old
// tree, because on the old tree that rendering was the defect. It is captured
// from this change and frozen, and it is guarded from vacuity by
// TestTheRoomLineMovesWhenAnIssuerIsPinned below: a golden of a surface that
// cannot move is not a guard.

// roomRecordFixture drives the record entries a room can hold, at fixed times,
// through appendRecordLine — where a record frame lands, which is why the
// evaluation time is a parameter here and a clock read in handleRoomEvent.
func roomRecordFixture(t *testing.T, m *Model, withIdentity bool) string {
	t.Helper()
	r := m.activeRoom()
	at := func(h, mn int) time.Time { return time.Date(2026, 6, 1, h, mn, 0, 0, time.UTC) }
	entries := []client.EvRecordEntry{
		{Seq: 1, Kind: "decision", AuthorName: "alice", AuthorFpr: fprAlice, Body: "rolled back to v2.3.1", Self: true, At: at(14, 30)},
		{Seq: 2, Kind: "action", AuthorName: "bob", AuthorFpr: fprBob, Actionee: "carol", Body: "page the on-call DBA", Self: true, At: at(14, 31)},
		{Seq: 3, Kind: "note", AuthorName: "carol", AuthorFpr: fprCarol, Body: "alice: the cache was cold", Self: true, At: at(14, 32)},
		{Seq: 4, Kind: "artifact", AuthorName: "alice", AuthorFpr: fprAlice, Self: true, At: at(14, 33),
			Body: `{"source":"requirements-agent","artifact_ref":"RFC-114 rollback plan","artifact_hash":"9f2b7c1d4e5a6b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e","approver_fpr":"` + fprBob + `","proposed_at":"2026-06-01T14:33:00Z","approved_at":"2026-06-01T14:33:20Z"}`},
		{Seq: 5, Kind: "decision", AuthorName: "bob", AuthorFpr: fprBob, Body: "an earlier decision", Replayed: true, Self: true, At: at(14, 34)},
	}
	if withIdentity {
		att, _, _ := rosaCredential(t, fprRosa,
			time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
		entries = append(entries, roomIdentityEntry(t, "alice", fprAlice, att, 6, at(14, 35)))
	}
	for _, e := range entries {
		m.appendRecordLine(r, e, at(14, 35))
	}
	return m.renderLines(r)
}

// TestRoomViewInertWithoutAnAttestation is the standalone-inert guard for the
// fifth surface. A room that carries no credential renders byte-for-byte what it
// rendered before this change: the identity branch is compiled in, reachable, and
// out of the way. Roadmap §6 rule 4.
func TestRoomViewInertWithoutAnAttestation(t *testing.T) {
	m := attributionModel(t)
	got := roomRecordFixture(t, m, false)
	want := readGolden(t, "room_record_pre3c.txt")
	if got != want {
		t.Errorf("the room view moved while carrying no attestation.\n"+
			"--- captured at 8624c11 (testdata/room_record_pre3c.txt) ---\n%s\n--- now ---\n%s", want, got)
	}
}

// TestTheRoomViewNoLongerRendersTheCapturedJSON compares against the bytes of the
// defect itself rather than against a description of it — the pane that used to
// carry twenty-two lines of identity.json now carries none of them.
func TestTheRoomViewNoLongerRendersTheCapturedJSON(t *testing.T) {
	before := readGolden(t, "room_identity_pre3c_json.txt")
	if !strings.Contains(before, `"netherchat_identity": "v2"`) {
		t.Fatal("the captured defect does not contain the artifact's JSON; this guard is comparing nothing")
	}
	m := attributionModel(t)
	r := m.activeRoom()
	m.admitMember(r, "id-r", "rosa", fprRosa, nil, midWindow())
	got := roomRecordFixture(t, m, true)
	if got == before {
		t.Fatal("the room view renders exactly what it rendered before 3c")
	}
	if n := len(strings.Split(before, "\n")) - len(strings.Split(got, "\n")); n <= 0 {
		t.Errorf("the new rendering is not shorter than the JSON it replaced (%d lines saved)", n)
	} else {
		t.Logf("one filed credential: %d lines before, %d after", len(strings.Split(before, "\n")), len(strings.Split(got, "\n")))
	}
}

// TestRoomIdentityInertWithNoIssuerPinned freezes what an UNPINNED client sees.
// It is the same claim TestPresenceInertWithCredentialsAndNoIssuerPinned makes
// for the panel, on the surface D-L never reached: the verification path exists,
// it is reachable, and on a client that pinned nothing it stays dormant and the
// bytes do not move.
func TestRoomIdentityInertWithNoIssuerPinned(t *testing.T) {
	m := attributionModel(t)
	if m.pinned() {
		t.Fatal("the inert fixture pinned a key; it is the unpinned case or it proves nothing")
	}
	r := m.activeRoom()
	m.admitMember(r, "id-r", "rosa", fprRosa, nil, midWindow())
	got := roomRecordFixture(t, m, true)
	want := readGolden(t, "room_identity_unpinned.txt")
	if got != want {
		t.Errorf("the unpinned room view moved.\n--- captured (testdata/room_identity_unpinned.txt) ---\n%s"+
			"\n--- now ---\n%s", want, got)
	}
	for _, forbidden := range []string{"◆", "Rosa Alvarez ◇", "checked here against"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("an unpinned client's room view claims %q:\n%s", forbidden, got)
		}
	}
}

// TestTheRoomLineMovesWhenAnIssuerIsPinned is the anti-vacuity half. Same room,
// same entry, same bytes on the wire — one client started with the key that
// signed the credential.
func TestTheRoomLineMovesWhenAnIssuerIsPinned(t *testing.T) {
	unpinned := attributionModel(t)
	unpinned.admitMember(unpinned.activeRoom(), "id-r", "rosa", fprRosa, nil, midWindow())
	before := roomRecordFixture(t, unpinned, true)

	nb, na := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	_, pub, _ := rosaCredential(t, fprRosa, nb, na)
	pinned := attributionModel(t)
	pinned.usePin(IssuerPin{Keys: []ed25519.PublicKey{pub}, Source: "acme-ca.pub"})
	pinned.admitMember(pinned.activeRoom(), "id-r", "rosa", fprRosa, nil, midWindow())
	after := roomRecordFixture(t, pinned, true)

	if after == before {
		t.Fatalf("pinning the issuer that signed the filed credential changed nothing in the room:\n%s", before)
	}
	if !strings.Contains(after, "filed a credential for Rosa Alvarez ◆") {
		t.Errorf("a checked credential does not render its signed name:\n%s", after)
	}
	if !strings.Contains(after, "2026-06-01T14:35:00Z") {
		t.Errorf("a frozen mark does not say when it was decided:\n%s", after)
	}
}

// --- what the room must never say -------------------------------------------

// TestARoomLineNeverAttachesASignedNameToTheAuthorWhoFiledIt is the join rule for
// this surface, and it is the one that keeps ◆ worth having here.
//
// mallory files a credential the pinned CA really did sign, about a key that is
// not mallory's. Every signature in it verifies, so the line legitimately shows
// ◆ and the signed name — what it must NOT do is let a reader come away thinking
// mallory is that person. The author slot keeps the name mallory typed, the
// credential's name sits after a verb, and the subject key is on screen.
func TestARoomLineNeverAttachesASignedNameToTheAuthorWhoFiledIt(t *testing.T) {
	nb, na := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	at := midWindow()
	att, pub, _ := rosaCredential(t, fprRosa, nb, na)

	m := attributionModel(t)
	m.usePin(IssuerPin{Keys: []ed25519.PublicKey{pub}, Source: "acme-ca.pub"})
	r := m.activeRoom()
	const mallory = "SHA256:MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM"
	m.appendRecordLine(r, roomIdentityEntry(t, "mallory", mallory, att, 6, at), at)

	pane := m.renderLines(r)
	if !strings.Contains(pane, "mallory: filed a credential for") {
		t.Fatalf("the author slot no longer carries the name mallory typed:\n%s", pane)
	}
	if strings.Contains(pane, "Rosa Alvarez: ") || strings.Contains(pane, "mallory: Rosa Alvarez") {
		t.Errorf("a signed name reached the slot the author's name goes in:\n%s", pane)
	}
	if !strings.Contains(pane, fprRosa) {
		t.Errorf("the room does not name the key the credential is about, so a reader cannot tell "+
			"it is not mallory's:\n%s", pane)
	}
	if !strings.Contains(pane, "nobody in this room holds that key") {
		t.Errorf("rosa is not here and the room does not say so:\n%s", pane)
	}
	// And the honest case is not dressed as an attack: the designated writer files
	// every approver's credential, so author ≠ subject is normal.
	if strings.Contains(pane, "◇✗") {
		t.Errorf("filing somebody else's credential — what the elected writer does on every "+
			"approval — was rendered as a failed subject join:\n%s", pane)
	}
}

// TestARoomLineIsNotReDecidedOnTheClock. A participants row is re-decided on the
// room tick because presence is now; a scrollback line is not, because it is a
// log of what happened. The credential below closes between the two ticks: the
// PANEL changes and the room line does not, and the room line says which instant
// its mark belongs to.
func TestARoomLineIsNotReDecidedOnTheClock(t *testing.T) {
	opens := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	closes := opens.Add(time.Hour)
	filed := opens.Add(30 * time.Minute)
	att, pub, _ := rosaCredential(t, fprRosa, opens, closes)

	m := attributionModel(t)
	m.usePin(IssuerPin{Keys: []ed25519.PublicKey{pub}, Source: "acme-ca.pub"})
	r := m.activeRoom()
	m.admitMember(r, "id-r", "rosa", fprRosa, uiCredentialBytes(t, att), filed)
	m.appendRecordLine(r, roomIdentityEntry(t, "alice", fprAlice, att, 6, filed), filed)

	before := m.renderLines(r)
	if !strings.Contains(before, "◆") {
		t.Fatalf("a credential inside its window did not render checked when it was filed:\n%s", before)
	}
	if !strings.Contains(before, filed.UTC().Format(time.RFC3339)) {
		t.Errorf("the line does not carry the instant it was decided at:\n%s", before)
	}

	m.recheckIdentities(closes.Add(time.Second))
	if row := paneRowFor(t, m, "rosa"); strings.Contains(row, "◆") {
		t.Fatalf("the panel did not notice the window close, so this test proves nothing: %q", row)
	}
	if after := m.renderLines(r); after != before {
		t.Errorf("a scrollback line was rewritten by the clock. A mark on a line stamped %s that "+
			"changes at %s leaves a reader no way to know which moment it belongs to.\n"+
			"--- before ---\n%s\n--- after ---\n%s", filed.Format("15:04"), closes.Format("15:04"), before, after)
	}
}

// TestAReplayedCredentialIsNotCheckedAgainstThisRoomsClock. /replay streams a
// past record's entries into a retro room. Evaluating one of its credentials
// against this room's wall clock answers "does it verify today", which is not the
// question anybody asked of a record that carries two signed timestamps of its
// own — so it is not answered, and the line says which command does.
func TestAReplayedCredentialIsNotCheckedAgainstThisRoomsClock(t *testing.T) {
	nb, na := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	at := midWindow()
	att, pub, _ := rosaCredential(t, fprRosa, nb, na)

	m := attributionModel(t)
	m.usePin(IssuerPin{Keys: []ed25519.PublicKey{pub}, Source: "acme-ca.pub"}) // pinned, and it still must not
	r := m.activeRoom()
	e := roomIdentityEntry(t, "carol", fprCarol, att, 6, at)
	e.Replayed = true
	m.appendRecordLine(r, e, at)

	pane := m.renderLines(r)
	if strings.Contains(pane, "◆") {
		t.Errorf("a replayed credential was checked against this room's clock and marked:\n%s", pane)
	}
	if !strings.Contains(pane, "netherchat verify") {
		t.Errorf("the line does not name the command that asks the right question:\n%s", pane)
	}
	if !strings.Contains(pane, "[REPLAY") {
		t.Errorf("a replayed identity entry left the room's replay convention:\n%s", pane)
	}
}

// A TYPED ENTRY THIS BUILD DOES NOT INTERPRET IS NOT AN IDENTITY ENTRY.
//
// The room's identity branch turns on record.IsIdentityEntry — the one place the
// schema tag is compared — so a consumer-defined typed entry falls through to the
// unchanged body rendering, which is correct: the library attaches no meaning to a
// consumer's schema and a room view must not invent one.
//
// What DID change for such an entry is the label. It read "📌 typed"; it now reads
// "📌 typed <tag>", because "typed" alone tells a reader nothing and the tag is the
// only thing about the entry this build is entitled to name. Netherchat produces
// no such entry today, so no operator's screen moves — it is stated because it is
// a change, not because it is reachable.
func TestAnUnknownTypedEntryKeepsItsBodyAndGainsItsTag(t *testing.T) {
	m := attributionModel(t)
	r := m.activeRoom()
	at := time.Date(2026, 6, 1, 14, 36, 0, 0, time.UTC)
	m.appendRecordLine(r, client.EvRecordEntry{
		Seq: 7, Kind: "typed", Schema: "acme.change-ticket/v3", AuthorName: "alice",
		AuthorFpr: fprAlice, Body: `{"ticket":"CHG-4471"}`, Self: true, At: at,
	}, at)

	pane := m.renderLines(r)
	if !strings.Contains(pane, "📌 typed acme.change-ticket/v3") {
		t.Errorf("the room does not name the schema tag, which is the only thing it may say about "+
			"an entry it does not interpret:\n%s", pane)
	}
	if !strings.Contains(pane, `{"ticket":"CHG-4471"}`) {
		t.Errorf("the room dropped an opaque consumer body it is not entitled to summarise:\n%s", pane)
	}
	if strings.Contains(pane, "◇") || strings.Contains(pane, "filed a credential") {
		t.Errorf("a consumer's typed entry was rendered through the identity branch:\n%s", pane)
	}
}
