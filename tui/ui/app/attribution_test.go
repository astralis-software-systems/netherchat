package app

import (
	"strings"
	"testing"
)

const (
	fprAlice = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	fprBob   = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	fprCarol = "SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
)

// attributionModel is a room with one SAS-verified peer, one [[trust]]-pinned
// peer, and one peer this client can say nothing about.
func attributionModel(t *testing.T) *Model {
	t.Helper()
	m := newModel("ws://localhost:3000", "me", "", "ops", "")
	m.fingerprint = "SHA256:MEMEMEMEMEMEMEMEMEMEMEMEMEMEMEMEMEMEMEMEMEM"
	m.source = "key file (~/.ssh/id_ed25519)"
	m.width, m.height = 100, 30
	m.membersW, m.bodyH = 22, 20
	m.ready = true
	// newModel defaults mouse capture per GOOS, and /whoami prints it. Pinned so
	// the goldens below are bytes about this change and not about the platform.
	m.mouseOn = false
	m.trust = []TrustEntry{{Handle: "carol", Fpr: fprCarol}}

	r := m.activeRoom()
	r.connected, r.keyReady = true, true
	r.addMember("id-a", "alice", fprAlice)
	r.addMember("id-b", "bob", fprBob)
	r.addMember("id-c", "carol", fprCarol)
	m.verified[fprAlice] = &verifyEntry{handle: "alice", verified: true}
	return m
}

// paneRowFor returns the participants-panel row for a handle, from the pane a
// user actually looks at (Model.membersView), with padding trimmed.
func paneRowFor(t *testing.T, m *Model, handle string) string {
	t.Helper()
	for _, ln := range strings.Split(m.membersView(), "\n") {
		if strings.Contains(ln, handle) {
			return strings.TrimRight(ln, " ")
		}
	}
	t.Fatalf("no participants-panel row for %q in:\n%s", handle, m.membersView())
	return ""
}

// TestTrustMarkMeansOneThingInBothPanes is the ✓ collision, made mechanical.
//
// Before this change ✓ meant SAS-verified in the participants panel and
// [[trust]]-pinned on a message, with ✓✓ for SAS — the same mark carrying two
// meanings two panes apart. A fourth state composed onto that would inherit it,
// so the vocabulary is settled first: whatever mark a peer earns, both panes
// draw the same one.
func TestTrustMarkMeansOneThingInBothPanes(t *testing.T) {
	m := attributionModel(t)
	for _, tc := range []struct {
		handle, fpr, what string
	}{
		{"alice", fprAlice, "SAS-verified"},
		{"bob", fprBob, "neither pinned nor SAS-verified"},
		{"carol", fprCarol, "[[trust]]-pinned"},
	} {
		row := paneRowFor(t, m, tc.handle)
		paneMark := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(row), "● "+tc.handle))
		msgMark := strings.TrimSpace(m.badge(line{from: tc.handle, fpr: tc.fpr, signed: true}))
		if paneMark != msgMark {
			t.Errorf("%s (%s): participants panel draws %q, a message from the same peer draws %q — "+
				"one mark, two meanings, two panes apart", tc.handle, tc.what, paneMark, msgMark)
		}
	}
}

// TestTrustVocabulary pins the decision itself: ✓✓ is the out-of-band check,
// ✓ is the configured pin, and nothing is nothing. Both are things THIS client
// established; the ordering says which is worth more.
func TestTrustVocabulary(t *testing.T) {
	m := attributionModel(t)
	for _, tc := range []struct{ handle, want, why string }{
		{"alice", "✓✓", "SAS-verified out of band this session"},
		{"carol", "✓", "fingerprint matches a [[trust]] pin"},
		{"bob", "", "nothing this client checked"},
	} {
		got := strings.TrimSpace(m.badge(line{from: tc.handle, fpr: map[string]string{
			"alice": fprAlice, "bob": fprBob, "carol": fprCarol,
		}[tc.handle], signed: true}))
		if got != tc.want {
			t.Errorf("message badge for %s (%s) = %q, want %q", tc.handle, tc.why, got, tc.want)
		}
	}
	if got := strings.TrimSpace(m.badge(line{from: "bob", fpr: fprBob, signed: false})); got != "?" {
		t.Errorf("unsigned message badge = %q, want %q", got, "?")
	}
}

// TestDetailSurfacesUseTheSameVocabulary keeps /verify and /roster from teaching
// a third meaning for ✓. They have room for words, so they carry the mark AND
// the words; what they must not do is print a bare ✓ that means something the
// panes do not mean. carol is pinned and not SAS-verified, so a surface that
// still equates ✓ with "verified" says nothing about her at all.
func TestDetailSurfacesUseTheSameVocabulary(t *testing.T) {
	m := attributionModel(t)
	r := m.activeRoom()
	for _, tc := range []struct{ name, text string }{
		{"/verify", m.verifyStatusText()},
		{"/roster", m.rosterText(r)},
	} {
		for _, want := range []string{"✓✓ SAS-verified", "✓ [[trust]]-pinned"} {
			if !strings.Contains(tc.text, want) {
				t.Errorf("%s does not carry %q — it teaches a vocabulary the panes do not use:\n%s",
					tc.name, want, tc.text)
			}
		}
		if strings.Contains(tc.text, "✓ verified") {
			t.Errorf("%s still prints %q, where ✓ alone now means [[trust]]-pinned:\n%s",
				tc.name, "✓ verified", tc.text)
		}
	}
}
