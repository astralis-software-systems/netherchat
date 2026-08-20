package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The presence surfaces, frozen twice.
//
// testdata/presence_*_pre3b.txt was captured from the clean tree at 1e7d92c,
// BEFORE any Phase 3b source change, by a throwaway harness that was then
// deleted. testdata/presence_*_w1.txt was captured immediately after W1 — the ✓
// vocabulary fix — and before a single line of attestation carriage existed.
//
// Two properties follow, and they are checked separately because they are
// different claims:
//
//	W1 moved exactly the marks and nothing else       — TestW1MovedOnlyTheMarks
//	carrying no attestation moves nothing at all      — TestPresenceInertWithoutAttestation
//
// The second is the standalone-inert guard for this phase, and it is a
// comparison against captured bytes rather than a re-derivation. Re-deriving is
// what the Close()-flush change did, and re-derivation cannot fail: whatever the
// code now produces is what the test then expects.

// presenceSurfaces renders every presence surface Phase 3b touches, keyed by
// golden basename. The model is the same one attribution_test.go builds — one
// SAS-verified peer, one [[trust]]-pinned peer, one plain peer, no attestation
// anywhere and no issuer key, because that is the inert case.
func presenceSurfaces(t *testing.T) map[string]string {
	t.Helper()
	m := attributionModel(t)
	return map[string]string{
		"presence_members_pane": m.membersView(),
		"presence_badges":       attributionBadges(m),
		"presence_whoami":       m.whoamiText(m.activeRoom()),
		"presence_verifylist":   m.verifyStatusText(),
	}
}

// attributionBadges renders the message badge for each peer state, in the same
// order and shape the pre-change capture used.
func attributionBadges(m *Model) string {
	var b strings.Builder
	for _, tc := range []struct {
		who, fpr string
		signed   bool
	}{
		{"alice", fprAlice, true},
		{"bob", fprBob, true},
		{"carol", fprCarol, true},
		{"bob", fprBob, false},
	} {
		b.WriteString(tc.who + "|" + m.badge(line{from: tc.who, fpr: tc.fpr, signed: tc.signed}) + "|\n")
	}
	return b.String()
}

func readGolden(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("golden %s: %v", name, err)
	}
	return string(b)
}

// TestPresenceInertWithoutAttestation is the standalone-inert guard: with no
// attestation carried and no issuer pinned anywhere, every presence surface is
// byte-identical to what it rendered before attestation carriage existed.
func TestPresenceInertWithoutAttestation(t *testing.T) {
	for name, got := range presenceSurfaces(t) {
		want := readGolden(t, name+"_w1.txt")
		if got != want {
			t.Errorf("%s moved while carrying no attestation and pinning no issuer.\n"+
				"--- captured (testdata/%s_w1.txt) ---\n%s\n--- now ---\n%s",
				name, name, want, got)
		}
	}
}

// TestW1MovedOnlyTheMarks bounds the one deliberate rendering change in this
// phase. Every line that differs between the pre-3b capture and the post-W1
// capture must be a line that carries a trust mark; a difference anywhere else
// is W1 having reached further than the vocabulary.
func TestW1MovedOnlyTheMarks(t *testing.T) {
	var moved []string
	for name := range presenceSurfaces(t) {
		before := strings.Split(readGolden(t, name+"_pre3b.txt"), "\n")
		after := strings.Split(readGolden(t, name+"_w1.txt"), "\n")
		if len(before) != len(after) {
			t.Fatalf("%s: %d lines before, %d after — W1 added or removed a line", name, len(before), len(after))
		}
		for i := range before {
			if before[i] == after[i] {
				continue
			}
			if !carriesAMark(before[i]) && !carriesAMark(after[i]) {
				t.Errorf("%s line %d changed and carries no trust mark:\n  before: %q\n  after:  %q",
					name, i+1, before[i], after[i])
				continue
			}
			moved = append(moved, name+": "+strings.TrimSpace(before[i])+"  →  "+strings.TrimSpace(after[i]))
		}
	}
	if len(moved) == 0 {
		t.Fatal("no line moved between the pre-3b and post-W1 captures; either the goldens are the " +
			"same file or W1 changed nothing, and both make this guard vacuous")
	}
	t.Logf("W1 moved %d line(s), all of them marks:\n  %s", len(moved), strings.Join(moved, "\n  "))
}

func carriesAMark(s string) bool {
	return strings.Contains(s, "✓") || strings.Contains(s, "unverified") || strings.Contains(s, "pinned")
}
