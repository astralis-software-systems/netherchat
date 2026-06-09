package app

import (
	"strings"
	"testing"
)

// TestRosterTextNoFile proves /roster with no flag prints the member list (with
// fingerprints and verification status) and writes no artifact.
func TestRosterTextNoFile(t *testing.T) {
	m := newModel("ws://localhost:3000", "me", "", "ops", "")
	m.fingerprint = testFpr
	r := m.activeRoom()
	r.addMember("id1", "alice", "SHA256:aaaaaaaaaaaaaaaa")

	m.runRoster(r, "")

	last := r.lines[len(r.lines)-1]
	if last.kind != lineSystem || !strings.Contains(last.text, "roster of #ops") {
		t.Fatalf("expected roster text, got %+v", last)
	}
	if !strings.Contains(last.text, "alice") || !strings.Contains(last.text, "(you)") {
		t.Errorf("roster text missing members:\n%s", last.text)
	}
	if !strings.Contains(last.text, m.fingerprint) {
		t.Errorf("roster text missing our fingerprint:\n%s", last.text)
	}
}

// TestParseRosterArgs covers the flag parser for /roster.
func TestParseRosterArgs(t *testing.T) {
	signed, out, err := parseRosterArgs("--signed --out r.json")
	if err != nil || !signed || out != "r.json" {
		t.Fatalf("parseRosterArgs = (%v,%q,%v), want (true,\"r.json\",nil)", signed, out, err)
	}
	if signed, out, err := parseRosterArgs(""); err != nil || signed || out != "" {
		t.Fatalf("empty args = (%v,%q,%v), want (false,\"\",nil)", signed, out, err)
	}
	if _, _, err := parseRosterArgs("--bogus"); err == nil {
		t.Error("expected an error on an unknown flag")
	}
}
