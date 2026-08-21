package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The seventh instance of the reassurance defect, and the first an operator
// reads at RUNTIME rather than in source (roadmap §8;
// docs/phase5-self-hosting-doc-2026-08-21.md §7.3).
//
// keygen's closing paragraph asserted a property OF THE PATH — "This path is
// under %LOCALAPPDATA%, not %APPDATA%" — while being gated on the operating
// system alone. Every --out an operator could name got the same sentence, so
// the one destination the paragraph exists to warn about was the one it
// reassured about.
//
// These tests fake the OS and the environment rather than skipping off-platform,
// because roadmap §8 records that WSL is structurally blind to OS-conditional
// behaviour on the platform that ships. A Windows-only advisory verified only on
// Windows is verified on the gate whose red runs prove nothing.

// fakeWindows makes keygen see a domain-joined Windows profile whichever gate is
// running the test.
func fakeWindows(t *testing.T, local, roaming string) {
	t.Helper()
	prevGOOS, prevEnv := goos, getenv
	goos = "windows"
	getenv = func(k string) string {
		switch k {
		case "LOCALAPPDATA":
			return local
		case "APPDATA":
			return roaming
		}
		return ""
	}
	t.Cleanup(func() { goos, getenv = prevGOOS, prevEnv })
}

// fakeGOOS drives the non-Windows branch from a Windows gate.
func fakeGOOS(t *testing.T, os string) {
	t.Helper()
	prev := goos
	goos = os
	t.Cleanup(func() { goos = prev })
}

// captureKeygen redirects the advisory an operator reads.
func captureKeygen(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := stdout
	stdout = &buf
	t.Cleanup(func() { stdout = prev })
	return &buf
}

// profileDirs returns a (local, roaming) pair under a temp dir, in the shape
// %LOCALAPPDATA% and %APPDATA% have on a real profile.
func profileDirs(t *testing.T) (string, string) {
	t.Helper()
	base := t.TempDir()
	return filepath.Join(base, "AppData", "Local"), filepath.Join(base, "AppData", "Roaming")
}

// TestKeygenRefusesAUNCDestination is the finding, driven at argv:
//
//	netherchat-identity keygen --out \\fileserver\share\ca
//
// This is the one destination where a warning cannot work, and that is what
// decides warn-versus-refuse. The advisory prints AFTER os.WriteFile returns —
// by then the private key is on the file server, in its backups, and on every
// restore of either, and a CA key has no in-format recovery: the only remedy is
// reaching every verifier and changing what they pinned. Deleting the file does
// not undo the copy. A message an operator cannot act on is not a warning, so
// the refusal has to come BEFORE any key material exists.
func TestKeygenRefusesAUNCDestination(t *testing.T) {
	t.Chdir(t.TempDir()) // a UNC path is one relative FILENAME on Linux; keep it out of the tree
	local, roaming := profileDirs(t)
	fakeWindows(t, local, roaming)
	out := captureKeygen(t)

	const unc = `\\fileserver\share\ca\issuer.json`
	code := runKeygen([]string{"--out", unc})

	if code == 0 {
		t.Errorf("keygen wrote a CA private key to %s and exited 0", unc)
	}
	if strings.Contains(out.String(), "%LOCALAPPDATA%") {
		t.Errorf("the advisory told the operator the key is under %%LOCALAPPDATA%%:\n%s", out.String())
	}
	// Nothing may exist yet: the refusal precedes generation, not just the write.
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("the refusal left %d file(s) behind: %v", len(entries), entries)
	}
}

// TestKeygenUNCRefusalNamesThePathAndTheWayThrough checks the refusal is usable:
// it has to say which path it refused and what to do instead, or an operator
// will reach for the nearest thing that works.
func TestKeygenUNCRefusalNamesThePathAndTheWayThrough(t *testing.T) {
	t.Chdir(t.TempDir())
	local, roaming := profileDirs(t)
	fakeWindows(t, local, roaming)

	const unc = `\\fileserver\share\ca\issuer.json`
	msg := networkPathRefusal(unc)

	if msg == "" {
		t.Fatalf("networkPathRefusal(%q) returned nothing", unc)
	}
	for _, want := range []string{unc, "--allow-network-path"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal must contain %q:\n%s", want, msg)
		}
	}
}

// TestKeygenAllowsAUNCDestinationWhenToldTo proves the override is a real way
// through and not decoration. An operator who means it must not be forced into
// something worse, like generating on a share by hand.
func TestKeygenAllowsAUNCDestinationWhenToldTo(t *testing.T) {
	dir := t.TempDir()
	local, roaming := profileDirs(t)
	fakeWindows(t, local, roaming)
	captureKeygen(t)

	// A path this test can actually write, classified as remote by the same
	// function the refusal uses — the override is what is under test, not UNC I/O.
	out := filepath.Join(dir, "issuer.json")
	prev := networkPathReason
	networkPathReason = func(string) string { return "a share on another host" }
	t.Cleanup(func() { networkPathReason = prev })

	if code := runKeygen([]string{"--out", out, "--allow-network-path"}); code != 0 {
		t.Fatalf("--allow-network-path did not let the key through: exit %d", code)
	}
	if _, err := os.Stat(out); err != nil {
		t.Errorf("no key at %s: %v", out, err)
	}
}

// TestKeygenAdvisoryOnARoamingOut is the other half of the brief's pair: an
// --out under %APPDATA% is the exact hazard the paragraph describes, and it was
// told the opposite. Unlike the UNC case a warning still works here — %APPDATA%
// roams at logoff, so the operator can still move the file — which is why this
// one warns and that one refuses.
func TestKeygenAdvisoryOnARoamingOut(t *testing.T) {
	local, roaming := profileDirs(t)
	fakeWindows(t, local, roaming)
	out := captureKeygen(t)

	path := filepath.Join(roaming, "netherchat", "issuer", "issuer.json")
	if code := runKeygen([]string{"--out", path}); code != 0 {
		t.Fatalf("keygen exit %d", code)
	}

	got := out.String()
	if strings.Contains(got, "This path is under %LOCALAPPDATA%") {
		t.Errorf("a key written under %%APPDATA%% was described as being under %%LOCALAPPDATA%%:\n%s", got)
	}
	// Case-insensitive: the assertion is about what the paragraph says, not how
	// it is typeset.
	for _, want := range []string{"%appdata%", "roam"} {
		if !strings.Contains(strings.ToLower(got), want) {
			t.Errorf("the advisory must say this path roams; it does not contain %q:\n%s", want, got)
		}
	}
}

// TestKeygenAdvisoryOnAnArbitraryOut is the case Phase 5 actually ran —
// `keygen --out ./acme-ca` — where the tool has no idea where the path leads. A
// mapped drive, a synced folder and a local directory look identical from here,
// so the honest answer is to say that. Claiming %LOCALAPPDATA% was the defect;
// claiming safety by silence would be the same defect one level up.
func TestKeygenAdvisoryOnAnArbitraryOut(t *testing.T) {
	dir := t.TempDir()
	local, roaming := profileDirs(t)
	fakeWindows(t, local, roaming)
	out := captureKeygen(t)

	path := filepath.Join(dir, "acme-ca")
	if code := runKeygen([]string{"--out", path}); code != 0 {
		t.Fatalf("keygen exit %d", code)
	}

	got := out.String()
	if strings.Contains(got, "This path is under %LOCALAPPDATA%") {
		t.Errorf("keygen --out %s was told its key is under %%LOCALAPPDATA%%:\n%s", path, got)
	}
	if !strings.Contains(got, path) {
		t.Errorf("an advisory about a path the operator named must name it:\n%s", got)
	}
}

// TestKeygenAdvisoryOnTheDefaultPath is the control: the paragraph the defect
// was found in is TRUE of the default location, and must survive intact.
func TestKeygenAdvisoryOnTheDefaultPath(t *testing.T) {
	local, roaming := profileDirs(t)
	fakeWindows(t, local, roaming)
	out := captureKeygen(t)

	if code := runKeygen(nil); code != 0 {
		t.Fatalf("keygen exit %d", code)
	}

	got := out.String()
	if !strings.Contains(got, "%LOCALAPPDATA%") || !strings.Contains(got, "%APPDATA%") {
		t.Errorf("the default path must still get the roaming-profile explanation:\n%s", got)
	}
	if want := filepath.Join(local, "netherchat", "issuer", "issuer.json"); !strings.Contains(got, want) {
		t.Errorf("the default key path %q is not in the output:\n%s", want, got)
	}
}

// TestKeygenSaysNothingAboutLocalityOffWindows is the control for the OS gate:
// the paragraph is about %APPDATA% and %LOCALAPPDATA%, which do not exist
// elsewhere, and inventing a claim off-platform would be a new instance of the
// defect rather than a fix for it. Driven with a faked GOOS so the Windows gate
// checks the Linux branch too.
func TestKeygenSaysNothingAboutLocalityOffWindows(t *testing.T) {
	dir := t.TempDir()
	fakeGOOS(t, "linux")
	out := captureKeygen(t)

	if code := runKeygen([]string{"--out", filepath.Join(dir, "issuer.json")}); code != 0 {
		t.Fatalf("keygen exit %d", code)
	}
	if got := out.String(); strings.Contains(got, "APPDATA") {
		t.Errorf("a Windows profile paragraph was printed on linux:\n%s", got)
	}
}

// TestUNCClassificationIsNotOSConditional pins the shapes the refusal fires on,
// with the OS as a parameter so both gates check both platforms. The rule is
// deliberately narrow: a leading double BACKSLASH is never a path a person types
// on purpose on POSIX, so it is refused everywhere; the forward-slash UNC form
// is real only on Windows, where //server/share is a share and //mnt/data is an
// ordinary POSIX path that must not be refused.
func TestUNCClassificationIsNotOSConditional(t *testing.T) {
	for _, tc := range []struct {
		path, os string
		remote   bool
	}{
		{`\\fileserver\share\ca`, "windows", true},
		{`\\fileserver\share\ca`, "linux", true},
		{`//fileserver/share/ca`, "windows", true},
		{`//mnt/data/ca`, "linux", false},
		{`C:\Users\ops\ca\issuer.json`, "windows", false},
		{`./acme-ca`, "linux", false},
		{`/home/ops/ca/issuer.json`, "linux", false},
		{`\\`, "windows", false}, // no host component: not a share, just malformed
	} {
		t.Run(tc.os+" "+tc.path, func(t *testing.T) {
			got := uncReason(tc.path, tc.os) != ""
			if got != tc.remote {
				t.Errorf("uncReason(%q, %q) remote=%v, want %v", tc.path, tc.os, got, tc.remote)
			}
		})
	}
}
