package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/salehkreiner/netherchat/server/config"
)

// THE SURFACE A USER TOUCHES IS THE FLAG (roadmap §8).
//
// `--issuer` on `connect` is the whole of D-L's configuration. Every test below
// starts at argv, because the defect this rule is written from is `--issuer` and
// `--at` being parsed and dropped on `netherchat verify`'s record branch — green
// CI the whole time, because every test began under the flag parse.

func writeConnectIssuerFile(t *testing.T, dir, name string, keys ...ed25519.PublicKey) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("# an organization's issuing authority\n")
	for _, k := range keys {
		b.WriteString(base64.StdEncoding.EncodeToString(k) + "\n")
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func mkIssuerKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// TestConnectAcceptsAnIssuerPin: the flag is parsed, the file is read, and the
// keys land where the TUI will look for them. Without this the flag could parse
// and be dropped, which is the shape of the Phase 2 defect.
func TestConnectAcceptsAnIssuerPin(t *testing.T) {
	dir := t.TempDir()
	k1, k2 := mkIssuerKey(t), mkIssuerKey(t)
	path := writeConnectIssuerFile(t, dir, "acme-ca.pub", k1, k2)

	f, url := parseConnectFlags([]string{"ws://relay.example:3000", "--room", "incident-4432", "--issuer", path})
	if url != "ws://relay.example:3000" || f.room != "incident-4432" {
		t.Fatalf("the positional URL or --room was eaten by --issuer: url=%q room=%q", url, f.room)
	}
	o, err := connectOptions(f, url, config.Default())
	if err != nil {
		t.Fatalf("connectOptions: %v", err)
	}
	if len(o.issuer.Keys) != 2 {
		t.Fatalf("--issuer parsed and was dropped: %d key(s) reached the TUI, want 2", len(o.issuer.Keys))
	}
	if o.issuer.Source != path {
		t.Errorf("issuer source = %q, want the path the operator typed (%q) — /issuer has to be able to say", o.issuer.Source, path)
	}
}

// With no --issuer the TUI is handed nothing at all, which is the standalone-
// inert state: an empty key slice is not "an empty pin", it is no pin.
func TestConnectWithoutAnIssuerPinsNothing(t *testing.T) {
	f, url := parseConnectFlags([]string{"--room", "ops"})
	o, err := connectOptions(f, url, config.Default())
	if err != nil {
		t.Fatalf("connectOptions: %v", err)
	}
	if len(o.issuer.Keys) != 0 || o.issuer.Source != "" {
		t.Fatalf("a connect with no --issuer produced a pin: %+v", o.issuer)
	}
}

// Fail-closed, matching --config and --attestation: an operator who named an
// issuer file asked for their screen to check against it, and a screen that
// quietly checked against nothing would render every credential as a claim while
// the operator believed it had been verified. That is worse than not offering
// the flag.
func TestConnectRefusesABrokenIssuerFile(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct{ name, body, why string }{
		{"garbage.pub", "not a key at all\n", "unparseable"},
		{"empty.pub", "# only a comment\n", "no keys in it"},
		{"short.pub", base64.StdEncoding.EncodeToString([]byte("too short")) + "\n", "wrong key size"},
	} {
		p := filepath.Join(dir, tc.name)
		if err := os.WriteFile(p, []byte(tc.body), 0o644); err != nil {
			t.Fatal(err)
		}
		f, url := parseConnectFlags([]string{"--issuer", p})
		if _, err := connectOptions(f, url, config.Default()); err == nil {
			t.Errorf("a %s issuer file was accepted; the session would render unchecked claims as if pinned", tc.why)
		}
	}
	f, url := parseConnectFlags([]string{"--issuer", filepath.Join(dir, "absent.pub")})
	if _, err := connectOptions(f, url, config.Default()); err == nil {
		t.Error("a missing issuer file was accepted")
	}
}

// PRESENCE IS NOW, AND THERE IS NO FLAG THAT SAYS OTHERWISE.
//
// `netherchat verify` takes --at, because a record carries signed timestamps and
// re-reading one at a stated time is the point. A live surface has no such
// timestamps: its evaluation time is the instant the check ran. A --at on
// connect would let an operator choose a time at which an expired credential
// renders as checked, which is a screen configured to say something the clock
// does not support.
func TestConnectHasNoEvaluationTimeFlag(t *testing.T) {
	var f connectFlags
	fs := newConnectFlagSet(&f)
	for _, name := range []string{"at", "evaluate-at", "now"} {
		if fs.Lookup(name) != nil {
			t.Errorf("connect declares --%s; the evaluation time on a live surface is the clock, not a parameter", name)
		}
	}
	if fs.Lookup("issuer") == nil {
		t.Fatal("connect declares no --issuer; D-L is not wired to the surface a user touches")
	}
}

// The usage line is where an operator finds the flag. A flag that works and is
// undocumented is a flag nobody types.
func TestConnectUsageNamesTheIssuerFlag(t *testing.T) {
	if !strings.Contains(connectUsageLine, "--issuer") {
		t.Errorf("the connect usage line does not mention --issuer:\n%s", connectUsageLine)
	}
}
