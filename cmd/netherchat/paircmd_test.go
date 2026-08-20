package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/salehkreiner/netherchat/server/config"
)

// These tests pin the [direct] table to an EFFECT. Both fields parsed cleanly and
// were read by nothing: an operator who set `lan_discovery = true` got no mDNS
// advertisement, and `port = 7777` got a random free port — the same silent-accept
// class as tls_cert/tls_key, which the server config now rejects outright. Here the
// honest fix was to wire them, because the mDNS advertise path already existed
// (sneakernet.Advertise, session.go RunHost) and had no way to be switched on.

func TestDirectPortFlagWinsOverConfig(t *testing.T) {
	if got := directPort(9000, 7777); got != 9000 {
		t.Errorf("--port 9000 with config port 7777 = %d, want 9000 (the flag is more specific)", got)
	}
}

func TestDirectPortFallsBackToConfig(t *testing.T) {
	// 0 is the flag default ("a free port"), so it means "unset" and the config
	// default applies. Without this, `[direct] port` was inert.
	if got := directPort(0, 7777); got != 7777 {
		t.Errorf("unset --port with config port 7777 = %d, want 7777", got)
	}
}

func TestDirectPortUnsetEverywhereIsFreePort(t *testing.T) {
	if got := directPort(0, 0); got != 0 {
		t.Errorf("unset at both levels = %d, want 0 (a free port)", got)
	}
}

// TestDirectConfigIsRead is the regression guard proper: a config that sets
// [direct] must round-trip into the values pairCmd hands to sneakernet.Options. If
// someone drops the wiring, the table goes back to parsing and doing nothing.
func TestDirectConfigIsRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "netherchat.toml")
	if err := os.WriteFile(path, []byte("[direct]\nport = 7777\nlan_discovery = true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, source, err := loadClientConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if source != path {
		t.Fatalf("source = %q, want %q", source, path)
	}
	if cfg.Direct.Port != 7777 {
		t.Errorf("cfg.Direct.Port = %d, want 7777", cfg.Direct.Port)
	}
	if !cfg.Direct.LANDiscovery {
		t.Error("cfg.Direct.LANDiscovery = false, want true")
	}
	if got := directPort(0, cfg.Direct.Port); got != 7777 {
		t.Errorf("resolved listener port = %d, want the configured 7777", got)
	}
	if !directLAN(false, cfg.Direct.LANDiscovery) {
		t.Error("lan_discovery = true must enable mDNS advertising without --lan")
	}
}

// TestLANFlagIsNotDisabledByConfig: --lan selects the discovery mode outright, so a
// config default must never switch it off. Config raises the floor; the flag is
// authoritative. (The inverse — config silently disabling a requested flag — is the
// same silent-degradation trap, just pointed the other way.)
func TestLANFlagIsNotDisabledByConfig(t *testing.T) {
	cfg := config.Default() // LANDiscovery false
	if !directLAN(true, cfg.Direct.LANDiscovery) {
		t.Error("--lan must stay on regardless of lan_discovery")
	}
	if directLAN(false, false) {
		t.Error("neither flag nor config set must leave advertising off")
	}
}

// THE PAIR COMMAND COULD NOT PROVISION A CREDENTIAL AT ALL.
//
// `connect` has taken --attestation since Phase 3a; `pair` never did. The wire
// carries the field in both modes now, and Phase 3a routed the artifact ops
// through the coordinator, but an operator in relay-less mode had no way to put
// a credential on either — so pair mode was structurally credential-free while
// every layer beneath it was ready. That is the shape roadmap §8 names: the test
// has to start above the surface a user touches, and the surface is the flag.

func TestPairAcceptsAnAttestation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")
	writeTestAttestation(t, path)

	opts, mode, err := pairOptions([]string{"--manual", "--attestation", path}, config.Default())
	if err != nil {
		t.Fatalf("pairOptions: %v", err)
	}
	if mode != pairModeHost {
		t.Fatalf("mode = %q, want %q", mode, pairModeHost)
	}
	if opts.Credential == nil {
		t.Fatal("--attestation parsed and was dropped: sneakernet.Options.Credential is nil, so the " +
			"relay-less Hello would carry nothing")
	}
	if opts.Credential.Principal != "rosa.alvarez@acme.example" {
		t.Errorf("Credential.Principal = %q, want the artifact's", opts.Credential.Principal)
	}
}

func TestPairWithoutAnAttestationCarriesNone(t *testing.T) {
	opts, _, err := pairOptions([]string{"--manual"}, config.Default())
	if err != nil {
		t.Fatalf("pairOptions: %v", err)
	}
	if opts.Credential != nil {
		t.Errorf("no --attestation produced a credential: %+v", opts.Credential)
	}
}

// A broken --attestation is fatal rather than a quiet join without it, matching
// `connect`: an operator who named one asked for it.
func TestPairRefusesABrokenAttestation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "broken.json")
	if err := os.WriteFile(path, []byte("{not an artifact"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := pairOptions([]string{"--manual", "--attestation", path}, config.Default()); err == nil {
		t.Fatal("a broken --attestation was accepted; pair would have joined carrying nothing")
	}
	if _, _, err := pairOptions([]string{"--manual", "--attestation", filepath.Join(dir, "absent.json")}, config.Default()); err == nil {
		t.Fatal("a missing --attestation file was accepted")
	}
}

// writeTestAttestation writes a signed artifact to path, using the same builder
// the identity command's tests use.
func writeTestAttestation(t *testing.T, path string) {
	t.Helper()
	a, _ := mkAttestation(t)
	b, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}
