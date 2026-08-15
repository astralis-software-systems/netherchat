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
