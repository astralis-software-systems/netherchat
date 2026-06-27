package config

import (
	"testing"
	"time"
)

// TestFreshnessDefaults: an unset [ingest.freshness] is repaired to the built-in
// 5m / 60s window by normalize().
func TestFreshnessDefaults(t *testing.T) {
	cfg, err := Parse([]byte("[[source]]\nname = \"s\"\nhmac_secret = \"x\"\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := cfg.Ingest.Freshness.Window.Std(); got != DefaultFreshnessWindow {
		t.Errorf("default window = %v, want %v", got, DefaultFreshnessWindow)
	}
	if got := cfg.Ingest.Freshness.FutureSkew.Std(); got != DefaultFreshnessFutureSkew {
		t.Errorf("default future_skew = %v, want %v", got, DefaultFreshnessFutureSkew)
	}
}

// TestFreshnessNonPositiveRepaired: a nonsensical (zero/negative) window is reverted
// to the built-in default, mirroring the limits-repair precedent.
func TestFreshnessNonPositiveRepaired(t *testing.T) {
	cfg, err := Parse([]byte("[ingest.freshness]\nwindow = \"0s\"\nfuture_skew = \"0s\"\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Ingest.Freshness.Window.Std() != DefaultFreshnessWindow {
		t.Errorf("zero window should be repaired to %v", DefaultFreshnessWindow)
	}
	if cfg.Ingest.Freshness.FutureSkew.Std() != DefaultFreshnessFutureSkew {
		t.Errorf("zero future_skew should be repaired to %v", DefaultFreshnessFutureSkew)
	}
}

// TestFreshnessOverridesParse: the global table and per-source overrides parse and
// survive normalization.
func TestFreshnessOverridesParse(t *testing.T) {
	toml := `
[ingest.freshness]
window = "10m"
future_skew = "30s"

[[source]]
name = "batch"
hmac_secret = "x"
require_fresh = true
freshness_window = "15m"
freshness_future_skew = "45s"
`
	cfg, err := Parse([]byte(toml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Ingest.Freshness.Window.Std() != 10*time.Minute {
		t.Errorf("global window = %v, want 10m", cfg.Ingest.Freshness.Window.Std())
	}
	if cfg.Ingest.Freshness.FutureSkew.Std() != 30*time.Second {
		t.Errorf("global future_skew = %v, want 30s", cfg.Ingest.Freshness.FutureSkew.Std())
	}
	s, ok := cfg.Source("batch")
	if !ok {
		t.Fatal("source batch not found")
	}
	if !s.RequireFresh {
		t.Error("require_fresh should be true")
	}
	if s.FreshnessWindow.Std() != 15*time.Minute {
		t.Errorf("per-source window = %v, want 15m", s.FreshnessWindow.Std())
	}
	if s.FreshnessFutureSkew.Std() != 45*time.Second {
		t.Errorf("per-source future_skew = %v, want 45s", s.FreshnessFutureSkew.Std())
	}
}

// TestRequireFreshNeedsHMAC: require_fresh on a token-only (or credential-less)
// source is a fail-closed config error — mandating freshness over an unsigned
// timestamp is security theater. With an hmac_secret it is valid.
func TestRequireFreshNeedsHMAC(t *testing.T) {
	bad := "[[source]]\nname = \"tok\"\ntoken = \"t\"\nrequire_fresh = true\n"
	if _, err := Parse([]byte(bad)); err == nil {
		t.Fatal("require_fresh without hmac_secret should be a config error")
	}

	good := "[[source]]\nname = \"sig\"\nhmac_secret = \"x\"\nrequire_fresh = true\n"
	if _, err := Parse([]byte(good)); err != nil {
		t.Fatalf("require_fresh with hmac_secret should be valid: %v", err)
	}
}
