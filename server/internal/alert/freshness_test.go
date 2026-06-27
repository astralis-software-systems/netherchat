package alert

import (
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/server/config"
)

// fixedGuards returns a guard set whose clock is pinned to now, so the window
// arithmetic is deterministic at the boundaries.
func fixedGuards(now time.Time) *Guards {
	g := NewGuards()
	g.now = func() time.Time { return now }
	return g
}

// freshDef is the resolved global default a normalized config would supply.
func freshDef() config.FreshnessConfig {
	return config.FreshnessConfig{
		Window:     config.Duration(config.DefaultFreshnessWindow),
		FutureSkew: config.Duration(config.DefaultFreshnessFutureSkew),
	}
}

func hmacSrc(name string) config.SourceConfig {
	return config.SourceConfig{Name: name, HMACSecret: "x"}
}

// TestAllowFreshStale: an HMAC source whose signed ts is older than the window is
// rejected with the distinct "stale timestamp" reason.
func TestAllowFreshStale(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	g := fixedGuards(now)
	ts := now.Add(-config.DefaultFreshnessWindow - time.Second).Unix()
	ok, reason, warn := g.AllowFresh(hmacSrc("siem"), ts, freshDef())
	if ok {
		t.Fatal("ts older than the window should be rejected")
	}
	if reason != "stale timestamp" {
		t.Fatalf("reason = %q, want %q", reason, "stale timestamp")
	}
	if warn != "" {
		t.Errorf("rejection should carry no warn, got %q", warn)
	}
}

// TestAllowFreshInWindow: a ts well inside the window is accepted.
func TestAllowFreshInWindow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	g := fixedGuards(now)
	ts := now.Add(-config.DefaultFreshnessWindow / 2).Unix()
	if ok, reason, _ := g.AllowFresh(hmacSrc("siem"), ts, freshDef()); !ok {
		t.Fatalf("in-window ts should be accepted, got reason %q", reason)
	}
}

// TestAllowFreshFutureSkew: a ts within the future-skew tolerance is accepted; one
// further ahead is rejected with the distinct "future timestamp" reason.
func TestAllowFreshFutureSkew(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	g := fixedGuards(now)

	within := now.Add(config.DefaultFreshnessFutureSkew / 2).Unix()
	if ok, reason, _ := g.AllowFresh(hmacSrc("siem"), within, freshDef()); !ok {
		t.Fatalf("ts within future skew should be accepted, got reason %q", reason)
	}

	ahead := now.Add(config.DefaultFreshnessFutureSkew + time.Second).Unix()
	ok, reason, _ := g.AllowFresh(hmacSrc("siem"), ahead, freshDef())
	if ok {
		t.Fatal("ts beyond future skew should be rejected")
	}
	if reason != "future timestamp" {
		t.Fatalf("reason = %q, want %q", reason, "future timestamp")
	}
}

// TestAllowFreshTSZeroBaseline: under the enforce-if-present baseline a ts==0 HMAC
// source passes, and the freshness-inactive warning is emitted exactly once.
func TestAllowFreshTSZeroBaseline(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	g := fixedGuards(now)
	src := hmacSrc("legacy")

	ok, reason, warn := g.AllowFresh(src, 0, freshDef())
	if !ok || reason != "" {
		t.Fatalf("ts==0 baseline should pass: ok=%v reason=%q", ok, reason)
	}
	if warn == "" {
		t.Fatal("first ts==0 should emit a freshness-inactive warning")
	}

	// De-duped: the same source does not warn again.
	if _, _, warn2 := g.AllowFresh(src, 0, freshDef()); warn2 != "" {
		t.Fatalf("ts==0 warning should fire once per source, got %q on second call", warn2)
	}
}

// TestAllowFreshRequireFreshRejectsMissing: require_fresh escalates to strict — a
// ts==0 is rejected rather than passed-with-warning.
func TestAllowFreshRequireFreshRejectsMissing(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	g := fixedGuards(now)
	src := config.SourceConfig{Name: "strict", HMACSecret: "x", RequireFresh: true}
	ok, reason, _ := g.AllowFresh(src, 0, freshDef())
	if ok {
		t.Fatal("require_fresh must reject a missing timestamp")
	}
	if reason == "" {
		t.Fatal("rejection must carry a reason")
	}
}

// TestAllowFreshTokenOnlyInert: a token-only source (no hmac_secret) has an unsigned
// ts, so freshness is inert even for a wildly out-of-window timestamp.
func TestAllowFreshTokenOnlyInert(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	g := fixedGuards(now)
	src := config.SourceConfig{Name: "tok", Token: "t"} // no HMACSecret
	ts := now.Add(-24 * time.Hour).Unix()
	ok, reason, warn := g.AllowFresh(src, ts, freshDef())
	if !ok || reason != "" || warn != "" {
		t.Fatalf("token-only freshness must be inert: ok=%v reason=%q warn=%q", ok, reason, warn)
	}
}

// TestAllowFreshPerSourceIsolation: two sources sharing one Guards are judged
// independently against their own timestamps.
func TestAllowFreshPerSourceIsolation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	g := fixedGuards(now)
	stale := now.Add(-2 * config.DefaultFreshnessWindow).Unix()
	fresh := now.Add(-time.Minute).Unix()

	if ok, _, _ := g.AllowFresh(hmacSrc("A"), stale, freshDef()); ok {
		t.Error("source A out-of-window should be rejected")
	}
	if ok, _, _ := g.AllowFresh(hmacSrc("B"), fresh, freshDef()); !ok {
		t.Error("source B in-window should be accepted")
	}
}

// TestAllowFreshPerSourceOverride: a per-source freshness_window override widens the
// acceptance window beyond the global default.
func TestAllowFreshPerSourceOverride(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	g := fixedGuards(now)
	ts := now.Add(-6 * time.Minute).Unix() // older than the 5m global, within a 10m override

	if ok, _, _ := g.AllowFresh(hmacSrc("base"), ts, freshDef()); ok {
		t.Fatal("6-minute-old ts should be rejected under the 5m global default")
	}

	override := config.SourceConfig{Name: "batch", HMACSecret: "x", FreshnessWindow: config.Duration(10 * time.Minute)}
	if ok, _, _ := g.AllowFresh(override, ts, freshDef()); !ok {
		t.Fatal("6-minute-old ts should be accepted under the 10m per-source override")
	}
}

// TestAllowFreshNilReceiver: a nil Guards allows everything (consistent with the
// existing AllowRequest/AllowSpawn nil-receiver contract).
func TestAllowFreshNilReceiver(t *testing.T) {
	var g *Guards
	if ok, _, _ := g.AllowFresh(hmacSrc("x"), 0, freshDef()); !ok {
		t.Error("nil guards must allow everything")
	}
}

// TestAllowFreshFallsBackWhenDefZero: even with an un-normalized (zero) global
// default, the gate falls back to the built-in window rather than treating every
// real ts as stale.
func TestAllowFreshFallsBackWhenDefZero(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	g := fixedGuards(now)
	ts := now.Add(-time.Minute).Unix()
	if ok, reason, _ := g.AllowFresh(hmacSrc("siem"), ts, config.FreshnessConfig{}); !ok {
		t.Fatalf("zero def should fall back to built-in window, got reason %q", reason)
	}
}
