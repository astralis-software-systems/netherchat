package invite

import (
	"testing"
	"time"
)

// TestSweepReclaimsExpired drives sweep(now) with a synthetic clock, mirroring the
// ephemeral registry's TestSweepExpiresPastDeadline: a token is untouched before
// its expiry, reclaimed exactly once after it, and a re-sweep reclaims nothing.
func TestSweepReclaimsExpired(t *testing.T) {
	s := New()
	tok, exp := s.Generate("room", time.Hour)
	if exp.IsZero() {
		t.Fatal("Generate with a positive ttl should set a non-zero expiry")
	}

	// Before the deadline: nothing reclaimed.
	if n := s.sweep(exp.Add(-time.Second)); n != 0 {
		t.Fatalf("sweep before expiry reclaimed %d, want 0", n)
	}

	// After the deadline: reclaimed exactly once.
	if n := s.sweep(exp.Add(time.Second)); n != 1 {
		t.Fatalf("sweep after expiry reclaimed %d, want 1", n)
	}
	if s.Redeem(tok, "room") {
		t.Error("an expired token should be gone after the sweep")
	}

	// Idempotent: a second sweep finds nothing left to reclaim.
	if n := s.sweep(exp.Add(time.Hour)); n != 0 {
		t.Fatalf("idempotent re-sweep reclaimed %d, want 0", n)
	}
}

// TestSweepKeepsLiveToken is the safety invariant observed end to end: a sweep
// before expiry never reclaims a live token, and that token still redeems. The
// sweep can only ever delete a token Redeem would already reject.
func TestSweepKeepsLiveToken(t *testing.T) {
	s := New()
	tok, exp := s.Generate("room", time.Hour)

	if n := s.sweep(exp.Add(-time.Minute)); n != 0 {
		t.Fatalf("sweep reclaimed a live, unexpired token: %d, want 0", n)
	}
	if !s.Redeem(tok, "room") {
		t.Error("a live token must still redeem after a pre-expiry sweep")
	}
}

// TestSweepSkipsZeroExpiry confirms a no-expiry token (ttl 0) is never reclaimed,
// even at a far-future now — matching Redeem, which never expires a zero-expiry
// token.
func TestSweepSkipsZeroExpiry(t *testing.T) {
	s := New()
	tok, exp := s.Generate("room", 0) // 0 ttl = no expiry
	if !exp.IsZero() {
		t.Fatalf("Generate with ttl 0 should leave expiry zero, got %s", exp)
	}

	if n := s.sweep(time.Now().Add(100 * time.Hour)); n != 0 {
		t.Fatalf("sweep reclaimed a zero-expiry token: %d, want 0", n)
	}
	if !s.Redeem(tok, "room") {
		t.Error("a zero-expiry token must still redeem after the sweep")
	}
}
