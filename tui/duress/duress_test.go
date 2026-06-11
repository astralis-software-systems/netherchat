package duress

import (
	"bytes"
	"strings"
	"testing"

	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

func TestModeValid(t *testing.T) {
	for _, m := range []Mode{ModeSilentScuttle, ModeDecoyView} {
		if err := m.Valid(); err != nil {
			t.Errorf("mode %q should be valid: %v", m, err)
		}
	}
	if err := Mode("erase_everything").Valid(); err == nil {
		t.Error("unknown mode should be invalid")
	}
}

// TestArmZeroesInputs is the crux of "passphrase never stored": after Arm returns,
// the caller's passphrase bytes must be wiped.
func TestArmZeroesInputs(t *testing.T) {
	real := []byte("correct horse battery staple")
	duress := []byte("under duress open the decoy")
	if _, err := Arm(real, duress, ModeDecoyView); err != nil {
		t.Fatalf("arm: %v", err)
	}
	if !allZero(real) {
		t.Errorf("real passphrase not zeroed after Arm: %q", real)
	}
	if !allZero(duress) {
		t.Errorf("duress passphrase not zeroed after Arm: %q", duress)
	}
}

func TestArmRejectsBadInputs(t *testing.T) {
	if _, err := Arm([]byte("same"), []byte("same"), ModeSilentScuttle); err == nil {
		t.Error("identical real and duress credentials should be rejected")
	}
	if _, err := Arm([]byte(""), []byte("x"), ModeSilentScuttle); err == nil {
		t.Error("empty real credential should be rejected")
	}
	if _, err := Arm([]byte("x"), []byte(""), ModeSilentScuttle); err == nil {
		t.Error("empty duress credential should be rejected")
	}
	if _, err := Arm([]byte("a"), []byte("b"), Mode("nope")); err == nil {
		t.Error("invalid mode should be rejected")
	}
}

func TestEvaluateDispositions(t *testing.T) {
	real := []byte("real-unlock-phrase")
	duress := []byte("duress-unlock-phrase")
	g, err := Arm(clone(real), clone(duress), ModeSilentScuttle)
	if err != nil {
		t.Fatalf("arm: %v", err)
	}
	if d := g.Evaluate(clone(duress)); d != Duress {
		t.Errorf("duress phrase => %s, want duress", d)
	}
	if d := g.Evaluate(clone(real)); d != Normal {
		t.Errorf("real phrase => %s, want normal", d)
	}
	if d := g.Evaluate([]byte("neither of these")); d != Reject {
		t.Errorf("wrong phrase => %s, want reject", d)
	}
}

// TestEvaluateZeroesInput proves the entered attempt is wiped after evaluation.
func TestEvaluateZeroesInput(t *testing.T) {
	g, err := Arm([]byte("real"), []byte("duress"), ModeDecoyView)
	if err != nil {
		t.Fatalf("arm: %v", err)
	}
	attempt := []byte("some attempt")
	g.Evaluate(attempt)
	if !allZero(attempt) {
		t.Errorf("entered attempt not zeroed after Evaluate: %q", attempt)
	}
}

func TestGuardMode(t *testing.T) {
	g, err := Arm([]byte("r"), []byte("d"), ModeDecoyView)
	if err != nil {
		t.Fatalf("arm: %v", err)
	}
	if g.Mode() != ModeDecoyView {
		t.Errorf("mode = %q, want %q", g.Mode(), ModeDecoyView)
	}
}

func TestBeaconRoundTrip(t *testing.T) {
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	b, err := SignBeacon(id, ModeSilentScuttle, "north-site")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if b.Actor != id.Fingerprint() {
		t.Errorf("actor = %q, want %q", b.Actor, id.Fingerprint())
	}

	raw, err := b.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := ParseBeacon(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := got.Verify(); err != nil {
		t.Fatalf("round-tripped beacon failed to verify: %v", err)
	}
	if got.Mode != string(ModeSilentScuttle) || got.Context != "north-site" {
		t.Errorf("fields not preserved: mode=%q context=%q", got.Mode, got.Context)
	}
}

func TestBeaconTamperDetection(t *testing.T) {
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	b, err := SignBeacon(id, ModeDecoyView, "")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Tampered signature.
	bad := *b
	bad.Sig = clone(b.Sig)
	bad.Sig[0] ^= 0xff
	if err := bad.Verify(); err == nil {
		t.Error("tampered signature should not verify")
	}

	// Swapped mode (covered by the signature).
	bad = *b
	bad.Mode = string(ModeSilentScuttle)
	if err := bad.Verify(); err == nil {
		t.Error("swapped mode should not verify")
	}

	// Mismatched actor key (does not hash to the claimed fingerprint).
	other, _ := crypto.GenerateIdentity()
	bad = *b
	bad.ActorKey = clone(other.SignPub)
	if err := bad.Verify(); err == nil {
		t.Error("actor_key not matching the fingerprint should not verify")
	}
}

// TestBeaconCarriesNoSecret guards the boundary law: a beacon is metadata only.
// The serialized form must not contain the passphrase that armed the session.
func TestBeaconCarriesNoSecret(t *testing.T) {
	secret := "super-secret-duress-passphrase"
	if _, err := Arm([]byte("real"), []byte(secret), ModeSilentScuttle); err != nil {
		t.Fatalf("arm: %v", err)
	}
	id, _ := crypto.GenerateIdentity()
	b, err := SignBeacon(id, ModeSilentScuttle, "ctx")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw, _ := b.Marshal()
	if strings.Contains(string(raw), secret) {
		t.Fatal("beacon leaked the duress passphrase")
	}
}

func TestSelfTest(t *testing.T) {
	for _, m := range []Mode{ModeSilentScuttle, ModeDecoyView} {
		if err := SelfTest(m); err != nil {
			t.Errorf("selftest(%s): %v", m, err)
		}
	}
	if err := SelfTest(Mode("bogus")); err == nil {
		t.Error("selftest with an invalid mode should error")
	}
}

func allZero(b []byte) bool {
	return bytes.Equal(b, make([]byte, len(b)))
}
