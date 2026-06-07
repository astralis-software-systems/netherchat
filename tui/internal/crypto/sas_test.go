package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestPGPWordListHas512Entries(t *testing.T) {
	if len(pgpEven) != 256 {
		t.Errorf("even list has %d entries, want 256", len(pgpEven))
	}
	if len(pgpOdd) != 256 {
		t.Errorf("odd list has %d entries, want 256", len(pgpOdd))
	}
	// All 512 words must be distinct (no collisions across or within lists).
	seen := make(map[string]bool, 512)
	for _, w := range pgpEven {
		if w == "" {
			t.Error("empty word in even list")
		}
		if seen[w] {
			t.Errorf("duplicate word %q", w)
		}
		seen[w] = true
	}
	for _, w := range pgpOdd {
		if w == "" {
			t.Error("empty word in odd list")
		}
		if seen[w] {
			t.Errorf("duplicate word %q", w)
		}
		seen[w] = true
	}
	if len(seen) != 512 {
		t.Errorf("total distinct words = %d, want 512", len(seen))
	}
}

func TestSASIsDeterministicAndSymmetric(t *testing.T) {
	alice, _ := newSASParty(t)
	bob, _ := newSASParty(t)
	var rk [32]byte
	if _, err := rand.Read(rk[:]); err != nil {
		t.Fatal(err)
	}

	// Same inputs → same words (deterministic).
	a1 := SASWords(alice.sign, alice.kx, bob.sign, bob.kx, rk)
	a2 := SASWords(alice.sign, alice.kx, bob.sign, bob.kx, rk)
	if !eqWords(a1, a2) {
		t.Fatal("SAS is not deterministic")
	}
	if len(a1) != 5 {
		t.Fatalf("SAS has %d words, want 5", len(a1))
	}

	// Alice computing SAS(self=alice, peer=bob) must equal Bob computing
	// SAS(self=bob, peer=alice) — the canonical ordering makes it symmetric.
	fromAlice := SASWords(alice.sign, alice.kx, bob.sign, bob.kx, rk)
	fromBob := SASWords(bob.sign, bob.kx, alice.sign, alice.kx, rk)
	if !eqWords(fromAlice, fromBob) {
		t.Fatalf("SAS not symmetric:\n alice: %v\n   bob: %v", fromAlice, fromBob)
	}
}

func TestSASChangesWhenKeyOrPeerSubstituted(t *testing.T) {
	alice, _ := newSASParty(t)
	bob, _ := newSASParty(t)
	mitm, _ := newSASParty(t)
	var rk, rk2 [32]byte
	_, _ = rand.Read(rk[:])
	_, _ = rand.Read(rk2[:])

	base := SASWords(alice.sign, alice.kx, bob.sign, bob.kx, rk)

	// A substituted peer KX key (the classic MITM on key distribution) changes it.
	if eqWords(base, SASWords(alice.sign, alice.kx, bob.sign, mitm.kx, rk)) {
		t.Error("SAS unchanged after peer KX substitution — MITM would go undetected")
	}
	// A substituted peer identity key changes it.
	if eqWords(base, SASWords(alice.sign, alice.kx, mitm.sign, bob.kx, rk)) {
		t.Error("SAS unchanged after peer identity substitution")
	}
	// A different room key changes it.
	if eqWords(base, SASWords(alice.sign, alice.kx, bob.sign, bob.kx, rk2)) {
		t.Error("SAS unchanged after room-key change")
	}
}

type sasParty struct {
	sign ed25519.PublicKey
	kx   [32]byte
}

func newSASParty(t *testing.T) (sasParty, *Identity) {
	t.Helper()
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return sasParty{sign: id.SignPub, kx: id.KXPub}, id
}

func eqWords(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
