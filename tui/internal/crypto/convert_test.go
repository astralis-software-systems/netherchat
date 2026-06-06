package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// TestEd25519ToCurve25519Consistency is the correctness anchor for the
// conversion: the X25519 public key derived from the Ed25519 PUBLIC key
// (Edwards→Montgomery) must equal the X25519 public key derived from the
// converted PRIVATE scalar (scalar·basepoint). If both conversions agree for
// random keys, the pair is a valid X25519 keypair and matches libsodium.
func TestEd25519ToCurve25519Consistency(t *testing.T) {
	for i := 0; i < 50; i++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate: %v", err)
		}

		kxPub, err := ed25519PublicToCurve25519(pub)
		if err != nil {
			t.Fatalf("public conversion: %v", err)
		}
		kxPriv := ed25519PrivateToCurve25519(priv)

		fromPriv, err := curve25519.X25519(kxPriv[:], curve25519.Basepoint)
		if err != nil {
			t.Fatalf("X25519: %v", err)
		}
		if [32]byte(fromPriv) != kxPub {
			t.Fatalf("iter %d: pk-converted X25519 key != sk-converted X25519 key\n pub-derived: %x\npriv-derived: %x", i, kxPub, fromPriv)
		}
	}
}

// TestConvertedKeyAgreementWorks proves the converted keys actually do ECDH:
// two identities converted from Ed25519 keys must reach the same shared secret.
func TestConvertedKeyAgreementWorks(t *testing.T) {
	_, aPriv, _ := ed25519.GenerateKey(rand.Reader)
	bPub, bPriv, _ := ed25519.GenerateKey(rand.Reader)
	aPubEd, _, _ := ed25519.GenerateKey(rand.Reader)
	_ = aPubEd

	aKXPriv := ed25519PrivateToCurve25519(aPriv)
	aKXPub, _ := ed25519PublicToCurve25519(aPriv.Public().(ed25519.PublicKey))
	bKXPriv := ed25519PrivateToCurve25519(bPriv)
	bKXPub, _ := ed25519PublicToCurve25519(bPub)

	ab, err := curve25519.X25519(aKXPriv[:], bKXPub[:])
	if err != nil {
		t.Fatalf("ab: %v", err)
	}
	ba, err := curve25519.X25519(bKXPriv[:], aKXPub[:])
	if err != nil {
		t.Fatalf("ba: %v", err)
	}
	if string(ab) != string(ba) {
		t.Fatal("ECDH shared secrets differ between converted keys")
	}
}
