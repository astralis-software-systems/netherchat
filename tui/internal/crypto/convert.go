package crypto

import (
	"crypto/ed25519"
	"crypto/sha512"
	"errors"
	"math/big"
)

// This file implements the standard Ed25519 → X25519 conversion (RFC 8032 →
// RFC 7748), so a single Ed25519 identity key (an SSH key, an age seed, or a
// generated key) yields BOTH the signing key and the X25519 key-agreement key
// used to wrap room keys. The conversion is byte-compatible with libsodium's
// crypto_sign_ed25519_{pk,sk}_to_curve25519, which is what makes "your identity
// is just your SSH key" cryptographically real rather than cosmetic.

// curve25519P is the field prime 2^255 - 19 shared by Ed25519 (Edwards form) and
// X25519 (Montgomery form).
var curve25519P, _ = new(big.Int).SetString(
	"57896044618658097711785492504343953926634992332820282019728792003956564819949", 10)

// ed25519PublicToCurve25519 maps an Ed25519 public key to its X25519 public key
// via the Edwards→Montgomery birational map u = (1 + y) / (1 - y) mod p, where y
// is the Edwards y-coordinate the Ed25519 public key encodes (little-endian, with
// the x-sign bit cleared). The result is the X25519 (Montgomery u) public half of
// the key whose private half is ed25519PrivateToCurve25519 of the same key.
func ed25519PublicToCurve25519(pub ed25519.PublicKey) ([32]byte, error) {
	var out [32]byte
	if len(pub) != ed25519.PublicKeySize {
		return out, errors.New("ed25519 public key wrong length")
	}
	// y = little-endian field element with the high (sign) bit cleared.
	le := make([]byte, 32)
	copy(le, pub)
	le[31] &= 0x7f
	y := leToBig(le)
	if y.Cmp(curve25519P) >= 0 {
		return out, errors.New("ed25519 public key is not a canonical field element")
	}

	one := big.NewInt(1)
	num := new(big.Int).Add(one, y) // 1 + y
	den := new(big.Int).Sub(one, y) // 1 - y
	den.Mod(den, curve25519P)
	if den.Sign() == 0 {
		return out, errors.New("ed25519 public key has no Montgomery image (1 - y == 0)")
	}
	denInv := new(big.Int).ModInverse(den, curve25519P)
	if denInv == nil {
		return out, errors.New("field inversion failed")
	}
	u := num.Mul(num, denInv)
	u.Mod(u, curve25519P)
	bigToLE(u, out[:])
	return out, nil
}

// ed25519PrivateToCurve25519 derives the X25519 private scalar from an Ed25519
// private key: the lower 32 bytes of SHA-512(seed), clamped per RFC 7748. This is
// exactly the Ed25519 secret scalar, so it pairs with ed25519PublicToCurve25519.
func ed25519PrivateToCurve25519(priv ed25519.PrivateKey) [32]byte {
	seed := priv.Seed()
	h := sha512.Sum512(seed)
	var out [32]byte
	copy(out[:], h[:32])
	out[0] &= 248
	out[31] &= 127
	out[31] |= 64
	return out
}

// leToBig interprets b as a little-endian unsigned integer.
func leToBig(b []byte) *big.Int {
	be := make([]byte, len(b))
	for i := range b {
		be[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(be)
}

// bigToLE writes x as a fixed-width little-endian byte slice into out.
func bigToLE(x *big.Int, out []byte) {
	be := make([]byte, len(out))
	x.FillBytes(be) // big-endian, left zero-padded to len(out)
	for i := range be {
		out[len(be)-1-i] = be[i]
	}
}
