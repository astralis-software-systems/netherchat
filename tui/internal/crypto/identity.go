// Package crypto implements Netherchat's client-side end-to-end encryption.
//
// It is deliberately placed under tui/internal so that Go's internal-package
// rule makes it importable ONLY by code rooted at tui/. The server tree cannot
// link it, which is how "the server cannot read your messages" becomes a
// compile-time guarantee rather than a promise (ARCHITECTURE_DECISION.md §3, §5).
//
// v1 primitives (all pure Go — no cgo — so the static binary and trivial
// cross-compilation survive):
//
//   - Ed25519 (crypto/ed25519)                  identity, signatures, fingerprint
//   - X25519 + XSalsa20-Poly1305 (nacl/box)      room-key wrapping (key agreement)
//   - XChaCha20-Poly1305 (x/crypto)              message AEAD (24-byte random nonce)
//   - HKDF-SHA256 (x/crypto)                     forward-secret epoch ratchet
//
// The group scheme is intentionally shaped around epochs + per-epoch room keys
// so it can be swapped for MLS/TreeKEM behind a stable interface later.
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// Identity is a client's long-term key material. It is generated once on first
// run and stored locally with 0600 permissions. The private halves are NEVER
// transmitted. There is no escrow and no recovery: lose this file and you lose
// access. That is a feature, documented prominently (requirement 5).
type Identity struct {
	SignPub  ed25519.PublicKey  // Ed25519 public  (32 bytes)
	SignPriv ed25519.PrivateKey // Ed25519 private (64 bytes, embeds the public key)
	KXPub    [32]byte           // X25519 public
	KXPriv   [32]byte           // X25519 private
}

// GenerateIdentity creates a fresh identity from the system CSPRNG.
func GenerateIdentity() (*Identity, error) {
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	kxPub, kxPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate x25519 key: %w", err)
	}
	return &Identity{SignPub: signPub, SignPriv: signPriv, KXPub: *kxPub, KXPriv: *kxPriv}, nil
}

// identityFile is the on-disk JSON form. Only the private keys are stored; the
// public keys are derived on load, so the file cannot become internally
// inconsistent.
type identityFile struct {
	Comment  string `json:"_comment"`
	SignPriv string `json:"sign_priv"` // base64, 64 bytes
	KXPriv   string `json:"kx_priv"`   // base64, 32 bytes
}

const identityComment = "Netherchat private identity. Keep this secret. There is NO recovery if lost."

// DefaultIdentityPath returns the per-user identity file location
// (%AppData%\netherchat on Windows, ~/.config/netherchat on Linux,
// ~/Library/Application Support/netherchat on macOS).
func DefaultIdentityPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "netherchat", "identity.json"), nil
}

// LoadOrCreateIdentity loads the identity at path, generating and persisting a
// new one if the file does not exist. The bool result reports whether a new
// identity was created.
func LoadOrCreateIdentity(path string) (id *Identity, created bool, err error) {
	if _, statErr := os.Stat(path); statErr == nil {
		id, err = loadIdentity(path)
		return id, false, err
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, false, statErr
	}
	id, err = GenerateIdentity()
	if err != nil {
		return nil, false, err
	}
	if err = id.Save(path); err != nil {
		return nil, false, err
	}
	return id, true, nil
}

func loadIdentity(path string) (*Identity, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f identityFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("parse identity file: %w", err)
	}
	signPriv, err := base64.StdEncoding.DecodeString(f.SignPriv)
	if err != nil {
		return nil, fmt.Errorf("decode sign_priv: %w", err)
	}
	if len(signPriv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("sign_priv wrong length: got %d, want %d", len(signPriv), ed25519.PrivateKeySize)
	}
	kxPriv, err := base64.StdEncoding.DecodeString(f.KXPriv)
	if err != nil {
		return nil, fmt.Errorf("decode kx_priv: %w", err)
	}
	if len(kxPriv) != 32 {
		return nil, fmt.Errorf("kx_priv wrong length: got %d, want 32", len(kxPriv))
	}

	id := &Identity{SignPriv: ed25519.PrivateKey(signPriv)}
	id.SignPub = id.SignPriv.Public().(ed25519.PublicKey)
	copy(id.KXPriv[:], kxPriv)
	// Derive the X25519 public key from the private scalar (clamped per RFC 7748
	// inside curve25519.X25519), matching what box.GenerateKey produced.
	pub, err := curve25519.X25519(id.KXPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive x25519 public: %w", err)
	}
	copy(id.KXPub[:], pub)
	return id, nil
}

// Save writes the identity to path with 0600 permissions, creating parent
// directories (0700) as needed.
func (id *Identity) Save(path string) error {
	f := identityFile{
		Comment:  identityComment,
		SignPriv: base64.StdEncoding.EncodeToString(id.SignPriv),
		KXPriv:   base64.StdEncoding.EncodeToString(id.KXPriv[:]),
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// Fingerprint returns a human-readable fingerprint of this identity's public
// signing key, for display by /whoami and for out-of-band verification.
func (id *Identity) Fingerprint() string { return Fingerprint(id.SignPub) }

// Fingerprint computes the display fingerprint of an Ed25519 public key:
// the SHA-256 of the key, rendered as the first 16 bytes in colon-separated hex.
func Fingerprint(signPub ed25519.PublicKey) string {
	sum := sha256.Sum256(signPub)
	parts := make([]string, 8)
	for i := 0; i < 8; i++ {
		parts[i] = hex.EncodeToString(sum[i*2 : i*2+2])
	}
	return strings.ToUpper(strings.Join(parts, ":"))
}

// ToKX converts a 32-byte slice (as carried on the wire) into an X25519 key.
func ToKX(b []byte) (out [32]byte, err error) {
	if len(b) != 32 {
		return out, fmt.Errorf("x25519 key wrong length: got %d, want 32", len(b))
	}
	copy(out[:], b)
	return out, nil
}

// ToSignPub validates and converts a 32-byte slice into an Ed25519 public key.
func ToSignPub(b []byte) (ed25519.PublicKey, error) {
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ed25519 key wrong length: got %d, want %d", len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}
