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
// As of Sprint 1, the identity is BRING-YOUR-OWN-KEY: it is the Ed25519 key you
// already have — an OpenSSH key file, ssh-agent, or an age seed — with the X25519
// key-agreement key DERIVED from it (RFC 8032 → RFC 7748, see convert.go). The
// signing key may live in ssh-agent and never enter this process; everything
// goes through the Signer abstraction.
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"
)

// Signer produces Ed25519 signatures for an identity. For local key files the
// private key is in memory; for ssh-agent the operation is delegated to the agent
// and the private key never enters this process. Sign returns the raw 64-byte
// Ed25519 signature (verifiable with ed25519.Verify against SignPub).
type Signer interface {
	Public() ed25519.PublicKey
	Sign(message []byte) ([]byte, error)
}

// localSigner signs with an in-memory Ed25519 private key.
type localSigner struct{ priv ed25519.PrivateKey }

func (s localSigner) Public() ed25519.PublicKey { return s.priv.Public().(ed25519.PublicKey) }
func (s localSigner) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, message), nil
}

// Identity is a client's long-term key material. The Ed25519 signing half is the
// trust anchor (its fingerprint is what /whois shows and what peers verify out of
// band); the X25519 half wraps room keys. The signing private key is NEVER
// transmitted, and for ssh-agent identities it never even loads into this
// process. There is no escrow and no recovery (requirement 5).
type Identity struct {
	SignPub ed25519.PublicKey // Ed25519 public  (32 bytes) — the identity
	KXPub   [32]byte          // X25519 public   (derived from SignPub)
	KXPriv  [32]byte          // X25519 private  (derived; in memory)
	Source  string            // human label: "ssh-agent", "~/.ssh/id_ed25519", "generated", …

	signer Signer
}

// Sign produces an Ed25519 signature over message using the identity's signing
// key (locally or via ssh-agent).
func (id *Identity) Sign(message []byte) ([]byte, error) {
	if id.signer == nil {
		return nil, errors.New("identity has no signer")
	}
	return id.signer.Sign(message)
}

// Fingerprint returns the SSH-style fingerprint of this identity's public signing
// key — "SHA256:<base64>", byte-for-byte identical to `ssh-keygen -lf` output so
// an engineer can compare the two side by side.
func (id *Identity) Fingerprint() string { return Fingerprint(id.SignPub) }

// Fingerprint computes the SSH SHA-256 fingerprint of an Ed25519 public key. It
// is exactly ssh.FingerprintSHA256 over the SSH wire encoding of the key, which
// is what `ssh-keygen -lf` prints. This format is the trust contract: any
// deviation breaks side-by-side comparison with a published key.
func Fingerprint(signPub ed25519.PublicKey) string {
	pub, err := ssh.NewPublicKey(signPub)
	if err != nil {
		return ""
	}
	return ssh.FingerprintSHA256(pub)
}

// GenerateIdentity creates a fresh identity from the system CSPRNG, deriving the
// X25519 key-agreement key from the Ed25519 seed (the unified BYO-key model).
// This is the last-resort source when no real key is available.
func GenerateIdentity() (*Identity, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	return identityFromEd25519(priv, "generated")
}

// identityFromEd25519 builds an Identity from an in-memory Ed25519 private key,
// deriving the X25519 key-agreement keypair via RFC 8032 → RFC 7748 conversion.
func identityFromEd25519(priv ed25519.PrivateKey, source string) (*Identity, error) {
	pub := priv.Public().(ed25519.PublicKey)
	kxPub, err := ed25519PublicToCurve25519(pub)
	if err != nil {
		return nil, fmt.Errorf("derive x25519 public: %w", err)
	}
	return &Identity{
		SignPub: pub,
		KXPub:   kxPub,
		KXPriv:  ed25519PrivateToCurve25519(priv),
		Source:  source,
		signer:  localSigner{priv},
	}, nil
}

// identityFile is the on-disk JSON form of the generated/legacy identity. The
// public keys are derived on load, so the file cannot become inconsistent.
type identityFile struct {
	Comment  string `json:"_comment"`
	SignPriv string `json:"sign_priv"` // base64, 64 bytes
	KXPriv   string `json:"kx_priv"`   // base64, 32 bytes
}

const identityComment = "Netherchat private identity. Keep this secret. There is NO recovery if lost."

// DefaultIdentityPath returns the per-user generated-identity file location
// (%AppData%\netherchat on Windows, ~/.config/netherchat on Linux,
// ~/Library/Application Support/netherchat on macOS).
func DefaultIdentityPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "netherchat", "identity.json"), nil
}

// LoadOrCreateIdentity loads the generated identity at path, creating and
// persisting a new one if absent. It is the last two steps (e, f) of the BYO-key
// cascade; see ResolveIdentity for the full precedence.
func LoadOrCreateIdentity(path string) (id *Identity, created bool, err error) {
	if _, statErr := os.Stat(path); statErr == nil {
		id, err = loadIdentityFile(path)
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

// loadIdentityFile loads the legacy/generated JSON identity. The stored X25519
// private key is honored as-is (older identities used an independent X25519 key),
// so existing identities keep working unchanged.
func loadIdentityFile(path string) (*Identity, error) {
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

	priv := ed25519.PrivateKey(signPriv)
	id := &Identity{
		SignPub: priv.Public().(ed25519.PublicKey),
		Source:  identityFileSource(path),
		signer:  localSigner{priv},
	}
	copy(id.KXPriv[:], kxPriv)
	pub, err := curve25519.X25519(id.KXPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive x25519 public: %w", err)
	}
	copy(id.KXPub[:], pub)
	return id, nil
}

func identityFileSource(path string) string {
	if def, err := DefaultIdentityPath(); err == nil && def == path {
		return "generated (~/.config/netherchat/identity.json)"
	}
	return path
}

// Save writes the identity to path with 0600 permissions. It stores the Ed25519
// private key and the derived X25519 private key (kept in the same format older
// identities used, so the file round-trips through loadIdentityFile). It only
// works for local identities (ssh-agent identities cannot be exported).
func (id *Identity) Save(path string) error {
	ls, ok := id.signer.(localSigner)
	if !ok {
		return errors.New("cannot save a delegated (ssh-agent) identity to disk")
	}
	f := identityFile{
		Comment:  identityComment,
		SignPriv: base64.StdEncoding.EncodeToString(ls.priv),
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
