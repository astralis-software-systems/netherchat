package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/salehkreiner/netherchat/protocol"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/box"
)

// RoomKey is the symmetric key shared by every member of a room for one epoch.
// Messages within an epoch are sealed under Key with XChaCha20-Poly1305. A new
// epoch begins on membership change, /vanish, or rotation cadence; see the
// epoch model in ARCHITECTURE_DECISION.md §3.
type RoomKey struct {
	Epoch uint64
	Key   [32]byte
}

// NewRoomKey mints a fresh random room key at the given epoch. Used by the first
// member of a room (epoch 0) and whenever a member is ADDED — a random rekey
// ensures a newcomer cannot derive keys for epochs before it joined.
func NewRoomKey(epoch uint64) (RoomKey, error) {
	rk := RoomKey{Epoch: epoch}
	if _, err := rand.Read(rk.Key[:]); err != nil {
		return RoomKey{}, fmt.Errorf("generate room key: %w", err)
	}
	return rk, nil
}

// Ratchet derives the next epoch's key from the current one via HKDF and returns
// it. This provides forward secrecy at epoch granularity: once the caller
// discards (Zero) the old key, messages from the previous epoch cannot be
// decrypted even if the new key is later compromised. Used for rotation that
// preserves the existing membership (e.g. /vanish, time cadence), as opposed to
// NewRoomKey which is used when adding members.
func (rk RoomKey) Ratchet() (RoomKey, error) {
	r := hkdf.New(sha256.New, rk.Key[:], nil, []byte("netherchat/epoch-ratchet/v1"))
	next := RoomKey{Epoch: rk.Epoch + 1}
	if _, err := io.ReadFull(r, next.Key[:]); err != nil {
		return RoomKey{}, fmt.Errorf("ratchet room key: %w", err)
	}
	return next, nil
}

// Zero wipes the key material from memory. Best-effort (Go's GC may have copied
// it), but it shortens the window in which a deleted key sits in process memory.
func (rk *RoomKey) Zero() {
	for i := range rk.Key {
		rk.Key[i] = 0
	}
}

// WrapRoomKey seals rk for a recipient's X25519 public key using nacl/box
// (authenticated X25519 + XSalsa20-Poly1305). The box is authenticated by the
// sender's X25519 private key, so the recipient learns which member distributed
// the key. The returned nonce/wrapped blob are opaque to the relay server.
func (id *Identity) WrapRoomKey(rk RoomKey, recipientKX [32]byte) (nonce, wrapped []byte, err error) {
	var n [24]byte
	if _, err := rand.Read(n[:]); err != nil {
		return nil, nil, fmt.Errorf("nonce: %w", err)
	}
	sealed := box.Seal(nil, rk.Key[:], &n, &recipientKX, &id.KXPriv)
	return n[:], sealed, nil
}

// UnwrapRoomKey opens a key blob produced by WrapRoomKey, verifying it came from
// senderKX. Returns the room key at the given epoch.
func (id *Identity) UnwrapRoomKey(epoch uint64, nonce, wrapped []byte, senderKX [32]byte) (RoomKey, error) {
	if len(nonce) != 24 {
		return RoomKey{}, fmt.Errorf("wrap nonce wrong length: got %d, want 24", len(nonce))
	}
	var n [24]byte
	copy(n[:], nonce)
	opened, ok := box.Open(nil, wrapped, &n, &senderKX, &id.KXPriv)
	if !ok {
		return RoomKey{}, errors.New("room key unwrap failed: box authentication error")
	}
	if len(opened) != 32 {
		return RoomKey{}, fmt.Errorf("unwrapped room key wrong length: got %d, want 32", len(opened))
	}
	rk := RoomKey{Epoch: epoch}
	copy(rk.Key[:], opened)
	return rk, nil
}

// SealMessage encrypts plaintext under the room key with XChaCha20-Poly1305 and
// signs the result with the sender's Ed25519 identity key. The epoch is bound
// both into the AEAD additional data and into the signature. Returns the wire
// fields for a protocol.Message.
func (id *Identity) SealMessage(rk RoomKey, fromID string, plaintext []byte) (nonce, ciphertext, signature []byte, err error) {
	aead, err := chacha20poly1305.NewX(rk.Key[:])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("init aead: %w", err)
	}
	nonce = make([]byte, chacha20poly1305.NonceSizeX) // 24 bytes; random is safe with XChaCha
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, nil, fmt.Errorf("nonce: %w", err)
	}
	ciphertext = aead.Seal(nil, nonce, plaintext, epochAD(rk.Epoch))
	signature, err = id.Sign(protocol.SigningBytes(fromID, rk.Epoch, nonce, ciphertext))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("sign message: %w", err)
	}
	return nonce, ciphertext, signature, nil
}

// OpenMessage verifies the sender's signature and decrypts a message under the
// room key. The signature is checked BEFORE decryption so a forged ciphertext
// is rejected without touching the AEAD. senderSignPub is the sender's Ed25519
// public key, known from the room's member list.
func OpenMessage(rk RoomKey, senderSignPub ed25519.PublicKey, fromID string, epoch uint64, nonce, ciphertext, signature []byte) ([]byte, error) {
	if len(senderSignPub) != ed25519.PublicKeySize {
		return nil, errors.New("sender signing key invalid")
	}
	if !ed25519.Verify(senderSignPub, protocol.SigningBytes(fromID, epoch, nonce, ciphertext), signature) {
		return nil, errors.New("message signature verification failed")
	}
	if rk.Epoch != epoch {
		return nil, fmt.Errorf("epoch mismatch: holding key for epoch %d, message is epoch %d", rk.Epoch, epoch)
	}
	aead, err := chacha20poly1305.NewX(rk.Key[:])
	if err != nil {
		return nil, fmt.Errorf("init aead: %w", err)
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, epochAD(epoch))
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

// epochAD is the AEAD additional-authenticated-data for a message: the epoch,
// big-endian. Binding the epoch prevents a ciphertext from being reinterpreted
// under a different epoch.
func epochAD(epoch uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], epoch)
	return b[:]
}
