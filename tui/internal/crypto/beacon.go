package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Status Beacon crypto (§1.2). A beacon publishes a single mutable status line to
// out-of-band stakeholders through a short-TTL link, encrypted to a key DERIVED
// from — but DISTINCT from — the room's message group key. A reader who holds the
// beacon key can decrypt the status but CANNOT read room messages (those use the
// room key directly); a room member can derive the beacon key and update it.

// beaconKeyInfo domain-separates the beacon key from the message key and from the
// epoch ratchet. Must match the web reader (web/src/crypto, "netherchat/beacon/v1").
const beaconKeyInfo = "netherchat/beacon/v1"

// BeaconKey derives the beacon key from a room key:
//
//	beacon_key = HKDF-SHA256(room_key, salt=nil, info="netherchat/beacon/v1")[:32]
//
// It is deterministic (the same room key always yields the same beacon key) and
// distinct from the room key, so handing out the beacon key never exposes the
// message key. The browser reader derives the identical key value, embedded in the
// beacon link.
func BeaconKey(rk RoomKey) [32]byte {
	r := hkdf.New(sha256.New, rk.Key[:], nil, []byte(beaconKeyInfo))
	var k [32]byte
	_, _ = io.ReadFull(r, k[:]) // 32 bytes from HKDF-SHA256 never short-reads
	return k
}

// SealBeacon encrypts a status line under the beacon key with XChaCha20-Poly1305
// and returns nonce(24) || ciphertext — the opaque blob the relay stores and the
// web reader decrypts. There is no AAD: the beacon key is already room/epoch
// specific, and keeping the format minimal lets the browser reader (which holds
// only the key) decrypt without any side data.
func SealBeacon(beaconKey [32]byte, status string) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(beaconKey[:])
	if err != nil {
		return nil, fmt.Errorf("init beacon aead: %w", err)
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX) // 24 bytes; random is safe with XChaCha
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("beacon nonce: %w", err)
	}
	ct := aead.Seal(nil, nonce, []byte(status), nil)
	return append(nonce, ct...), nil
}

// OpenBeacon decrypts a blob produced by SealBeacon under the same beacon key.
func OpenBeacon(beaconKey [32]byte, blob []byte) (string, error) {
	if len(blob) < chacha20poly1305.NonceSizeX {
		return "", errors.New("beacon blob too short")
	}
	aead, err := chacha20poly1305.NewX(beaconKey[:])
	if err != nil {
		return "", fmt.Errorf("init beacon aead: %w", err)
	}
	nonce, ct := blob[:chacha20poly1305.NonceSizeX], blob[chacha20poly1305.NonceSizeX:]
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt beacon: %w", err)
	}
	return string(pt), nil
}
