package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// knownRoomKey is the fixed room key used by the pinned beacon vectors.
func knownRoomKey() RoomKey {
	var rk RoomKey
	for i := range rk.Key {
		rk.Key[i] = byte(i) // 0x00..0x1f, fixed
	}
	return rk
}

// TestBeaconKeyVector pins the exact beacon-key derivation for a known room key
// (§1.2), the same way protocol/signing_test pins its bytes. The web reader derives
// the identical key value; if either side changes, beacon links stop decrypting.
func TestBeaconKeyVector(t *testing.T) {
	bk := BeaconKey(knownRoomKey())
	got := hex.EncodeToString(bk[:])
	const want = "a38aaae51f23179ce85e388f8f7ade26c44593fdc8a24f59172251d0f2520104"
	if got != want {
		t.Fatalf("BeaconKey vector changed (update web interop too):\n got %s\nwant %s", got, want)
	}
}

// TestBeaconKeyDeterministicAndDistinct proves the beacon key is deterministic for
// a given room key and is NOT the room key itself — a beacon reader can never
// recover the message key from it.
func TestBeaconKeyDeterministicAndDistinct(t *testing.T) {
	rk := knownRoomKey()
	a := BeaconKey(rk)
	b := BeaconKey(rk)
	if a != b {
		t.Fatal("BeaconKey is not deterministic")
	}
	if bytes.Equal(a[:], rk.Key[:]) {
		t.Fatal("beacon key must be DISTINCT from the room/message key")
	}
	// A different room key yields a different beacon key.
	var rk2 RoomKey
	for i := range rk2.Key {
		rk2.Key[i] = byte(0xFF - i)
	}
	if BeaconKey(rk2) == a {
		t.Fatal("different room keys must yield different beacon keys")
	}
}

// TestBeaconSealOpenRoundTrip proves a sealed beacon decrypts back to the same
// status, and that a wrong key or tampered blob fails.
func TestBeaconSealOpenRoundTrip(t *testing.T) {
	bk := BeaconKey(knownRoomKey())
	const status = "Cause isolated, mitigation deploying, ETA 20m"

	blob, err := SealBeacon(bk, status)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := OpenBeacon(bk, blob)
	if err != nil || got != status {
		t.Fatalf("round-trip: got %q err %v", got, err)
	}

	// A wrong beacon key cannot read it.
	var wrong [32]byte
	if _, err := OpenBeacon(wrong, blob); err == nil {
		t.Fatal("a wrong key must not decrypt the beacon")
	}
	// A tampered blob is rejected (AEAD integrity).
	blob[len(blob)-1] ^= 0xFF
	if _, err := OpenBeacon(bk, blob); err == nil {
		t.Fatal("a tampered blob must not decrypt")
	}
}

// TestGenBeaconInteropVector prints a Go-produced beacon vector — the derived
// beacon key and a fixed-nonce ciphertext blob — for the web reader's interop test
// to decrypt, proving the browser decrypts exactly what the TUI encrypts. Skipped
// in normal runs:
//
//	GEN_INTEROP=1 go test ./tui/internal/crypto -run TestGenBeaconInteropVector -v
func TestGenBeaconInteropVector(t *testing.T) {
	if os.Getenv("GEN_INTEROP") == "" {
		t.Skip("set GEN_INTEROP=1 to print the beacon interop vector")
	}
	bk := BeaconKey(knownRoomKey())
	const status = "SEV1 declared, cause under investigation"

	// Fixed nonce so the blob is reproducible for the pinned web vector.
	var nonce [chacha20poly1305.NonceSizeX]byte
	for i := range nonce {
		nonce[i] = byte(i)
	}
	aead, _ := chacha20poly1305.NewX(bk[:])
	ct := aead.Seal(nil, nonce[:], []byte(status), nil)
	blob := append(nonce[:], ct...)

	t.Logf("\n--- BEGIN BEACON INTEROP VECTOR ---\n"+
		"beaconKeyHex: %s\n"+
		"beaconKeyB64: %s\n"+
		"status:       %q\n"+
		"blobB64:      %s\n"+
		"--- END BEACON INTEROP VECTOR ---",
		hex.EncodeToString(bk[:]), base64.StdEncoding.EncodeToString(bk[:]),
		status, base64.StdEncoding.EncodeToString(blob))
}
