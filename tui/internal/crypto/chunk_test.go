package crypto

import (
	"bytes"
	"testing"
)

// TestSealOpenChunkRoundTrip proves a file chunk encrypts and decrypts under the
// room key (§2.3), the ciphertext does not leak plaintext, and the epoch is bound
// as AAD so a chunk cannot be opened under a different epoch.
func TestSealOpenChunkRoundTrip(t *testing.T) {
	rk, err := NewRoomKey(7)
	if err != nil {
		t.Fatal(err)
	}
	pt := bytes.Repeat([]byte("artifact-bytes "), 5000) // ~75 KB

	nonce, ct, err := SealChunk(rk, pt)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Contains(ct, []byte("artifact-bytes")) {
		t.Fatal("ciphertext leaks plaintext")
	}

	got, err := OpenChunk(rk, nonce, ct)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatal("round-trip mismatch")
	}

	// Wrong epoch (same key bytes) must fail: the epoch is bound as AAD.
	wrong := RoomKey{Epoch: rk.Epoch + 1, Key: rk.Key}
	if _, err := OpenChunk(wrong, nonce, ct); err == nil {
		t.Fatal("opening under a different epoch should fail")
	}
}
