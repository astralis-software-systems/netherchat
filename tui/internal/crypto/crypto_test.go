package crypto

import (
	"bytes"
	"crypto/ed25519"
	"path/filepath"
	"testing"
)

func mustIdentity(t *testing.T) *Identity {
	t.Helper()
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	return id
}

func TestIdentitySaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	id, created, err := LoadOrCreateIdentity(path)
	if err != nil {
		t.Fatalf("LoadOrCreateIdentity (create): %v", err)
	}
	if !created {
		t.Fatal("expected created=true on first call")
	}

	loaded, created, err := LoadOrCreateIdentity(path)
	if err != nil {
		t.Fatalf("LoadOrCreateIdentity (load): %v", err)
	}
	if created {
		t.Fatal("expected created=false on second call")
	}

	if !bytes.Equal(id.SignPub, loaded.SignPub) {
		t.Error("sign public key changed across save/load")
	}
	if id.KXPriv != loaded.KXPriv {
		t.Error("x25519 private key changed across save/load")
	}
	if id.KXPub != loaded.KXPub {
		t.Error("x25519 public key (derived on load) does not match original")
	}
	if id.Fingerprint() != loaded.Fingerprint() {
		t.Error("fingerprint not stable across save/load")
	}

	// The reloaded identity must still be able to sign verifiably (the private
	// signing key survived the round-trip).
	sig, err := loaded.Sign([]byte("round-trip"))
	if err != nil {
		t.Fatalf("Sign after reload: %v", err)
	}
	if !ed25519.Verify(loaded.SignPub, []byte("round-trip"), sig) {
		t.Error("signature from reloaded identity does not verify")
	}
}

func TestRoomKeyWrapUnwrap(t *testing.T) {
	alice := mustIdentity(t)
	bob := mustIdentity(t)

	rk, err := NewRoomKey(0)
	if err != nil {
		t.Fatalf("NewRoomKey: %v", err)
	}

	// Alice wraps the room key for Bob and sends nonce+blob through the (blind) server.
	nonce, wrapped, err := alice.WrapRoomKey(rk, bob.KXPub)
	if err != nil {
		t.Fatalf("WrapRoomKey: %v", err)
	}
	// The wrapped blob must not contain the raw key (sanity: it's encrypted).
	if bytes.Contains(wrapped, rk.Key[:]) {
		t.Fatal("wrapped key blob leaks the raw room key")
	}

	got, err := bob.UnwrapRoomKey(rk.Epoch, nonce, wrapped, alice.KXPub)
	if err != nil {
		t.Fatalf("UnwrapRoomKey: %v", err)
	}
	if got.Key != rk.Key || got.Epoch != rk.Epoch {
		t.Fatal("unwrapped room key does not match original")
	}

	// Unwrapping with the wrong sender key must fail (authentication).
	mallory := mustIdentity(t)
	if _, err := bob.UnwrapRoomKey(rk.Epoch, nonce, wrapped, mallory.KXPub); err == nil {
		t.Fatal("expected unwrap to fail with wrong sender key")
	}
}

func TestMessageSealOpenRoundTrip(t *testing.T) {
	alice := mustIdentity(t)
	rk, _ := NewRoomKey(3)
	plaintext := []byte("messaging that lives below the surface")

	nonce, ct, sig, err := alice.SealMessage(rk, "alice-id", plaintext)
	if err != nil {
		t.Fatalf("SealMessage: %v", err)
	}
	if bytes.Contains(ct, plaintext) {
		t.Fatal("ciphertext contains plaintext")
	}

	got, err := OpenMessage(rk, alice.SignPub, "alice-id", rk.Epoch, nonce, ct, sig)
	if err != nil {
		t.Fatalf("OpenMessage: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plaintext)
	}
}

func TestMessageRejectsTamperedSignature(t *testing.T) {
	alice := mustIdentity(t)
	rk, _ := NewRoomKey(0)
	nonce, ct, sig, _ := alice.SealMessage(rk, "alice-id", []byte("hello"))

	// Flip a bit in the signature.
	bad := bytes.Clone(sig)
	bad[0] ^= 0x01
	if _, err := OpenMessage(rk, alice.SignPub, "alice-id", rk.Epoch, nonce, ct, bad); err == nil {
		t.Fatal("expected signature verification to fail on tampered signature")
	}

	// A different sender's key must not verify Alice's message.
	bob := mustIdentity(t)
	if _, err := OpenMessage(rk, bob.SignPub, "alice-id", rk.Epoch, nonce, ct, sig); err == nil {
		t.Fatal("expected verification to fail with wrong signing key")
	}
}

func TestMessageRejectsWrongRoomKey(t *testing.T) {
	alice := mustIdentity(t)
	rk, _ := NewRoomKey(0)
	nonce, ct, sig, _ := alice.SealMessage(rk, "alice-id", []byte("secret"))

	other, _ := NewRoomKey(0) // same epoch, different key
	if _, err := OpenMessage(other, alice.SignPub, "alice-id", rk.Epoch, nonce, ct, sig); err == nil {
		t.Fatal("expected decryption to fail under a different room key")
	}
}

func TestMessageRejectsEpochMismatch(t *testing.T) {
	alice := mustIdentity(t)
	rk, _ := NewRoomKey(5)
	nonce, ct, sig, _ := alice.SealMessage(rk, "alice-id", []byte("hi"))

	wrongEpoch := RoomKey{Epoch: 6, Key: rk.Key}
	if _, err := OpenMessage(wrongEpoch, alice.SignPub, "alice-id", 5, nonce, ct, sig); err == nil {
		t.Fatal("expected epoch-mismatch error")
	}
}

func TestRatchetIsDeterministicAndMovesForward(t *testing.T) {
	rk, _ := NewRoomKey(0)
	a, err := rk.Ratchet()
	if err != nil {
		t.Fatalf("Ratchet: %v", err)
	}
	b, _ := rk.Ratchet()
	if a.Key != b.Key {
		t.Fatal("ratchet is not deterministic")
	}
	if a.Epoch != 1 {
		t.Fatalf("ratchet epoch: got %d want 1", a.Epoch)
	}
	if a.Key == rk.Key {
		t.Fatal("ratchet produced the same key (no forward movement)")
	}
}
