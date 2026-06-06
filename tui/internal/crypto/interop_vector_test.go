package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"testing"
)

// TestGenInteropVector prints a Go-produced message vector (a sealed,
// Ed25519-signed XChaCha20-Poly1305 message under a fixed room key) for the web
// client's cross-language interop test to consume. It is skipped in normal runs;
// run it deliberately to regenerate the frozen vector in
// web/src/net/interop.test.ts:
//
//	GEN_INTEROP=1 go test ./tui/internal/crypto -run TestGenInteropVector -v
//
// The web test then decrypts these exact bytes, proving the browser and the Go
// TUI share byte-for-byte crypto.
func TestGenInteropVector(t *testing.T) {
	if os.Getenv("GEN_INTEROP") == "" {
		t.Skip("set GEN_INTEROP=1 to regenerate the web interop vector")
	}

	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i + 1) // 0x01..0x20, fixed
	}
	signPriv := ed25519.NewKeyFromSeed(seed[:])
	id := &Identity{SignPriv: signPriv, SignPub: signPriv.Public().(ed25519.PublicKey)}

	rk := RoomKey{Epoch: 7}
	for i := range rk.Key {
		rk.Key[i] = byte(0xA0 + i) // fixed room key
	}

	const fromID = "alice-9f3c"
	const plaintext = "the database is on fire 🔥 `kubectl rollout undo`"

	nonce, ct, sig, err := id.SealMessage(rk, fromID, []byte(plaintext))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	b64 := base64.StdEncoding.EncodeToString
	t.Logf("\n--- BEGIN INTEROP VECTOR ---\n"+
		"roomKey:   %s\n"+
		"signPub:   %s\n"+
		"fromID:    %s\n"+
		"epoch:     %d\n"+
		"plaintext: %q\n"+
		"nonce:     %s\n"+
		"cipher:    %s\n"+
		"sig:       %s\n"+
		"--- END INTEROP VECTOR ---",
		b64(rk.Key[:]), b64(id.SignPub), fromID, rk.Epoch, plaintext,
		b64(nonce), b64(ct), b64(sig))
}
