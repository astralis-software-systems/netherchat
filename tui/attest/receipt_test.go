package attest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// makeReceipt builds an n-signer scuttle receipt for room/reason.
func makeReceipt(t *testing.T, room, reason string, n int, keysZeroized bool) *ScuttleReceipt {
	t.Helper()
	fprs := make([]string, n)
	privs := make([]ed25519.PrivateKey, n)
	for i := 0; i < n; i++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		privs[i] = priv
		fprs[i] = crypto.Fingerprint(pub)
	}
	core := ReceiptCore{
		Version:      ReceiptVersion,
		Room:         room,
		EpochRange:   EpochRange{First: 0, Last: 3},
		Reason:       reason,
		ScuttledAt:   "2026-06-08T03:47:00Z",
		ScuttledBy:   fprs[0],
		MemberFprs:   fprs,
		KeysZeroized: keysZeroized,
	}
	preimage := protocol.ScuttleReceiptSigningBytes(coreHash(core))
	sigs := make(map[string][]byte, n)
	keys := make(map[string][]byte, n)
	for i := 0; i < n; i++ {
		pub := privs[i].Public().(ed25519.PublicKey)
		sigs[fprs[i]] = ed25519.Sign(privs[i], preimage)
		keys[fprs[i]] = pub
	}
	return NewReceipt(core, sigs, keys)
}

func coreHash(c ReceiptCore) []byte {
	h := c.Hash()
	return h[:]
}

// TestReceiptHashMatchesCanonical proves receipt_hash equals SHA-256 of the
// canonical core bytes, and survives a marshal/parse round-trip.
func TestReceiptHashMatchesCanonical(t *testing.T) {
	r := makeReceipt(t, "inc-3f9a2b71", "manual", 2, true)
	want := r.ReceiptCore.Hash()
	if hex.EncodeToString(want[:]) != r.ReceiptHash {
		t.Fatalf("receipt_hash %s != canonical %s", r.ReceiptHash, hex.EncodeToString(want[:]))
	}

	b, err := r.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseReceipt(b)
	if err != nil {
		t.Fatalf("round-trip parse: %v", err)
	}
	h2 := back.ReceiptCore.Hash()
	if hex.EncodeToString(h2[:]) != back.ReceiptHash {
		t.Error("receipt_hash drifted across marshal/parse")
	}
}

// TestVerifyReceiptValid proves a correctly co-signed receipt verifies.
func TestVerifyReceiptValid(t *testing.T) {
	r := makeReceipt(t, "inc-3f9a2b71", "manual", 2, true)
	res, err := VerifyReceipt(r)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("receipt should verify: %s", res.Error)
	}
	if len(res.Signers) != 2 || res.Reason != "manual" {
		t.Errorf("signers=%d reason=%q, want 2/manual", len(res.Signers), res.Reason)
	}
}

// TestVerifyReceiptTampered proves a mutated core field (without recomputing the
// hash) is rejected.
func TestVerifyReceiptTampered(t *testing.T) {
	r := makeReceipt(t, "inc-3f9a2b71", "manual", 2, true)
	r.Reason = "idle" // tamper a hashed field; receipt_hash no longer matches
	res, err := VerifyReceipt(r)
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid {
		t.Fatal("a tampered receipt must not verify")
	}
}

// TestVerifyReceiptTamperedSignature proves a corrupted signature is rejected.
func TestVerifyReceiptTamperedSignature(t *testing.T) {
	r := makeReceipt(t, "inc-3f9a2b71", "manual", 2, true)
	for fpr, sigB64 := range r.Signatures {
		raw, _ := base64.StdEncoding.DecodeString(sigB64)
		raw[0] ^= 0xff
		r.Signatures[fpr] = base64.StdEncoding.EncodeToString(raw)
		break
	}
	res, _ := VerifyReceipt(r)
	if res.Valid {
		t.Fatal("a tampered signature must not verify")
	}
}

// TestVerifyReceiptKeysNotZeroized proves a receipt that does not attest
// destruction (keys_zeroized=false) is rejected even when otherwise well-formed.
func TestVerifyReceiptKeysNotZeroized(t *testing.T) {
	r := makeReceipt(t, "inc-3f9a2b71", "manual", 1, false)
	res, _ := VerifyReceipt(r)
	if res.Valid {
		t.Fatal("keys_zeroized=false must not verify")
	}
}

// TestParseReceiptRejectsUnknownField proves a receipt with an extra/renamed key
// fails loudly.
func TestParseReceiptRejectsUnknownField(t *testing.T) {
	if _, err := ParseReceipt([]byte(`{"netherchat_receipt":"v1","surprise":true}`)); err == nil {
		t.Fatal("ParseReceipt should reject unknown fields")
	}
}

// TestReceiptHashIgnoresMemberOrder proves the canonical hash is independent of
// the order member_fprs are supplied.
func TestReceiptHashIgnoresMemberOrder(t *testing.T) {
	base := ReceiptCore{
		Version: ReceiptVersion, Room: "r", EpochRange: EpochRange{0, 1},
		Reason: "manual", ScuttledAt: "t", ScuttledBy: "a",
		MemberFprs: []string{"c", "a", "b"}, KeysZeroized: true,
	}
	reordered := base
	reordered.MemberFprs = []string{"a", "b", "c"}
	if !bytes.Equal(coreHash(base), coreHash(reordered)) {
		t.Fatal("receipt hash must not depend on member_fprs order")
	}
}
