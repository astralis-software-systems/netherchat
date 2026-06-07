package protocol

import (
	"encoding/hex"
	"testing"
)

// TestSigningBytesVector pins the exact byte layout of SigningBytes for a fixed
// input. The SAME vector is asserted in the TypeScript client
// (web/src/crypto/signing.test.ts), so this is the cross-implementation contract:
// if the two ever diverge, signatures stop verifying across Go and the browser
// and one of these tests fails.
func TestSigningBytesVector(t *testing.T) {
	nonce := make([]byte, 24)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	got := hex.EncodeToString(SigningBytes("ops", "alice", 7, nonce, []byte("netherchat")))

	const want = "00000000000000116e6574686572636861742f6d73672f7631" + // field("netherchat/msg/v1")
		"00000000000000036f7073" + // field("ops")
		"0000000000000005616c696365" + // field("alice")
		"0000000000000007" + // epoch 7, big-endian (not length-prefixed)
		"0000000000000018000102030405060708090a0b0c0d0e0f1011121314151617" + // field(nonce[0..23])
		"000000000000000a6e657468657263686174" // field("netherchat")

	if got != want {
		t.Fatalf("SigningBytes layout changed (update web/src/crypto/signing.test.ts to match):\n got %s\nwant %s", got, want)
	}
}
