package protocol

import (
	"encoding/hex"
	"testing"
)

// TestRecordSigningBytesVector pins the exact byte layout of RecordSigningBytes
// (§1.4). The sealed record's authenticity rests on every implementation deriving
// these bytes identically — a Go client signing an entry, an offline `netherchat
// verify`, and a future TypeScript verifier must all agree. If this layout
// changes, previously sealed records stop verifying; that is a breaking change to
// the record format and must bump the "netherchat/record/v1" tag.
func TestRecordSigningBytesVector(t *testing.T) {
	prev := make([]byte, 32)
	for i := range prev {
		prev[i] = byte(i)
	}
	got := hex.EncodeToString(RecordSigningBytes(7, 7, "alice", "decision", "", "netherchat", prev))

	const want = "0000000000000014" + "6e6574686572636861742f7265636f72642f7631" + // field("netherchat/record/v1")
		"0000000000000007" + // seq 7, big-endian
		"0000000000000007" + // ts 7, big-endian
		"0000000000000005" + "616c696365" + // field("alice")
		"0000000000000008" + "6465636973696f6e" + // field("decision")
		"0000000000000000" + // field("") — empty actionee
		"000000000000000a" + "6e657468657263686174" + // field("netherchat")
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" // prevHash[32], raw

	if got != want {
		t.Fatalf("RecordSigningBytes layout changed (breaking — bump the v1 tag):\n got %s\nwant %s", got, want)
	}
}

// TestSealSigningBytesVector pins the seal signature preimage (§1.4): the bytes a
// participant signs to co-sign a record head. Domain-separated and room-bound, so
// a seal signature can never be replayed as a message/record signature nor reused
// to attest the same chain in a different room.
func TestSealSigningBytesVector(t *testing.T) {
	head := make([]byte, 32)
	for i := range head {
		head[i] = byte(i)
	}
	got := hex.EncodeToString(SealSigningBytes("ops", head))

	const want = "0000000000000012" + "6e6574686572636861742f7365616c2f7631" + // field("netherchat/seal/v1")
		"0000000000000003" + "6f7073" + // field("ops")
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" // headHash[32], raw

	if got != want {
		t.Fatalf("SealSigningBytes layout changed (breaking):\n got %s\nwant %s", got, want)
	}
}
