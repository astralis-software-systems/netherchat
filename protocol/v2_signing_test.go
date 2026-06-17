package protocol

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// These vectors pin the exact byte layout of the v2 signing preimages by
// re-deriving the expected bytes independently from the documented field order.
// As with the v1 vectors, the sealed record's authenticity rests on every
// implementation deriving these bytes identically; a change here is a breaking
// change to the corresponding format and must bump its "…/v2" tag.

// refField mirrors writeField: an independent re-implementation so the vector is
// a genuine cross-check of the production layout, not a tautology.
func refField(b string) []byte {
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(len(b)))
	return append(l[:], []byte(b)...)
}

func refBE64(v uint64) []byte {
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], v)
	return x[:]
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func ramp32() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func TestRecordSigningBytesV2Vector(t *testing.T) {
	prev := ramp32()
	got := RecordSigningBytesV2(7, 9, "alice", "typed", "", "the body",
		"transcript", "1", []string{"abc123", "def456"}, []string{"derived-from", "supersedes"}, prev)

	want := cat(
		refField("netherchat/record/v2"),
		refBE64(7), refBE64(9),
		refField("alice"), refField("typed"), refField(""), refField("the body"),
		refField("transcript"), refField("1"),
		refBE64(2),
		refField("abc123"), refField("derived-from"),
		refField("def456"), refField("supersedes"),
		prev,
	)
	if !bytes.Equal(got, want) {
		t.Fatalf("RecordSigningBytesV2 layout changed (breaking — bump the v2 tag):\n got %x\nwant %x", got, want)
	}
}

// TestRecordV2DiffersFromV1 confirms the v2 preimage is domain-separated from v1
// even when the v2-only fields are empty, so the two can never collide.
func TestRecordV2DiffersFromV1(t *testing.T) {
	prev := ramp32()
	v1 := RecordSigningBytes(7, 9, "alice", "note", "", "the body", prev)
	v2 := RecordSigningBytesV2(7, 9, "alice", "note", "", "the body", "", "", nil, nil, prev)
	if bytes.Equal(v1, v2) {
		t.Fatal("v2 record preimage equals v1 — domain separation missing")
	}
}

func TestSealSigningBytesV2Vector(t *testing.T) {
	head := ramp32()
	got := SealSigningBytesV2("ops", "approved", "alice", "2026-06-17T00:00:00Z", head)

	want := cat(
		refField("netherchat/seal/v2"),
		refField("ops"),
		refField("approved"), refField("alice"), refField("2026-06-17T00:00:00Z"),
		head,
	)
	if !bytes.Equal(got, want) {
		t.Fatalf("SealSigningBytesV2 layout changed (breaking — bump the v2 tag):\n got %x\nwant %x", got, want)
	}
}

func TestActionApprovalSigningBytesV2Vector(t *testing.T) {
	got := ActionApprovalSigningBytesV2("req1", "ph", "fpr", "nonce", "approved", "alice", "2026-06-17T00:00:00Z")

	want := cat(
		refField("netherchat/action-approval/v2"),
		refField("req1"), refField("ph"), refField("fpr"), refField("nonce"),
		refField("approved"), refField("alice"), refField("2026-06-17T00:00:00Z"),
	)
	if !bytes.Equal(got, want) {
		t.Fatalf("ActionApprovalSigningBytesV2 layout changed (breaking — bump the v2 tag):\n got %x\nwant %x", got, want)
	}
}
