package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
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

// TestArtifactApprovalSigningBytesV2Vector pins the role-typed artifact-approval v2
// preimage. Unlike the other v2 vectors (re-derived only), it keeps a FROZEN-HEX anchor
// as well — consistent with the Pass A artifact-approval/v1 tripwire — so the layout is
// nailed two independent ways. The four middle fields are byte-for-byte the already-
// verified fragments from the v1 vector; only the tag and the trailing role field are
// new (both self-checked: tag len 0x1f, role "qa" = 7161).
func TestArtifactApprovalSigningBytesV2Vector(t *testing.T) {
	got := hex.EncodeToString(ArtifactApprovalSigningBytesV2("a3f9", "deadbeef", "SHA256:abc", "nonce0", "qa"))

	const want = "000000000000001f" + "6e6574686572636861742f61727469666163742d617070726f76616c2f7632" + // field("netherchat/artifact-approval/v2")
		"0000000000000004" + "61336639" + // field("a3f9")
		"0000000000000008" + "6465616462656566" + // field("deadbeef")
		"000000000000000a" + "5348413235363a616263" + // field("SHA256:abc")
		"0000000000000006" + "6e6f6e636530" + // field("nonce0")
		"0000000000000002" + "7161" // field("qa")

	if got != want {
		t.Fatalf("ArtifactApprovalSigningBytesV2 layout changed (breaking — bump the v2 tag):\n got %s\nwant %s", got, want)
	}

	// Independent re-derivation cross-check (refField), so a field reorder is caught even
	// if the frozen const above were edited to match a drifted function.
	rederived := cat(
		refField("netherchat/artifact-approval/v2"),
		refField("a3f9"), refField("deadbeef"), refField("SHA256:abc"), refField("nonce0"),
		refField("qa"),
	)
	if hex.EncodeToString(rederived) != want {
		t.Fatalf("ArtifactApprovalSigningBytesV2 re-derivation disagrees with the frozen const:\n got %x\nwant %s", rederived, want)
	}
}

// TestArtifactApprovalV2DiffersFromV1 confirms the v2 preimage is domain-separated from
// v1 (mirrors TestRecordV2DiffersFromV1): a v2 approval can never collide with a v1 one,
// so a signature from one context never verifies in the other.
func TestArtifactApprovalV2DiffersFromV1(t *testing.T) {
	v1 := ArtifactApprovalSigningBytes("p1", "h1", "f1", "n1")
	v2 := ArtifactApprovalSigningBytesV2("p1", "h1", "f1", "n1", "qa")
	if bytes.Equal(v1, v2) {
		t.Fatal("v2 artifact-approval preimage equals v1 — domain separation missing")
	}
}
