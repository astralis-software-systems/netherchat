package protocol

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestIdentitySigningBytesVector pins the exact byte layout of the identity/v1
// issuer-signature preimage. Everything the format claims rests on an issuer, a
// verifier in a room, and an offline reader three years later deriving these
// bytes identically. If this layout changes, every attestation ever issued stops
// verifying; that is a breaking change and must bump the
// "netherchat/identity/v1" tag.
func TestIdentitySigningBytesVector(t *testing.T) {
	got := hex.EncodeToString(IdentitySigningBytes(
		"s1",           // serial
		"SHA256:aa",    // subject
		"rosa@acme",    // principal
		"person",       // principal type
		[]string{"qa"}, // roles
		"2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z",
		"ed25519",
		"SHA256:bb", // issuer
	))

	const want = "0000000000000016" + "6e6574686572636861742f6964656e746974792f7631" + // field("netherchat/identity/v1")
		"0000000000000002" + "7331" + // field("s1")
		"0000000000000009" + "5348413235363a6161" + // field("SHA256:aa")
		"0000000000000009" + "726f736140" + "61636d65" + // field("rosa@acme")
		"0000000000000006" + "706572736f6e" + // field("person")
		"0000000000000001" + // nroles = 1, big-endian, NOT length-prefixed
		"0000000000000002" + "7161" + // field("qa")
		"0000000000000014" + "323032362d30312d30315430303a30303a30305a" + // field(issued_at)
		"0000000000000014" + "323032362d30342d30315430303a30303a30305a" + // field(expires_at)
		"0000000000000007" + "65643235353139" + // field("ed25519")
		"0000000000000009" + "5348413235363a6262" // field("SHA256:bb")

	if got != want {
		t.Fatalf("IdentitySigningBytes layout changed (breaking — bump the v1 tag):\n got %s\nwant %s", got, want)
	}
}

// TestIdentitySigningBytesIsInjective proves the length-prefixed encoding leaves
// no way to move a byte from one field into its neighbour and produce the same
// preimage. Without it an attestation for "rosa@acme" in role "admin" and one
// for "rosa@acmeadmin" in role "" could sign the same bytes.
func TestIdentitySigningBytesIsInjective(t *testing.T) {
	a := IdentitySigningBytes("s", "SHA256:aa", "rosa@acme", "admin", []string{"qa"},
		"2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z", "ed25519", "SHA256:bb")
	b := IdentitySigningBytes("s", "SHA256:aa", "rosa@acmeadmin", "", []string{"qa"},
		"2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z", "ed25519", "SHA256:bb")
	if bytes.Equal(a, b) {
		t.Fatal("moving a byte across a field boundary must change the preimage")
	}
}

// TestIdentitySigningBytesBindsRoleCountAndOrder proves the signed role count
// makes a role impossible to add or drop, and that order is signed rather than
// normalized — so a reordered artifact fails the signature check instead of
// quietly verifying.
func TestIdentitySigningBytesBindsRoleCountAndOrder(t *testing.T) {
	base := func(roles ...string) []byte {
		return IdentitySigningBytes("s", "SHA256:aa", "rosa@acme", "person", roles,
			"2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z", "ed25519", "SHA256:bb")
	}
	two := base("qa", "technical")
	if bytes.Equal(two, base("qa")) {
		t.Error("dropping a role must change the preimage")
	}
	if bytes.Equal(two, base("qa", "technical", "release")) {
		t.Error("adding a role must change the preimage")
	}
	if bytes.Equal(two, base("technical", "qa")) {
		t.Error("role order is signed, not normalized: reordering must change the preimage")
	}
	// The count is what closes the "one role that happens to concatenate" gap.
	if bytes.Equal(base("ab", "c"), base("abc")) {
		t.Error("the role count must be part of the preimage")
	}
}

// TestIdentityPreimagesAreDomainSeparated proves an identity signature can never
// be replayed as a revocation, a roster, a seal, a record entry, or a message —
// the tags differ, so the same key signing the same content in two contexts
// produces two unrelated signatures.
func TestIdentityPreimagesAreDomainSeparated(t *testing.T) {
	id := IdentitySigningBytes("s", "SHA256:aa", "p", "person", []string{"qa"},
		"2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z", "ed25519", "SHA256:bb")
	rev := RevocationSigningBytes("SHA256:bb", "stmt", 1, "2026-01-01T00:00:00Z", "",
		[]string{"s"}, []string{"2026-01-02T00:00:00Z"}, []string{""})

	others := [][]byte{
		rev,
		RosterSigningBytes("room", 1, make([]byte, 32)),
		SealSigningBytes("room", make([]byte, 32)),
		RecordSigningBytes(0, 0, "a", "note", "", "b", make([]byte, 32)),
		SigningBytes("room", "from", 0, nil, nil),
	}
	for i, o := range others {
		if bytes.HasPrefix(o, id[:24]) {
			t.Errorf("preimage %d shares the identity domain tag", i)
		}
	}
	if bytes.Equal(id, rev) {
		t.Error("identity and revocation preimages must never coincide")
	}
}

// TestRevocationSigningBytesVector pins the revocation layout, including the
// inline entry list: the whole list is length-prefixed field by field rather
// than hashed into a digest first, so no separator can be smuggled inside a
// serial and no entry can be added or dropped.
func TestRevocationSigningBytesVector(t *testing.T) {
	got := hex.EncodeToString(RevocationSigningBytes(
		"SHA256:bb", "st1", 2, "2026-01-01T00:00:00Z", "",
		[]string{"s1"}, []string{"2026-01-02T00:00:00Z"}, []string{"lost"},
	))

	const want = "0000000000000021" + "6e6574686572636861742f6964656e746974792d7265766f636174696f6e2f7631" + // tag
		"0000000000000009" + "5348413235363a6262" + // field("SHA256:bb")
		"0000000000000003" + "737431" + // field("st1")
		"0000000000000002" + // number 2, big-endian
		"0000000000000014" + "323032362d30312d30315430303a30303a30305a" + // field(issued_at)
		"0000000000000000" + // field("") — no next_update
		"0000000000000001" + // one entry, big-endian
		"0000000000000002" + "7331" + // field("s1")
		"0000000000000014" + "323032362d30312d30325430303a30303a30305a" + // field(revoked_at)
		"0000000000000004" + "6c6f7374" // field("lost")

	if got != want {
		t.Fatalf("RevocationSigningBytes layout changed (breaking — bump the v1 tag):\n got %s\nwant %s", got, want)
	}
}

// TestRevocationSigningBytesBindsTheList proves an entry can be neither added,
// dropped, nor reordered without breaking the signature.
func TestRevocationSigningBytesBindsTheList(t *testing.T) {
	at := []string{"2026-01-02T00:00:00Z", "2026-01-03T00:00:00Z"}
	why := []string{"a", "b"}
	two := RevocationSigningBytes("SHA256:bb", "st", 1, "2026-01-01T00:00:00Z", "",
		[]string{"s1", "s2"}, at, why)
	one := RevocationSigningBytes("SHA256:bb", "st", 1, "2026-01-01T00:00:00Z", "",
		[]string{"s1"}, at[:1], why[:1])
	swapped := RevocationSigningBytes("SHA256:bb", "st", 1, "2026-01-01T00:00:00Z", "",
		[]string{"s2", "s1"}, at, why)
	if bytes.Equal(two, one) {
		t.Error("dropping a revoked serial must change the preimage")
	}
	if bytes.Equal(two, swapped) {
		t.Error("reordering the list must change the preimage")
	}
}
