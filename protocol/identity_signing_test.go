package protocol

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// TestIdentitySigningBytesVector pins the exact byte layout of the identity/v2
// issuer-signature preimage. Everything the format claims rests on an issuer, a
// verifier in a room, and an offline reader three years later deriving these
// bytes identically. If this layout changes, every attestation ever issued stops
// verifying; that is a breaking change and must bump the
// "netherchat/identity/v2" tag.
//
// It has been through that once. v1 had no display_name and this vector pinned
// its bytes; Phase 2.5 added the field, this test failed with the byte diff, and
// the tag moved from v1 to v2 in the same change — which is what the sentence
// above is for. The vector's display name is deliberately non-ASCII: it proves
// the field carries UTF-8 BYTES and is neither folded nor re-encoded on the way
// into the signature.
func TestIdentitySigningBytesVector(t *testing.T) {
	got := hex.EncodeToString(IdentitySigningBytes(
		"s1",           // serial
		"SHA256:aa",    // subject
		"rosa@acme",    // principal
		"Rosa Álvarez", // display name
		"person",       // principal type
		[]string{"qa"}, // roles
		"2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z",
		"ed25519",
		"SHA256:bb", // issuer
	))

	const want = "0000000000000016" + "6e6574686572636861742f6964656e746974792f7632" + // field("netherchat/identity/v2")
		"0000000000000002" + "7331" + // field("s1")
		"0000000000000009" + "5348413235363a6161" + // field("SHA256:aa")
		"0000000000000009" + "726f736140" + "61636d65" + // field("rosa@acme")
		"000000000000000d" + "526f736120" + "c381" + "6c766172657a" + // field("Rosa Álvarez") — THIRTEEN bytes, not twelve runes: Á is c381
		"0000000000000006" + "706572736f6e" + // field("person")
		"0000000000000001" + // nroles = 1, big-endian, NOT length-prefixed
		"0000000000000002" + "7161" + // field("qa")
		"0000000000000014" + "323032362d30312d30315430303a30303a30305a" + // field(issued_at)
		"0000000000000014" + "323032362d30342d30315430303a30303a30305a" + // field(expires_at)
		"0000000000000007" + "65643235353139" + // field("ed25519")
		"0000000000000009" + "5348413235363a6262" // field("SHA256:bb")

	if got != want {
		t.Fatalf("IdentitySigningBytes layout changed (breaking — bump the v2 tag):\n got %s\nwant %s", got, want)
	}
}

// TestIdentitySigningBytesIsInjective proves the length-prefixed encoding leaves
// no way to move a byte from one field into its neighbour and produce the same
// preimage. Without it an attestation for "rosa@acme" in role "admin" and one
// for "rosa@acmeadmin" in role "" could sign the same bytes.
func TestIdentitySigningBytesIsInjective(t *testing.T) {
	a := IdentitySigningBytes("s", "SHA256:aa", "rosa@acme", "", "admin", []string{"qa"},
		"2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z", "ed25519", "SHA256:bb")
	b := IdentitySigningBytes("s", "SHA256:aa", "rosa@acmeadmin", "", "", []string{"qa"},
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
		return IdentitySigningBytes("s", "SHA256:aa", "rosa@acme", "", "person", roles,
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

// TestIdentitySigningBytesBindsDisplayName proves the display name is inside the
// signature and cannot be moved, edited, or smuggled in from a neighbouring
// field. "Optional" means an issuer may leave it out; it does not mean the field
// escapes the preimage, and this is the test that says so in bytes rather than in
// a comment.
//
// The last two cases are the ones that matter. A display name sits between
// principal and principal_type, and both neighbours are attacker-visible strings:
// without a length prefix on every field, an issuer's signature over
// "rosa@acme" / "Alvarez" would equally cover "rosa@acmeAlvarez" / "" — one
// signature, two different claims about who somebody is.
func TestIdentitySigningBytesBindsDisplayName(t *testing.T) {
	base := func(principal, display, ptype string) []byte {
		return IdentitySigningBytes("s", "SHA256:aa", principal, display, ptype, []string{"qa"},
			"2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z", "ed25519", "SHA256:bb")
	}
	named := base("rosa@acme", "Rosa Alvarez", "person")
	if bytes.Equal(named, base("rosa@acme", "Rosa Alvarez ", "person")) {
		t.Error("a display name is signed byte-for-byte: trailing whitespace must change the preimage")
	}
	if bytes.Equal(named, base("rosa@acme", "rosa alvarez", "person")) {
		t.Error("a display name is signed byte-for-byte: case must change the preimage")
	}
	if bytes.Equal(named, base("rosa@acme", "Someone Else", "person")) {
		t.Error("editing the display name must break the signature, not survive it")
	}
	if bytes.Equal(named, base("rosa@acme", "", "person")) {
		t.Error("an absent display name and a present one must not sign the same bytes")
	}
	// The two field boundaries the display name introduced.
	if bytes.Equal(base("rosa@acme", "Alvarez", "person"), base("rosa@acmeAlvarez", "", "person")) {
		t.Error("a byte must not be movable across the principal/display_name boundary")
	}
	if bytes.Equal(base("rosa@acme", "X", "person"), base("rosa@acme", "", "Xperson")) {
		t.Error("a byte must not be movable across the display_name/principal_type boundary")
	}
}

// TestIdentitySigningBytesEmptyDisplayNameIsEightZeroBytes pins the one encoding
// of "this issuer named no display name". The field is written unconditionally,
// so the layout keeps a fixed shape and the number of fields never depends on the
// data — the same choice field(nextUpdate) makes for an omitted next_update. It
// is also what makes absent and empty unconfusable: there is one encoding, so
// there are not two states to confuse.
func TestIdentitySigningBytesEmptyDisplayNameIsEightZeroBytes(t *testing.T) {
	got := hex.EncodeToString(IdentitySigningBytes(
		"s1", "SHA256:aa", "rosa@acme", "", "person", []string{"qa"},
		"2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z", "ed25519", "SHA256:bb",
	))
	const wantField = "0000000000000009" + "726f736140" + "61636d65" + // field("rosa@acme")
		"0000000000000000" + // field("") — no display name, and the field is still there
		"0000000000000006" + "706572736f6e" // field("person")
	if !strings.Contains(got, wantField) {
		t.Fatalf("an empty display name must still occupy a length-prefixed field:\n got %s\nwant a run of %s", got, wantField)
	}
}

// TestIdentityPreimagesAreDomainSeparated proves an identity signature can never
// be replayed as a revocation, a roster, a seal, a record entry, or a message —
// the tags differ, so the same key signing the same content in two contexts
// produces two unrelated signatures.
func TestIdentityPreimagesAreDomainSeparated(t *testing.T) {
	id := IdentitySigningBytes("s", "SHA256:aa", "p", "", "person", []string{"qa"},
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
