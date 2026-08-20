package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The additive claim for the presence carrier, proved against captured bytes.
//
// testdata/presence_wire_pre3b.json holds the marshalled form of every struct
// the attestation field touches, taken from the clean tree at 1e7d92c BEFORE the
// field existed. A structure that carries no attestation must still marshal to
// those exact bytes, or "additive" is a word rather than a property.
//
// This is a comparison, not a re-derivation. A test that re-derives the expected
// bytes from the current struct cannot fail: whatever the code produces becomes
// what the test expects.

func loadPreChangeWire(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "presence_wire_pre3b.json"))
	if err != nil {
		t.Fatalf("pre-change wire golden: %v", err)
	}
	var out map[string]string
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("pre-change wire golden: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("the pre-change wire golden is empty; this guard would compare nothing")
	}
	return out
}

func presenceFixtureKeys() (signPub, kxPub []byte) {
	signPub = make([]byte, 32)
	kxPub = make([]byte, 32)
	for i := range signPub {
		signPub[i] = byte(i)
		kxPub[i] = byte(0x80 + i)
	}
	return signPub, kxPub
}

// TestUnattestedPresenceWireBytesUnchanged: with no attestation set, every
// presence structure marshals to the bytes it marshalled to before the field
// existed. An older peer therefore cannot tell a new sender from an old one.
func TestUnattestedPresenceWireBytesUnchanged(t *testing.T) {
	want := loadPreChangeWire(t)
	key, kx := presenceFixtureKeys()
	got := map[string]any{
		"hello":             Hello{ProtocolVersion: Version, Room: "ops", DisplayName: "alice", IdentityKey: key, KXKey: kx},
		"hello_with_invite": Hello{ProtocolVersion: Version, Room: "ops", DisplayName: "alice", IdentityKey: key, KXKey: kx, InviteToken: "tok"},
		"member":            Member{ID: "id-a", DisplayName: "alice", IdentityKey: key, KXKey: kx},
		"welcome_empty":     Welcome{ProtocolVersion: Version, YourID: "id-a", Room: "ops", Members: []Member{}, YouAreFirst: true},
		"member_joined":     MemberJoined{Member: Member{ID: "id-a", DisplayName: "alice", IdentityKey: key, KXKey: kx}},
		"key_request":       KeyRequest{ForMember: Member{ID: "id-a", DisplayName: "alice", IdentityKey: key, KXKey: kx}},
	}
	if len(got) != len(want) {
		t.Fatalf("the golden holds %d structure(s) and this test builds %d; one of them was added "+
			"without the other", len(want), len(got))
	}
	for name, v := range got {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(b) != want[name] {
			t.Errorf("%s moved while carrying no attestation:\n before: %s\n  after: %s", name, want[name], b)
		}
	}
}

// TestAttestedPresenceWireCarriesTheBytesVerbatim is the other half: when the
// field IS set, it is the artifact's bytes and nothing else — no wrapper, no
// re-encoding, no wire-specific shape (identity spec §4.5).
func TestAttestedPresenceWireCarriesTheBytesVerbatim(t *testing.T) {
	key, kx := presenceFixtureKeys()
	artifact := []byte(`{"netherchat_identity":"v2","serial":"acme-0001"}`)

	for name, v := range map[string]any{
		"hello":  Hello{ProtocolVersion: Version, Room: "ops", DisplayName: "alice", IdentityKey: key, KXKey: kx, Attestation: artifact},
		"member": Member{ID: "id-a", DisplayName: "alice", IdentityKey: key, KXKey: kx, Attestation: artifact},
	} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var back struct {
			Attestation []byte `json:"attestation"`
		}
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(back.Attestation) != string(artifact) {
			t.Errorf("%s round-tripped the artifact as %q, want %q", name, back.Attestation, artifact)
		}
	}
}

// TestOlderFrameDecodesAsCarriedNone is the newer-peer-reads-older-frame
// direction, asserted on the pre-change bytes themselves rather than on a
// hand-written approximation of them: decoding yields a nil slice, which is the
// state "carried none", not an error and not an empty artifact.
func TestOlderFrameDecodesAsCarriedNone(t *testing.T) {
	golden := loadPreChangeWire(t)
	var h Hello
	if err := json.Unmarshal([]byte(golden["hello"]), &h); err != nil {
		t.Fatalf("a pre-change Hello does not decode into the current struct: %v", err)
	}
	if h.Attestation != nil {
		t.Errorf("a pre-change Hello decoded to %d attestation byte(s), want nil", len(h.Attestation))
	}
	var mj MemberJoined
	if err := json.Unmarshal([]byte(golden["member_joined"]), &mj); err != nil {
		t.Fatalf("a pre-change MemberJoined does not decode into the current struct: %v", err)
	}
	if mj.Member.Attestation != nil {
		t.Errorf("a pre-change Member decoded to %d attestation byte(s), want nil", len(mj.Member.Attestation))
	}
	if mj.Member.DisplayName != "alice" {
		t.Errorf("a pre-change Member lost its display name: %q", mj.Member.DisplayName)
	}
}

// TestOlderPeerIgnoresTheNewKey is the older-peer-reads-newer-frame direction.
// It cannot import an older build, so it asserts the property that makes the
// claim true: the wire decoder is a plain json.Unmarshal with no
// DisallowUnknownFields, so a key a struct does not declare is dropped rather
// than refused. `oldHello` stands in for the pre-3b struct.
func TestOlderPeerIgnoresTheNewKey(t *testing.T) {
	type oldHello struct {
		ProtocolVersion int    `json:"protocol_version"`
		Room            string `json:"room"`
		DisplayName     string `json:"name"`
		IdentityKey     []byte `json:"identity_key"`
		KXKey           []byte `json:"kx_key"`
		InviteToken     string `json:"invite_token,omitempty"`
	}
	key, kx := presenceFixtureKeys()
	newer, err := json.Marshal(Hello{
		ProtocolVersion: Version, Room: "ops", DisplayName: "alice",
		IdentityKey: key, KXKey: kx,
		Attestation: []byte(`{"netherchat_identity":"v2"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	var old oldHello
	if err := json.Unmarshal(newer, &old); err != nil {
		t.Fatalf("a pre-3b Hello struct refused a 3b frame: %v\n%s", err, newer)
	}
	if old.Room != "ops" || old.DisplayName != "alice" || len(old.IdentityKey) != 32 {
		t.Errorf("a pre-3b struct decoded a 3b frame into %+v; the fields it knows must be intact", old)
	}
}
