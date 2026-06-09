package attest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// makeRoster builds a valid n-member roster attestation, every member co-signing.
func makeRoster(t *testing.T, room string, epoch uint64, n int) *RosterAttestation {
	t.Helper()
	members := make([]RosterMember, n)
	fprs := make([]string, n)
	privs := make([]ed25519.PrivateKey, n)
	for i := 0; i < n; i++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		privs[i] = priv
		fprs[i] = crypto.Fingerprint(pub)
		members[i] = RosterMember{Name: fmt.Sprintf("m%d", i), Fpr: fprs[i]}
	}
	preimage := protocol.RosterSigningBytes(room, epoch, SetHash(fprs))
	sigs := make(map[string][]byte, n)
	keys := make(map[string][]byte, n)
	for i := 0; i < n; i++ {
		pub := privs[i].Public().(ed25519.PublicKey)
		sigs[fprs[i]] = ed25519.Sign(privs[i], preimage)
		keys[fprs[i]] = pub
	}
	return NewRoster(room, epoch, fprs[0], members, sigs, keys)
}

// TestSetHashOrderIndependent proves set_hash depends only on the SET of
// fingerprints, not the order they are listed — the determinism the spec needs.
func TestSetHashOrderIndependent(t *testing.T) {
	a := SetHash([]string{"SHA256:c", "SHA256:a", "SHA256:b"})
	b := SetHash([]string{"SHA256:a", "SHA256:b", "SHA256:c"})
	if !bytes.Equal(a, b) {
		t.Fatal("set_hash must be independent of member join order")
	}
	if bytes.Equal(a, SetHash([]string{"SHA256:a", "SHA256:b"})) {
		t.Fatal("a different member set must produce a different hash")
	}
}

// TestVerifyRosterValid proves a correctly co-signed roster verifies.
func TestVerifyRosterValid(t *testing.T) {
	r := makeRoster(t, "inc-3f9a", 3, 3)
	res, err := VerifyRoster(r)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("roster should be valid: %s", res.Reason)
	}
	if len(res.Signers) != 3 || res.Members != 3 {
		t.Errorf("signers=%d members=%d, want 3/3", len(res.Signers), res.Members)
	}
}

// TestVerifyRosterTamperedSetHash proves a set_hash that no longer matches the
// listed members is rejected.
func TestVerifyRosterTamperedSetHash(t *testing.T) {
	r := makeRoster(t, "inc-3f9a", 3, 2)
	r.SetHash = "00" + r.SetHash[2:] // corrupt the first byte
	res, err := VerifyRoster(r)
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid {
		t.Fatal("a tampered set_hash must not verify")
	}
}

// TestVerifyRosterTamperedSignature proves a corrupted signature is rejected.
func TestVerifyRosterTamperedSignature(t *testing.T) {
	r := makeRoster(t, "inc-3f9a", 3, 2)
	for fpr, sigB64 := range r.Signatures {
		raw, _ := base64.StdEncoding.DecodeString(sigB64)
		raw[0] ^= 0xff // flip a byte
		r.Signatures[fpr] = base64.StdEncoding.EncodeToString(raw)
		break
	}
	res, err := VerifyRoster(r)
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid {
		t.Fatal("a tampered signature must not verify")
	}
}

// TestRosterRoundTripStrict proves the artifact round-trips through the strict
// (DisallowUnknownFields) parser, and that the verify result is itself clean
// JSON that decodes strictly — the basis of the --json contract.
func TestRosterRoundTripStrict(t *testing.T) {
	r := makeRoster(t, "inc-3f9a", 3, 2)
	b, err := r.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRoster(b); err != nil {
		t.Fatalf("round-trip parse failed: %v", err)
	}

	res, _ := VerifyRoster(r)
	rb, _ := json.Marshal(res)
	dec := json.NewDecoder(bytes.NewReader(rb))
	dec.DisallowUnknownFields()
	var back RosterResult
	if err := dec.Decode(&back); err != nil {
		t.Fatalf("verify result does not decode strictly: %v", err)
	}
}

// TestParseRosterRejectsUnknownField proves a roster with an extra/renamed key
// fails loudly rather than verifying a shape we do not fully understand.
func TestParseRosterRejectsUnknownField(t *testing.T) {
	if _, err := ParseRoster([]byte(`{"netherchat_roster":"v1","surprise":true}`)); err == nil {
		t.Fatal("ParseRoster should reject unknown fields")
	}
}
