package e2e

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/sealedrecord"
	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/record"
)

// TestIdentityAttestationTravelsTheProducerPath is the Phase 2 producer path end
// to end, and it exists because until it did, no Netherchat code appended a
// typed entry at all: the entry format was exercised only by a downstream
// consumer, which is a poor way to find out a format is wrong.
//
// Two real clients through a real relay: alice records a decision, then places
// an issuer-signed attestation into the same chain. Bob receives it, verifies it
// as an ordinary entry, and appends it — so the chains converge. Alice seals,
// bob co-signs, and the record is verified twice: once with an issuer key
// pinned, once with none.
//
// The second verification is the point. With no issuer pinned the result is
// BYTE-IDENTICAL to plain Verify, which is the standalone-inert guarantee
// asserted on a record that actually carries attestations rather than on one
// that does not.
func TestIdentityAttestationTravelsTheProducerPath(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLogger()))
	defer ts.Close()

	alice := connect(t, ts.URL, "inc-identity", "alice", "")
	waitMatch[client.EvKeyReady](t, alice, nil, 5*time.Second)
	bob := connect(t, ts.URL, "inc-identity", "bob", "")
	waitMatch[client.EvKeyReady](t, bob, nil, 5*time.Second)
	waitMatch[client.EvMemberJoined](t, alice, func(e client.EvMemberJoined) bool { return e.Name == "bob" }, 5*time.Second)

	if err := alice.Decide("rolled back to v2.3.1 at 03:47 UTC"); err != nil {
		t.Fatalf("decide: %v", err)
	}
	waitMatch[client.EvRecordEntry](t, bob, func(e client.EvRecordEntry) bool {
		return !e.Self && e.Kind == record.KindDecision
	}, 5*time.Second)

	// The subject is alice's own key: the common case is a person carrying their
	// own credential into a record they are part of. Nothing requires that — the
	// entry author need not be the subject and need not be the issuer.
	issuerPub, issuerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerFpr := sealedrecord.Fingerprint(issuerPub)
	subject := alice.Fingerprint()

	unsigned := attest.NewIdentityAttestation(attest.IdentitySpec{
		Serial:        "acme-0042",
		Subject:       subject,
		Principal:     "rosa.alvarez@acme.example",
		PrincipalType: "person",
		Roles:         []string{"technical", "incident-commander"},
		ExpiresAt:     time.Now().UTC().Add(90 * 24 * time.Hour).Format(time.RFC3339),
		Algorithm:     attest.AlgorithmEd25519,
		Issuer:        issuerFpr,
	}, nil, nil)
	att := unsigned.WithSignatures(
		map[string][]byte{issuerFpr: ed25519.Sign(issuerPriv, attest.IdentitySigningBytes(unsigned))},
		map[string][]byte{issuerFpr: issuerPub},
	)

	if err := alice.AttestIdentity(att); err != nil {
		t.Fatalf("attest: %v", err)
	}
	// Bob receiving it at all is the load-bearing half: the entry crossed the
	// wire as an ordinary OpRecordEntry, and his AppendRemote ran VerifyEntry on
	// a typed entry and accepted it.
	//
	// AND THE EVENT MUST CARRY THE SCHEMA TAG. Phase 3c's room view decides what a
	// filed credential looks like by asking record.IsIdentityEntry, which needs the
	// Kind AND the Schema. Every unit test in tui/ui/app builds its own event and
	// would pass with the tag dropped somewhere between record.Entry and
	// EvRecordEntry — and a peer's credential would then land in the message pane
	// as the artifact's raw JSON, which is the exact defect 3c closed. This is the
	// only assertion above that seam.
	got := waitMatch[client.EvRecordEntry](t, bob, func(e client.EvRecordEntry) bool {
		return !e.Self && e.Kind == record.KindTyped && strings.Contains(e.Body, "rosa.alvarez@acme.example")
	}, 5*time.Second)
	if !record.IsIdentityEntry(record.Entry{Kind: got.Kind, Schema: got.Schema}) {
		t.Fatalf("the event bob received is kind=%q schema=%q; a room view cannot tell it from any "+
			"other typed entry and will render its body verbatim", got.Kind, got.Schema)
	}

	aliceEntries, bobEntries := alice.RecordEntries(), bob.RecordEntries()
	if len(aliceEntries) != 2 || len(bobEntries) != 2 {
		t.Fatalf("chain lengths: alice=%d bob=%d, want 2 and 2", len(aliceEntries), len(bobEntries))
	}
	for i := range aliceEntries {
		if aliceEntries[i].Hash() != bobEntries[i].Hash() {
			t.Fatalf("entry %d differs between alice and bob (chains diverged on a typed entry)", i)
		}
	}
	if !record.IsIdentityEntry(bobEntries[1]) {
		t.Fatalf("bob's entry 1 is kind=%q schema=%q, want the identity schema tag",
			bobEntries[1].Kind, bobEntries[1].Schema)
	}

	if err := alice.Seal(); err != nil {
		t.Fatalf("alice seal: %v", err)
	}
	waitMatch[client.EvSealRequest](t, bob, func(e client.EvSealRequest) bool {
		return !e.Self && e.Matches && e.NumEntries == 2
	}, 5*time.Second)
	if err := bob.Seal(); err != nil {
		t.Fatalf("bob co-sign: %v", err)
	}
	done := waitMatch[client.EvSealComplete](t, alice, nil, 10*time.Second)
	if done.Record == nil {
		t.Fatal("seal complete carried no record")
	}
	b, err := done.Record.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Read it back the way an offline verifier would: from bytes, with an issuer
	// key and an evaluation time supplied from outside the file.
	withPin, err := record.VerifyBytesWithIdentity(b, attest.IdentityOptions{
		IssuerKeys: []ed25519.PublicKey{issuerPub},
		At:         time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("verify with identity: %v", err)
	}
	if !withPin.Valid {
		t.Fatalf("the sealed record did not verify: %s", withPin.Reason)
	}
	bindings := record.VerifiedIdentitiesOf(withPin, subject)
	if len(bindings) != 1 {
		t.Fatalf("want one binding for %s, got %d", subject, len(bindings))
	}
	if bindings[0].Principal != "rosa.alvarez@acme.example" {
		t.Errorf("binding principal = %q", bindings[0].Principal)
	}
	if len(bindings[0].VerifiedBy) != 1 || bindings[0].VerifiedBy[0] != issuerFpr {
		t.Errorf("VerifiedBy = %v, want [%s]", bindings[0].VerifiedBy, issuerFpr)
	}

	// And with no issuer pinned: byte-identical to plain verification of the same
	// bytes. A record carrying attestations is, to an install that pinned nobody,
	// exactly the record it was before this feature existed.
	plain, err := record.VerifyBytes(b)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	inert, err := record.VerifyBytesWithIdentity(b, attest.IdentityOptions{})
	if err != nil {
		t.Fatalf("verify with no pin must be a legal call: %v", err)
	}
	pj, _ := json.Marshal(plain)
	ij, _ := json.Marshal(inert)
	if string(pj) != string(ij) {
		t.Fatalf("with no issuer pinned a record carrying attestations must verify byte-identically:\n plain: %s\n inert: %s", pj, ij)
	}
	if strings.Contains(string(pj), "identity_bindings") {
		t.Error("plain verification must not emit an identity surface")
	}

	// THE MINUTES, AND WHAT CHANGED HERE IN PHASE 3C.
	//
	// This block used to assert the opposite: "minutes must not render an
	// attestation body in Phase 2". That was true of the code and it was a
	// statement about a phase, not about a property — RenderMinutes dropped every
	// typed entry, so a record whose chain bound a name to a key produced a
	// human-readable half that did not mention it. Phase 3c closed the gap, so the
	// assertion inverts: the minutes now name the credential AS A CLAIM.
	//
	// What must NOT change, and is asserted above rather than here, is that a
	// verification with no pin stays byte-identical. The minutes are a rendering;
	// the evidence is not.
	md := record.RenderMinutes(done.Record)
	if !strings.Contains(md, "rosa.alvarez@acme.example") {
		t.Errorf("minutes must name the credential the record carries:\n%s", md)
	}
	if strings.Contains(md, "netherchat_identity") {
		t.Errorf("minutes must not render the artifact's raw JSON:\n%s", md)
	}
	if !strings.Contains(md, "not verified here") {
		t.Errorf("minutes print an issuer's words without saying nobody here checked them:\n%s", md)
	}
	if !strings.Contains(md, "rolled back to v2.3.1 at 03:47 UTC") {
		t.Error("minutes must still carry the decision")
	}
}
