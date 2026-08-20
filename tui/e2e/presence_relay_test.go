package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/sealedrecord"
	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// The relay half of the presence carrier: two real clients through a real relay,
// each carrying a credential, each seeing the other's arrive verbatim.
//
// The relay is the site that rebuilds a Member from a received Hello field by
// field, so it is the one that can drop the field for EVERY peer at once rather
// than for one transport. It is also the site that must stay blind: it copies
// bytes it never parses, exactly as it already does for identity_key and kx_key.

// e2eCredential signs an attestation about subject. displayName may be empty.
func e2eCredential(t *testing.T, subject, principal, displayName string, roles ...string) *attest.IdentityAttestation {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("issuer key: %v", err)
	}
	unsigned := attest.NewIdentityAttestation(attest.IdentitySpec{
		Serial:        "acme-" + subject[7:15],
		Subject:       subject,
		Principal:     principal,
		DisplayName:   displayName,
		PrincipalType: "person",
		Roles:         roles,
		ExpiresAt:     time.Now().UTC().Add(90 * 24 * time.Hour).Format(time.RFC3339),
		Algorithm:     attest.AlgorithmEd25519,
		Issuer:        sealedrecord.Fingerprint(pub),
	}, nil, nil)
	fpr := sealedrecord.Fingerprint(pub)
	return unsigned.WithSignatures(
		map[string][]byte{fpr: ed25519.Sign(priv, attest.IdentitySigningBytes(unsigned))},
		map[string][]byte{fpr: pub},
	)
}

// connectWithCredential is `connect` plus provisioning, in the order the wire
// forces: UseIdentity before Connect, because Connect enqueues the Hello.
func connectWithCredential(t *testing.T, url, room, name string, cred *attest.IdentityAttestation) *client.Client {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	c, err := client.NewWithIdentity(url, room, name, id)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if cred != nil {
		if err := c.UseIdentity(cred); err != nil {
			t.Fatalf("%s UseIdentity: %v", name, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("connect %s: %v", name, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// rawWelcomeAfterJoin puts a real, credential-carrying client into a room and
// then joins it over a raw WebSocket, returning the relay's Welcome bytes
// verbatim. Reading the relay's own output is the only way to assert what it
// PUT ON THE WIRE: a decoded protocol.Welcome would have been re-encoded by the
// reader's own types on the way in.
func rawWelcomeAfterJoin(t *testing.T, url, room string, id *crypto.Identity, cred *attest.IdentityAttestation) []byte {
	t.Helper()
	c, err := client.NewWithIdentity(url, room, "alice", id)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if err := c.UseIdentity(cred); err != nil {
		t.Fatalf("UseIdentity: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	waitMatch[client.EvKeyReady](t, c, nil, 5*time.Second)
	return rawJoin(t, url, room, "observer", 0x33)
}

func mustMarshal(t *testing.T, a *attest.IdentityAttestation) []byte {
	t.Helper()
	b, err := a.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// TestRelayCarriesTheAttestationOntoMemberJoined: alice is already in the room
// when bob arrives carrying a credential; the relay rebuilds bob's Member from
// his Hello and alice receives the credential verbatim.
func TestRelayCarriesTheAttestationOntoMemberJoined(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLogger()))
	defer ts.Close()

	alice := connectWithCredential(t, ts.URL, "presence", "alice", nil)
	waitMatch[client.EvKeyReady](t, alice, nil, 5*time.Second)

	bobID, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bobCred := e2eCredential(t, bobID.Fingerprint(), "sam.okafor@acme.example", "Sam Okafor", "qa")
	bob, err := client.NewWithIdentity(ts.URL, "presence", "bob", bobID)
	if err != nil {
		t.Fatal(err)
	}
	if err := bob.UseIdentity(bobCred); err != nil {
		t.Fatal(err)
	}
	bctx, bcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer bcancel()
	if err := bob.Connect(bctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bob.Close() })

	joined := waitMatch[client.EvMemberJoined](t, alice,
		func(e client.EvMemberJoined) bool { return e.Name == "bob" }, 5*time.Second)

	want := mustMarshal(t, bobCred)
	if !bytes.Equal(joined.Attestation, want) {
		t.Fatalf("the relay forwarded %d attestation byte(s) on MemberJoined, want bob's credential "+
			"verbatim (%d bytes)\n got: %s\nwant: %s", len(joined.Attestation), len(want), joined.Attestation, want)
	}
}

// TestRelayCarriesTheAttestationOntoWelcome: the other arrival order. Alice is
// already present WITH a credential; bob joins and learns it from Welcome, which
// is a different relay code path (hub.Existing, not the join broadcast).
func TestRelayCarriesTheAttestationOntoWelcome(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLogger()))
	defer ts.Close()

	aliceID, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	aliceCred := e2eCredential(t, aliceID.Fingerprint(), "rosa.alvarez@acme.example", "Rosa Alvarez", "incident-commander")
	alice, err := client.NewWithIdentity(ts.URL, "presence-w", "alice", aliceID)
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.UseIdentity(aliceCred); err != nil {
		t.Fatal(err)
	}
	actx, acancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer acancel()
	if err := alice.Connect(actx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = alice.Close() })
	waitMatch[client.EvKeyReady](t, alice, nil, 5*time.Second)

	bob := connectWithCredential(t, ts.URL, "presence-w", "bob", nil)
	conn := waitMatch[client.EvConnected](t, bob, nil, 5*time.Second)
	if len(conn.Members) != 1 {
		t.Fatalf("bob's Welcome listed %d member(s), want 1", len(conn.Members))
	}
	want := mustMarshal(t, aliceCred)
	if !bytes.Equal(conn.Members[0].Attestation, want) {
		t.Fatalf("Welcome carried %d attestation byte(s), want alice's credential verbatim (%d bytes)\n"+
			" got: %s\nwant: %s", len(conn.Members[0].Attestation), len(want), conn.Members[0].Attestation, want)
	}
}

// TestRelayStaysBlindToTheAttestation states what the relay does with the field:
// it moves it. The frame the relay emits carries the attestation as one opaque
// base64 string under a key the relay never decodes into anything — the same
// treatment identity_key and kx_key get. Asserted on the relay's own bytes,
// because a decoded protocol.Member would hide a re-encoding.
func TestRelayStaysBlindToTheAttestation(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLogger()))
	defer ts.Close()

	aliceID, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	cred := e2eCredential(t, aliceID.Fingerprint(), "rosa.alvarez@acme.example", "Rosa Alvarez", "incident-commander")
	raw := rawWelcomeAfterJoin(t, ts.URL, "blindness", aliceID, cred)

	var env struct {
		Data struct {
			Members []struct {
				Attestation []byte `json:"attestation"`
			} `json:"members"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal welcome: %v\n%s", err, raw)
	}
	if len(env.Data.Members) != 1 {
		t.Fatalf("welcome listed %d member(s), want 1\n%s", len(env.Data.Members), raw)
	}
	want := mustMarshal(t, cred)
	if !bytes.Equal(env.Data.Members[0].Attestation, want) {
		t.Fatalf("the relay's own bytes carried a different attestation than the one that arrived\n"+
			" got: %s\nwant: %s", env.Data.Members[0].Attestation, want)
	}
}
