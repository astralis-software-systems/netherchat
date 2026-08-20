package sneakernet

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// PAIR MODE IS THE MODE NOTHING ELSE COVERS.
//
// protocol.Member is built field by field at three sites, and the coordinator's
// is the third. interop-live runs a relay, so it exercises the relay's Member
// literal and structurally cannot reach this one; a field named at the other two
// and forgotten here compiles, ships, and silently drops every attestation in
// relay-less mode. tui/e2e/presence_carrier_test.go catches that omission in the
// source; this catches it in the behaviour, and between them the next field is
// covered from both directions.
//
// Membership travels two ways and both are asserted, because they are two
// different literals reached by two different code paths: the joiner learns
// about the host from Welcome, and the host learns about the joiner from
// MemberJoined.

// presenceCredential signs an attestation about subject. displayName may be
// empty, which is a legal binding an issuer that has no name to assert produces.
func presenceCredential(t *testing.T, subject, principal, displayName string, roles ...string) *attest.IdentityAttestation {
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
		Issuer:        crypto.Fingerprint(pub),
	}, nil, nil)
	sig := ed25519.Sign(priv, attest.IdentitySigningBytes(unsigned))
	return unsigned.WithSignatures(
		map[string][]byte{crypto.Fingerprint(pub): sig},
		map[string][]byte{crypto.Fingerprint(pub): pub},
	)
}

func marshalled(t *testing.T, a *attest.IdentityAttestation) []byte {
	t.Helper()
	b, err := a.Marshal()
	if err != nil {
		t.Fatalf("marshal attestation: %v", err)
	}
	return b
}

// presencePair is a relay-LESS pair whose peers both carry a credential, with
// the events each one saw up to and including its key. UseIdentity happens
// before ConnectWith because the Hello is enqueued by ConnectWith: provisioning
// after it has gone out provisions nothing.
type presencePair struct {
	host, joiner           *client.Client
	hostCred, joinerCred   *attest.IdentityAttestation
	hostEvents, joinEvents []client.Event
}

// collectUntilKey drains a client's events until EvKeyReady, returning them all,
// so an assertion can look at EvConnected — which waitEvent would have thrown
// away on its way past.
func collectUntilKey(t *testing.T, c *client.Client, timeout time.Duration) []client.Event {
	t.Helper()
	var got []client.Event
	deadline := time.After(timeout)
	for {
		select {
		case ev := <-c.Events():
			got = append(got, ev)
			if _, ok := ev.(client.EvKeyReady); ok {
				return got
			}
		case <-c.Done():
			t.Fatalf("connection closed while waiting for the room key")
		case <-deadline:
			t.Fatalf("timed out waiting for the room key")
		}
	}
}

func newPresencePair(t *testing.T, hostDisplayName, joinerDisplayName string) presencePair {
	t.Helper()
	hostID, joinerID := mustID(t), mustID(t)
	hostCred := presenceCredential(t, hostID.Fingerprint(), "rosa.alvarez@acme.example", hostDisplayName, "incident-commander")
	joinerCred := presenceCredential(t, joinerID.Fingerprint(), "sam.okafor@acme.example", joinerDisplayName, "qa")

	co := NewCoordinator("ops", hostID, quietLog())
	addr, err := co.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = co.Close() })

	// Through newSessionClient, not around it: Options.Credential is the surface
	// `netherchat pair --attestation` fills in, and a test that called UseIdentity
	// itself would prove the wire works while the command that reaches it did
	// nothing. cmd/netherchat covers the flag above this; this covers Options
	// downward.
	host, err := newSessionClient(Options{Room: "ops", Name: "alice", Credential: hostCred}, hostID)
	if err != nil {
		t.Fatalf("host client: %v", err)
	}
	if err := host.ConnectWith(co.Loopback()); err != nil {
		t.Fatalf("host connect: %v", err)
	}
	t.Cleanup(func() { _ = host.Close() })
	hostEvents := collectUntilKey(t, host, 5*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dt, err := Dial(ctx, addr, joinerID, hostID.Fingerprint())
	if err != nil {
		t.Fatalf("joiner dial+auth: %v", err)
	}
	joiner, err := newSessionClient(Options{Room: "ops", Name: "bob", Credential: joinerCred}, joinerID)
	if err != nil {
		t.Fatalf("joiner client: %v", err)
	}
	if err := joiner.ConnectWith(dt); err != nil {
		t.Fatalf("joiner connect: %v", err)
	}
	t.Cleanup(func() { _ = joiner.Close() })
	joinEvents := collectUntilKey(t, joiner, 5*time.Second)

	return presencePair{host, joiner, hostCred, joinerCred, hostEvents, joinEvents}
}

func connectedFrom(t *testing.T, evs []client.Event) client.EvConnected {
	t.Helper()
	for _, ev := range evs {
		if c, ok := ev.(client.EvConnected); ok {
			return c
		}
	}
	t.Fatal("no EvConnected among the events collected before the room key")
	return client.EvConnected{}
}

// TestDirectWelcomeCarriesTheHostCredential — relay-less, the joiner's Welcome
// names the host as an existing member and that Member carries the host's
// attestation verbatim.
func TestDirectWelcomeCarriesTheHostCredential(t *testing.T) {
	p := newPresencePair(t, "Rosa Alvarez", "Sam Okafor")
	conn := connectedFrom(t, p.joinEvents)
	if len(conn.Members) != 1 {
		t.Fatalf("joiner saw %d existing member(s), want 1", len(conn.Members))
	}
	want := marshalled(t, p.hostCred)
	got := conn.Members[0].Attestation
	if !bytes.Equal(got, want) {
		t.Fatalf("Welcome's Member carried %d attestation byte(s) with no relay running, want the "+
			"host's credential verbatim (%d bytes)\n got: %s\nwant: %s", len(got), len(want), got, want)
	}
}

// TestDirectMemberJoinedCarriesTheJoinerCredential — the other direction, and a
// different literal: the coordinator broadcasts the joiner's Member to the host.
func TestDirectMemberJoinedCarriesTheJoinerCredential(t *testing.T) {
	p := newPresencePair(t, "Rosa Alvarez", "Sam Okafor")
	joined := waitEvent[client.EvMemberJoined](t, p.host, 5*time.Second)
	want := marshalled(t, p.joinerCred)
	if !bytes.Equal(joined.Attestation, want) {
		t.Fatalf("MemberJoined carried %d attestation byte(s) with no relay running, want the "+
			"joiner's credential verbatim (%d bytes)\n got: %s\nwant: %s",
			len(joined.Attestation), len(want), joined.Attestation, want)
	}
}

// TestDirectPresenceInertWithoutCredentials is the standalone-inert half in the
// mode with no relay: two peers carrying nothing see nil, not an empty artifact
// and not an error. The room still forms and still encrypts.
func TestDirectPresenceInertWithoutCredentials(t *testing.T) {
	host, joiner, _ := directPair(t)
	if err := host.Send("nothing carried here"); err != nil {
		t.Fatalf("host send: %v", err)
	}
	if got := waitInbound(t, joiner, 5*time.Second); got.Text != "nothing carried here" || !got.Signed {
		t.Fatalf("joiner received %+v, want the signed message", got)
	}
	joined := waitEvent[client.EvMemberJoined](t, host, 5*time.Second)
	if joined.Attestation != nil {
		t.Errorf("a peer that carried no credential produced %d attestation byte(s): %s",
			len(joined.Attestation), joined.Attestation)
	}
}
