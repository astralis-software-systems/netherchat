package sneakernet

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// Compile-time proof that both transports satisfy the one interface the client
// runs over — the seam that makes Sneakernet Mode possible (§1.1).
var (
	_ client.Transport = (*DirectTransport)(nil)
	_ client.Transport = (*client.RelayTransport)(nil)
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func mustID(t *testing.T) *crypto.Identity {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	return id
}

func waitEvent[T client.Event](t *testing.T, c *client.Client, timeout time.Duration) T {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case ev := <-c.Events():
			if v, ok := ev.(T); ok {
				return v
			}
		case <-c.Done():
			t.Fatalf("connection closed while waiting for %T", *new(T))
		case <-deadline:
			t.Fatalf("timed out waiting for %T", *new(T))
		}
	}
}

// waitInbound returns the first message FROM A PEER (skipping our own local echo),
// which is what a receive-side assertion cares about.
func waitInbound(t *testing.T, c *client.Client, timeout time.Duration) client.EvMessage {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case ev := <-c.Events():
			if m, ok := ev.(client.EvMessage); ok && !m.Self {
				return m
			}
		case <-c.Done():
			t.Fatalf("connection closed while waiting for an inbound message")
		case <-deadline:
			t.Fatalf("timed out waiting for an inbound message")
		}
	}
}

// directPair stands up a relay-LESS two-peer room: a host running a Coordinator
// (its own client over the in-process loopback, so it mints the key) and a joiner
// dialing in over a real TCP connection authenticated by Ed25519. No relay server
// is ever started — that is the whole point.
func directPair(t *testing.T) (host, joiner *client.Client, co *Coordinator) {
	t.Helper()
	hostID, joinerID := mustID(t), mustID(t)

	co = NewCoordinator("ops", hostID, quietLog())
	addr, err := co.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = co.Close() })

	host, err = client.NewWithIdentity(directPlaceholderURL, "ops", "alice", hostID)
	if err != nil {
		t.Fatalf("host client: %v", err)
	}
	if err := host.ConnectWith(co.Loopback()); err != nil {
		t.Fatalf("host connect: %v", err)
	}
	t.Cleanup(func() { _ = host.Close() })
	waitEvent[client.EvKeyReady](t, host, 5*time.Second) // host is first → mints the key

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dt, err := Dial(ctx, addr, joinerID, hostID.Fingerprint())
	if err != nil {
		t.Fatalf("joiner dial+auth: %v", err)
	}
	joiner, err = client.NewWithIdentity(directPlaceholderURL, "ops", "bob", joinerID)
	if err != nil {
		t.Fatalf("joiner client: %v", err)
	}
	if err := joiner.ConnectWith(dt); err != nil {
		t.Fatalf("joiner connect: %v", err)
	}
	t.Cleanup(func() { _ = joiner.Close() })
	waitEvent[client.EvKeyReady](t, joiner, 5*time.Second) // key wrapped by the host, no relay
	return host, joiner, co
}

// TestDirectE2ENoRelay is the §1.1 acceptance test: two peers exchange E2E-encrypted
// messages with NO relay process running. If this fails, the feature is not done.
func TestDirectE2ENoRelay(t *testing.T) {
	host, joiner, _ := directPair(t)

	if err := host.Send("we cannot assume the relay host is clean"); err != nil {
		t.Fatalf("host send: %v", err)
	}
	got := waitInbound(t, joiner, 5*time.Second)
	if got.Text != "we cannot assume the relay host is clean" || !got.Signed {
		t.Fatalf("joiner received %+v, want the signed message", got)
	}

	if err := joiner.Send("agreed — re-forming peer to peer"); err != nil {
		t.Fatalf("joiner send: %v", err)
	}
	back := waitInbound(t, host, 5*time.Second)
	if back.Text != "agreed — re-forming peer to peer" || !back.Signed {
		t.Fatalf("host received %+v, want the signed reply", back)
	}
}

// TestDirectVanish proves the epoch ratchet (/vanish) works over the direct
// transport: both peers advance to the next key and messages still flow.
func TestDirectVanish(t *testing.T) {
	host, joiner, _ := directPair(t)
	before := host.Epoch()

	host.Vanish()
	// The joiner ratchets on the relayed vanish control.
	waitEvent[client.EvControl](t, joiner, 5*time.Second)

	if host.Epoch() != before+1 {
		t.Fatalf("host epoch = %d, want %d after vanish", host.Epoch(), before+1)
	}
	// A message under the NEW epoch still decrypts on the other side.
	if err := host.Send("post-vanish"); err != nil {
		t.Fatalf("send after vanish: %v", err)
	}
	got := waitInbound(t, joiner, 5*time.Second)
	if got.Text != "post-vanish" {
		t.Fatalf("post-vanish message = %q", got.Text)
	}
}

// TestDirectSeal proves the multi-party sealed record (/decide + /seal) works over
// the direct transport: the host records a decision, both co-sign, and the host
// finalizes a 2-signer record — all with no relay.
func TestDirectSeal(t *testing.T) {
	host, joiner, _ := directPair(t)

	if err := host.Decide("rolled back to v2.3.1"); err != nil {
		t.Fatalf("decide: %v", err)
	}
	waitEvent[client.EvRecordEntry](t, joiner, 5*time.Second) // entry propagated to the joiner

	if err := host.Seal(); err != nil {
		t.Fatalf("host seal: %v", err)
	}
	waitEvent[client.EvSealRequest](t, joiner, 5*time.Second) // joiner sees the proposal
	if err := joiner.Seal(); err != nil {
		t.Fatalf("joiner co-sign: %v", err)
	}

	done := waitEvent[client.EvSealComplete](t, host, 5*time.Second)
	if done.Entries != 1 {
		t.Fatalf("sealed entries = %d, want 1", done.Entries)
	}
	if done.Signers != 2 {
		t.Fatalf("sealed signers = %d, want 2 (host + joiner)", done.Signers)
	}
	if done.Record == nil {
		t.Fatal("seal produced no record")
	}
}

// TestDirectAuthRejectsWrongFingerprint proves the Ed25519 gate: a dialer that
// expects a DIFFERENT host fingerprint than the one presented refuses to connect.
// A rogue process answering on the host's address cannot impersonate it.
func TestDirectAuthRejectsWrongFingerprint(t *testing.T) {
	hostID := mustID(t)
	co := NewCoordinator("ops", hostID, quietLog())
	addr, err := co.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer co.Close()

	dialerID := mustID(t)
	imposterFpr := mustID(t).Fingerprint() // a fingerprint the host does NOT hold

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = Dial(ctx, addr, dialerID, imposterFpr)
	if err == nil {
		t.Fatal("dial succeeded against a host whose fingerprint did not match — auth gate failed")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("error = %v, want an identity mismatch", err)
	}

	// The same host, dialed with the CORRECT fingerprint, authenticates fine.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	dt, err := Dial(ctx2, addr, dialerID, hostID.Fingerprint())
	if err != nil {
		t.Fatalf("dial with the correct fingerprint failed: %v", err)
	}
	if dt.PeerID() != hostID.Fingerprint() {
		t.Fatalf("authenticated peer = %s, want %s", dt.PeerID(), hostID.Fingerprint())
	}
	_ = dt.Close()
}

// TestBlobRoundTrip proves an offer blob armors, parses, and verifies.
func TestBlobRoundTrip(t *testing.T) {
	id := mustID(t)
	b, err := NewBlob(id, "ops", []string{"192.168.1.42:7777", "10.0.0.5:7777"})
	if err != nil {
		t.Fatalf("new blob: %v", err)
	}
	if err := b.Verify(); err != nil {
		t.Fatalf("fresh blob did not verify: %v", err)
	}
	parsed, err := ParseBlob(b.Armor("offer"))
	if err != nil {
		t.Fatalf("parse armored offer: %v", err)
	}
	if parsed.Fpr != id.Fingerprint() || parsed.Room != "ops" || len(parsed.Addrs) != 2 {
		t.Fatalf("parsed blob = %+v", parsed)
	}
}

// TestBlobCompactRoundTrip proves the QR-encoded (Compact, no armor) offer form
// parses back — so a scanned `pair --manual --qr` offer is usable (§2.4).
func TestBlobCompactRoundTrip(t *testing.T) {
	id := mustID(t)
	b, err := NewBlob(id, "ops", []string{"192.168.1.42:7777"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseBlob(b.Compact())
	if err != nil {
		t.Fatalf("parse compact (QR) blob: %v", err)
	}
	if parsed.Fpr != id.Fingerprint() {
		t.Fatalf("compact blob fingerprint = %s, want %s", parsed.Fpr, id.Fingerprint())
	}
}

// TestBlobExpired proves an expired blob is rejected.
func TestBlobExpired(t *testing.T) {
	id := mustID(t)
	b, err := NewBlob(id, "ops", []string{"127.0.0.1:7777"})
	if err != nil {
		t.Fatal(err)
	}
	// Backdate and re-sign so the signature is valid but the blob is expired.
	b.Expires = time.Now().Add(-time.Minute).Unix()
	sig, _ := id.Sign(b.signingBytes())
	b.Sig = base64.StdEncoding.EncodeToString(sig)

	if err := b.Verify(); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected an expiry error, got %v", err)
	}
}

// TestBlobTamperRejected proves a modified blob (re-routed addresses) fails the
// signature check.
func TestBlobTamperRejected(t *testing.T) {
	id := mustID(t)
	b, err := NewBlob(id, "ops", []string{"127.0.0.1:7777"})
	if err != nil {
		t.Fatal(err)
	}
	b.Addrs = []string{"10.6.6.6:7777"} // attacker substitutes their own address, no re-sign
	if err := b.Verify(); err == nil {
		t.Fatal("a tampered blob verified; the signature must cover the addresses")
	}
}

// TestTransportLabel proves /whoami reports the direct mode.
func TestTransportLabel(t *testing.T) {
	host, joiner, co := directPair(t)
	if got := TransportLabel(host, co); !strings.Contains(got, "direct") {
		t.Fatalf("host transport label = %q, want it to mention direct", got)
	}
	if got := TransportLabel(joiner, nil); !strings.Contains(got, "direct (1 peer") {
		t.Fatalf("joiner transport label = %q, want direct (1 peer …)", got)
	}
}

// TestMDNSAdvertiseBrowse exercises the LAN discovery path on loopback. mDNS needs
// working multicast, which many CI/sandbox networks lack — so this skips (does not
// fail) when nothing is discovered.
//
// It is opt-in because the advertise is a real side effect on the local network,
// and the skips below happen only AFTER that side effect. Not testing.Short():
// `-short` means slow, and this test is not slow, it is side-effecting.
func TestMDNSAdvertiseBrowse(t *testing.T) {
	if os.Getenv("NETHERCHAT_TEST_MDNS") == "" {
		t.Skip("mDNS LAN discovery is opt-in: it binds UDP 5353 and advertises " +
			"_netherchat._tcp on the local network. Set NETHERCHAT_TEST_MDNS=1 to run it.")
	}
	id := mustID(t)
	adv, err := Advertise(id, "ops", 7777)
	if err != nil {
		t.Skipf("mDNS advertise unavailable in this environment: %v", err)
	}
	defer adv.Close()

	ctx := context.Background()
	peers, err := Browse(ctx, "ops", 2*time.Second)
	if err != nil {
		t.Skipf("mDNS browse unavailable in this environment: %v", err)
	}
	found := false
	for _, p := range peers {
		if p.Fpr == id.Fingerprint() {
			found = true
		}
	}
	if !found {
		t.Skip("no mDNS peer discovered (multicast likely unavailable); the manual blob path is the fallback")
	}
}
