package bridge

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// These tests drive REAL clients through the REAL relay so the bridge consumes
// genuine decrypted, signature-verified events — the only honest way to prove the
// provenance path. The bridge is a normal room member here, exactly as in
// production; only its reaction (an HTTP callback) differs from the TUI's.

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newServer(t *testing.T) string {
	t.Helper()
	ts := httptest.NewServer(server.Handler(config.Default(), quietLog()))
	t.Cleanup(ts.Close)
	return ts.URL
}

// dialMember joins room as an ordinary E2E client, returning it and the identity
// it holds (so a test can verify signatures against the member's real public key).
func dialMember(t *testing.T, url, room, name string) (*client.Client, *crypto.Identity) {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	c, err := client.NewWithIdentity(url, room, name, id)
	if err != nil {
		t.Fatalf("new client %s: %v", name, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("connect %s: %v", name, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, id
}

func waitForEv[T client.Event](t *testing.T, c *client.Client, timeout time.Duration) T {
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

// captured is one received callback.
type captured struct {
	header http.Header
	body   []byte
}

// newSink is a callback endpoint that records each request and replies with status.
func newSink(t *testing.T, status int) (string, <-chan captured) {
	t.Helper()
	ch := make(chan captured, 16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ch <- captured{header: r.Header.Clone(), body: body}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, ch
}

func recv(t *testing.T, ch <-chan captured, timeout time.Duration) captured {
	t.Helper()
	select {
	case c := <-ch:
		return c
	case <-time.After(timeout):
		t.Fatal("timed out waiting for a callback")
		return captured{}
	}
}

func recvNone(t *testing.T, ch <-chan captured, within time.Duration) {
	t.Helper()
	select {
	case c := <-ch:
		t.Fatalf("unexpected extra callback: event=%q", c.header.Get("X-Netherchat-Event"))
	case <-time.After(within):
	}
}

func newBridge(t *testing.T, room, postURL string, on ...string) *Bridge {
	t.Helper()
	br, err := New(Config{Room: room, On: set(on...), PostURL: postURL, Out: io.Discard})
	if err != nil {
		t.Fatalf("new bridge: %v", err)
	}
	return br
}

// pump drives a bridge from a client's event stream, firing each matched callback.
// This is exactly what the daemon's event loop does (minus the per-fire goroutine,
// which is unnecessary against a fast local sink).
func pump(ctx context.Context, c *client.Client, br *Bridge) {
	for {
		select {
		case ev := <-c.Events():
			if cb, ok := br.Match(ev); ok {
				br.Fire(ctx, cb)
			}
		case <-c.Done():
			return
		case <-ctx.Done():
			return
		}
	}
}

func TestBridgeFiresOnMatchingEvents(t *testing.T) {
	url := newServer(t)
	alice, _ := dialMember(t, url, "ops", "alice")
	waitForEv[client.EvKeyReady](t, alice, 5*time.Second)
	bridgeC, _ := dialMember(t, url, "ops", "bridge")
	waitForEv[client.EvMemberJoined](t, alice, 5*time.Second) // bridge is now a registered member

	sinkURL, ch := newSink(t, http.StatusOK)
	br := newBridge(t, "ops", sinkURL, "decision", "ack")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pump(ctx, bridgeC, br)

	if err := alice.Decide("rolled back to v2.3.1"); err != nil {
		t.Fatalf("decide: %v", err)
	}
	if err := alice.Ack("drain-complete"); err != nil {
		t.Fatalf("ack: %v", err)
	}

	got := map[string]captured{}
	for i := 0; i < 2; i++ {
		c := recv(t, ch, 5*time.Second)
		got[c.header.Get("X-Netherchat-Event")] = c
	}
	for _, ev := range []string{"decision", "ack"} {
		c, ok := got[ev]
		if !ok {
			t.Fatalf("no %s callback fired", ev)
		}
		if c.header.Get("X-Netherchat-Room") != "ops" {
			t.Errorf("%s room header = %q", ev, c.header.Get("X-Netherchat-Room"))
		}
		if c.header.Get("X-Netherchat-Actor") != "alice" {
			t.Errorf("%s actor header = %q, want alice", ev, c.header.Get("X-Netherchat-Actor"))
		}
		if c.header.Get("X-Netherchat-Sig") == "" {
			t.Errorf("%s callback carried no X-Netherchat-Sig", ev)
		}
		if !json.Valid(c.body) {
			t.Errorf("%s body is not valid JSON: %s", ev, c.body)
		}
	}
}

func TestBridgeIgnoresUnsubscribedEvents(t *testing.T) {
	url := newServer(t)
	alice, _ := dialMember(t, url, "ops", "alice")
	waitForEv[client.EvKeyReady](t, alice, 5*time.Second)
	bridgeC, _ := dialMember(t, url, "ops", "bridge")
	waitForEv[client.EvMemberJoined](t, alice, 5*time.Second)

	sinkURL, ch := newSink(t, http.StatusOK)
	br := newBridge(t, "ops", sinkURL, "ack") // ack only — decision must be ignored
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pump(ctx, bridgeC, br)

	// The decision is sent first; if the bridge wrongly fired on it, it would arrive
	// before the ack (same ordered relay connection).
	if err := alice.Decide("rolled back to v2.3.1"); err != nil {
		t.Fatalf("decide: %v", err)
	}
	if err := alice.Ack("drain-complete"); err != nil {
		t.Fatalf("ack: %v", err)
	}

	first := recv(t, ch, 5*time.Second)
	if ev := first.header.Get("X-Netherchat-Event"); ev != "ack" {
		t.Fatalf("first (and only) callback was %q, want ack — decision must not fire", ev)
	}
	recvNone(t, ch, 500*time.Millisecond)
}

func TestSigHeaderCarriesOriginalSignature(t *testing.T) {
	url := newServer(t)
	alice, _ := dialMember(t, url, "ops", "alice")
	waitForEv[client.EvKeyReady](t, alice, 5*time.Second)
	bridgeC, _ := dialMember(t, url, "ops", "bridge")
	waitForEv[client.EvKeyReady](t, bridgeC, 5*time.Second) // bridge holds the key + is registered

	sinkURL, ch := newSink(t, http.StatusOK)
	br := newBridge(t, "ops", sinkURL, "ack")

	if err := alice.Ack("drain-complete"); err != nil {
		t.Fatalf("ack: %v", err)
	}
	ack := waitForEv[client.EvAck](t, bridgeC, 5*time.Second)
	if len(ack.Sig) == 0 {
		t.Fatal("decrypted EvAck carried no signature")
	}
	cb, ok := br.Match(ack)
	if !ok {
		t.Fatal("bridge did not match the ack")
	}
	br.Fire(context.Background(), cb)

	req := recv(t, ch, 5*time.Second)
	want := base64.StdEncoding.EncodeToString(ack.Sig)
	if got := req.header.Get("X-Netherchat-Sig"); got != want {
		t.Fatalf("X-Netherchat-Sig = %q, want the original frame signature %q", got, want)
	}
}

func TestProvenanceVerifiesAgainstActorKey(t *testing.T) {
	url := newServer(t)
	alice, aliceID := dialMember(t, url, "ops", "alice")
	waitForEv[client.EvKeyReady](t, alice, 5*time.Second)
	bridgeC, _ := dialMember(t, url, "ops", "bridge")
	waitForEv[client.EvKeyReady](t, bridgeC, 5*time.Second)

	sinkURL, ch := newSink(t, http.StatusOK)
	br := newBridge(t, "ops", sinkURL, "ack")

	if err := alice.Ack("drain-complete"); err != nil {
		t.Fatalf("ack: %v", err)
	}
	ack := waitForEv[client.EvAck](t, bridgeC, 5*time.Second)

	// The event itself verifies against alice's real public key over the bytes the
	// signature covers — this is the cryptographic provenance the bridge forwards.
	if !ed25519.Verify(aliceID.SignPub, ack.SignBytes, ack.Sig) {
		t.Fatal("EvAck signature does not verify against alice's public key")
	}

	cb, _ := br.Match(ack)
	br.Fire(context.Background(), cb)
	req := recv(t, ch, 5*time.Second)

	// The signature reconstructed from the header verifies the same way — a receiver
	// holding alice's key can attribute the callback to her, not to the relay.
	sig, err := base64.StdEncoding.DecodeString(req.header.Get("X-Netherchat-Sig"))
	if err != nil {
		t.Fatalf("decode sig header: %v", err)
	}
	if !ed25519.Verify(aliceID.SignPub, ack.SignBytes, sig) {
		t.Fatal("X-Netherchat-Sig header does not verify against alice's public key")
	}
	if got := req.header.Get("X-Netherchat-Fpr"); got != aliceID.Fingerprint() {
		t.Fatalf("X-Netherchat-Fpr = %q, want alice's fingerprint %q", got, aliceID.Fingerprint())
	}
}

func TestMultipleBridgesWatchIndependently(t *testing.T) {
	url := newServer(t)
	alice, _ := dialMember(t, url, "ops", "alice")
	waitForEv[client.EvKeyReady](t, alice, 5*time.Second)
	b1c, _ := dialMember(t, url, "ops", "bridge-1")
	waitForEv[client.EvMemberJoined](t, alice, 5*time.Second)
	b2c, _ := dialMember(t, url, "ops", "bridge-2")
	waitForEv[client.EvMemberJoined](t, alice, 5*time.Second)

	sinkURL, ch := newSink(t, http.StatusOK)
	br1 := newBridge(t, "ops", sinkURL, "ack")
	br2 := newBridge(t, "ops", sinkURL, "ack")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pump(ctx, b1c, br1)
	go pump(ctx, b2c, br2)

	if err := alice.Ack("rollback"); err != nil {
		t.Fatalf("ack: %v", err)
	}

	// Each independent bridge fires its own callback for the one ack.
	for i := 0; i < 2; i++ {
		c := recv(t, ch, 5*time.Second)
		if ev := c.header.Get("X-Netherchat-Event"); ev != "ack" {
			t.Fatalf("callback %d event = %q, want ack", i, ev)
		}
		if c.header.Get("X-Netherchat-Actor") != "alice" {
			t.Fatalf("callback %d actor = %q, want alice", i, c.header.Get("X-Netherchat-Actor"))
		}
	}
	recvNone(t, ch, 500*time.Millisecond)
}

func TestBridgeSurvivesMemberJoinLeave(t *testing.T) {
	url := newServer(t)
	alice, _ := dialMember(t, url, "ops", "alice")
	waitForEv[client.EvKeyReady](t, alice, 5*time.Second)
	bridgeC, _ := dialMember(t, url, "ops", "bridge")
	waitForEv[client.EvMemberJoined](t, alice, 5*time.Second)

	sinkURL, ch := newSink(t, http.StatusOK)
	br := newBridge(t, "ops", sinkURL, "ack")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pump(ctx, bridgeC, br)

	// Membership churns under the bridge: carol joins, then leaves. The bridge's
	// event loop sees member_joined / member_left (which it ignores) and must not
	// crash or wedge.
	carol, _ := dialMember(t, url, "ops", "carol")
	waitForEv[client.EvMemberJoined](t, alice, 5*time.Second)
	_ = carol.Close()
	waitForEv[client.EvMemberLeft](t, alice, 5*time.Second)

	// After the churn, an ack still flows through to a callback.
	if err := alice.Ack("post-churn"); err != nil {
		t.Fatalf("ack: %v", err)
	}
	c := recv(t, ch, 5*time.Second)
	if ev := c.header.Get("X-Netherchat-Event"); ev != "ack" {
		t.Fatalf("post-churn callback event = %q, want ack", ev)
	}
}
