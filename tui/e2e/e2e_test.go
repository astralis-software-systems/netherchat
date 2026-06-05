// Package e2e holds the M1 acceptance test: two client cores exchanging
// end-to-end-encrypted messages through the real relay server, plus a proof that
// what the server relays is ciphertext only, and a structural guard that the
// server binary cannot even link the client crypto package.
//
// This package lives under tui/ so it is allowed (by Go's internal rule) to
// import the client crypto package.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

const secret = "NETHERCHAT::SECRET::do-not-leak::a1b2c3d4"

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// waitMatch consumes events until one of type T satisfying pred arrives, or
// fails the test on timeout / disconnect.
func waitMatch[T client.Event](t *testing.T, c *client.Client, pred func(T) bool, timeout time.Duration) T {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case ev := <-c.Events():
			if v, ok := ev.(T); ok && (pred == nil || pred(v)) {
				return v
			}
		case <-c.Done():
			t.Fatalf("connection closed while waiting for %T", *new(T))
		case <-deadline:
			t.Fatalf("timed out waiting for %T", *new(T))
		}
	}
}

func newClient(t *testing.T, url, name string) *client.Client {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	c, err := client.NewWithIdentity(url, "general", name, id)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("connect %s: %v", name, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestEndToEndThroughBlindRelay(t *testing.T) {
	ts := httptest.NewServer(server.Handler(quietLogger()))
	defer ts.Close()

	// Alice connects first and mints the room key.
	alice := newClient(t, ts.URL, "alice")
	waitMatch[client.EvKeyReady](t, alice, nil, 5*time.Second)

	// Bob connects; the server asks Alice (oldest member) to wrap the room key
	// for him. Bob holds the key once EvKeyReady fires — without the server ever
	// seeing it.
	bob := newClient(t, ts.URL, "bob")
	waitMatch[client.EvKeyReady](t, bob, nil, 5*time.Second)

	// Eve is a passive eavesdropper: a raw WebSocket member that records every
	// frame the server relays to it but never uses the key. She stands in for
	// "what the server can see" — pure relayed bytes.
	eve := newEavesdropper(t, ts.URL)

	// Alice -> Bob.
	if err := alice.Send(secret); err != nil {
		t.Fatalf("alice send: %v", err)
	}
	got := waitMatch[client.EvMessage](t, bob, func(m client.EvMessage) bool { return !m.Self }, 5*time.Second)
	if got.Text != secret {
		t.Fatalf("bob decrypted %q, want %q", got.Text, secret)
	}
	if got.FromName != "alice" {
		t.Errorf("bob saw sender %q, want alice", got.FromName)
	}

	// Bob -> Alice (bidirectional).
	const reply = "ack: " + secret
	if err := bob.Send(reply); err != nil {
		t.Fatalf("bob send: %v", err)
	}
	got = waitMatch[client.EvMessage](t, alice, func(m client.EvMessage) bool { return !m.Self }, 5*time.Second)
	if got.Text != reply {
		t.Fatalf("alice decrypted %q, want %q", got.Text, reply)
	}

	// The server relayed two messages to Eve. Assert that none of the raw frames
	// she captured contain the plaintext anywhere — the relay carried ciphertext
	// only. This is the automated form of "a Wireshark capture shows ciphertext".
	frames := eve.waitForMessages(t, 2, 5*time.Second)
	for i, raw := range frames {
		if bytes.Contains(raw, []byte(secret)) || bytes.Contains(raw, []byte(reply)) {
			t.Fatalf("relayed frame %d leaked plaintext: %s", i, raw)
		}
		var env protocol.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatalf("frame %d not valid json: %v", i, err)
		}
		if env.Type != protocol.OpMessage {
			continue
		}
		var m protocol.Message
		if err := env.Decode(&m); err != nil {
			t.Fatalf("frame %d decode: %v", i, err)
		}
		if len(m.Ciphertext) == 0 {
			t.Fatalf("frame %d has empty ciphertext", i)
		}
		if bytes.Contains(m.Ciphertext, []byte(secret)) || bytes.Contains(m.Ciphertext, []byte(reply)) {
			t.Fatalf("frame %d ciphertext leaked plaintext", i)
		}
	}
}

// eavesdropper is a raw WebSocket member that records relayed frames without
// ever decrypting them.
type eavesdropper struct {
	got chan []byte
}

func newEavesdropper(t *testing.T, url string) *eavesdropper {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("eve identity: %v", err)
	}
	wsurl := strings.Replace(strings.Replace(url, "https://", "wss://", 1), "http://", "ws://", 1) + "/ws"

	dialCtx, cancelDial := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelDial()
	c, resp, err := websocket.Dial(dialCtx, wsurl, nil)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		t.Fatalf("eve dial: %v", err)
	}
	c.SetReadLimit(1 << 20)
	t.Cleanup(func() { _ = c.Close(websocket.StatusNormalClosure, "bye") })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	hello, _ := protocol.Encode(protocol.OpHello, protocol.Hello{
		ProtocolVersion: protocol.Version,
		Room:            "general",
		DisplayName:     "eve",
		IdentityKey:     id.SignPub,
		KXKey:           id.KXPub[:],
	})
	if err := wsjson.Write(ctx, c, hello); err != nil {
		t.Fatalf("eve hello: %v", err)
	}

	e := &eavesdropper{got: make(chan []byte, 64)}
	ready := make(chan struct{})
	go func() {
		var once bool
		for {
			_, data, err := c.Read(ctx)
			if err != nil {
				return
			}
			var env protocol.Envelope
			_ = json.Unmarshal(data, &env)
			if env.Type == protocol.OpWelcome && !once {
				once = true
				close(ready) // Eve is now a registered room member
			}
			if env.Type == protocol.OpMessage {
				e.got <- bytes.Clone(data)
			}
		}
	}()

	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("eve never received welcome")
	}
	return e
}

func (e *eavesdropper) waitForMessages(t *testing.T, n int, timeout time.Duration) [][]byte {
	t.Helper()
	var frames [][]byte
	deadline := time.After(timeout)
	for len(frames) < n {
		select {
		case f := <-e.got:
			frames = append(frames, f)
		case <-deadline:
			t.Fatalf("eve captured %d/%d relayed message frames before timeout", len(frames), n)
		}
	}
	return frames
}

// TestServerBinaryDoesNotLinkClientCrypto proves the blind-relay boundary at the
// build-graph level: the server binary's transitive dependencies must not
// include the client crypto package. The server literally cannot decrypt.
func TestServerBinaryDoesNotLinkClientCrypto(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/salehkreiner/netherchat/cmd/netherchat-server").CombinedOutput()
	if err != nil {
		t.Skipf("go list unavailable: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "tui/internal/crypto") {
		t.Fatalf("server binary transitively imports tui/internal/crypto — blind-relay boundary violated")
	}
}
