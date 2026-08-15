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
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
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
	ts := httptest.NewServer(server.Handler(config.Default(), quietLogger()))
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

// cryptoPkg is the import path of the client crypto package, taken from the
// package itself rather than written out as a string literal. The guard below
// asserts an ABSENCE, and an absence is vacuously true the moment you look for a
// name that no longer exists: rename or move the package and a hardcoded path
// would keep passing forever while checking nothing at all. Derived this way the
// path follows the package, and a path that stopped resolving would not compile.
//
// This value is platform-stable, which matters because the guard below resolves
// graphs for platforms other than the host. It is a compile-time constant of THIS
// test binary, built for the host, and an import path is a module-relative directory
// path: build constraints select files WITHIN a package, never the package's path.
// tui/internal/crypto carries no build tags and compiles the same nine files on
// every target, so there is no GOOS on which crypto.Identity resolves elsewhere.
var cryptoPkg = reflect.TypeOf(crypto.Identity{}).PkgPath()

// TestServerBinaryDoesNotLinkClientCrypto proves the blind-relay boundary at the
// build-graph level: the server binary's transitive dependencies must not
// include the client crypto package. The server literally cannot decrypt.
//
// The graph is resolved once per released platform (serverBuildTargets), not once
// for the host. Package sets are GOOS-conditional, so an import reaching the relay
// through a build-constrained file is invisible from a machine that does not build
// that file — which is exactly how github.com/google/uuid slipped past the module
// guard next door and landed on main. README.md sells this test as the reason "the
// relay cannot read your messages" is a property of the build graph rather than a
// promise; that sentence is about every binary shipped, so the check is too.
//
// Like the egress guard next door, this does not skip when the toolchain
// misbehaves: a guard that can silently not run is not a guard, and `go test`
// running at all means `go list` is there. README.md sells this check as "CI
// fails if that ever changes ... not a marketing line", and a Skip would make
// that sentence true only on the days nothing went wrong — a module-cache blip
// or a transient download failure would turn the boundary check into a green
// tick. serverLinkedPackagesFor fails loudly on a go list error or an empty graph,
// per platform, so the only way to reach the comparisons below is holding real
// graphs for all of them.
func TestServerBinaryDoesNotLinkClientCrypto(t *testing.T) {
	counts := make([]string, 0, len(serverBuildTargets))

	for _, tgt := range serverBuildTargets {
		platform := tgt.GOOS + "/" + tgt.GOARCH
		pkgs := serverLinkedPackagesFor(t, tgt.GOOS, tgt.GOARCH)

		linked := make(map[string]bool, len(pkgs))
		for _, p := range pkgs {
			linked[p.ImportPath] = true
		}

		// Positive control: packages the relay must link, matched exactly the way the
		// crypto path is matched below. If these are missing, the comparison is not
		// finding packages that ARE in the graph, and the absence proved afterwards
		// would mean nothing.
		//
		// Checked per platform, not once against the union: a target that resolved to
		// a truncated graph contributes no packages, so it would prove its absence
		// vacuously and hide behind the targets that did resolve. Every platform earns
		// its own positive control before its absence counts for anything.
		for _, must := range []string{serverMainPkg, netherchatModule + "/protocol"} {
			if !linked[must] {
				t.Fatalf("%s is absent from the %d-package %s dependency graph for %s; the guard is not inspecting the relay", must, len(linked), serverMainPkg, platform)
			}
		}

		for _, p := range pkgs {
			if p.ImportPath != cryptoPkg && !strings.HasPrefix(p.ImportPath, cryptoPkg+"/") {
				continue
			}
			t.Fatalf(`the server binary transitively imports %s on %s — the blind-relay boundary is violated.

Only packages under tui/ may reach the client crypto package; that Go visibility rule is
what makes "the server cannot read message content" a property of the build graph rather
than a promise. To share a type across the boundary, put a crypto-free one in protocol/ —
do not import %s from a server-side package.

The import was found while resolving the graph for %s and may sit behind a build
constraint, so a build on your own machine can look clean. The boundary holds on every
released platform or it does not hold.`, p.ImportPath, platform, cryptoPkg, platform)
		}

		counts = append(counts, fmt.Sprintf("%s=%d", platform, len(linked)))
	}

	t.Logf("%s absent from %s across %d platforms (%s)", cryptoPkg, serverMainPkg, len(serverBuildTargets), strings.Join(counts, " "))
}
