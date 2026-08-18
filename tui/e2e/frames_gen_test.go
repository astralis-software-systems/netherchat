// Captured wire frames for the browser client's tests.
//
// The web tests had one structural blind spot: every frame they fed the client
// was a TypeScript object literal typed against web/src/net/protocol.ts. The
// type system therefore decided what the wire could contain, and the wire
// disagreed — `Welcome.members` is a Go slice that marshals to `null` for an
// empty room, a shape `members: WireMember[]` forbids anyone from even writing
// down. A fixture authored in the consuming language cannot catch that class of
// defect; only bytes the relay actually produced can.
//
// So TestGenWireFrames stands up a real relay, joins it over a raw WebSocket for
// both the empty-room and non-empty-room cases, and writes the exact envelope
// bytes the relay sent to web/src/net/testdata/frames.json. web/src/net's tests
// replay those strings through the client's onmessage unparsed. Regenerate with:
//
//	GEN_INTEROP=1 go test ./tui/e2e -run TestGenWireFrames -v
//
// It follows the generator pattern already used for the crypto vectors
// (tui/internal/crypto TestGenInteropVector): skipped in normal runs, the
// artifact committed.
//
// TestWelcomeMembersIsNeverNull is the Go half of the same contract, and it is
// NOT gated: it asserts on the relay's real bytes that `members` is an array
// even when the room was empty. Without it the fixture can only regress at the
// next regeneration, which may be never.
package e2e

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
	"net/http/httptest"
)

// fixedKeys returns a deterministic 32-byte Ed25519-shaped and X25519-shaped key
// pair for a captured member. They are not real keys and never used to seal
// anything: the browser client only requires 32 bytes to register a member
// (web/src/net/client.ts addMember). Fixed so that regenerating the fixture
// produces a small diff instead of two fresh base64 blobs.
func fixedKeys(tag byte) (signPub, kxPub []byte) {
	signPub = make([]byte, 32)
	kxPub = make([]byte, 32)
	for i := range signPub {
		signPub[i] = tag ^ byte(i)
		kxPub[i] = tag ^ byte(0x80+i)
	}
	return signPub, kxPub
}

// rawJoin dials the relay over a plain WebSocket, sends a Hello, and returns the
// raw bytes of the Welcome frame the relay replied with. The connection is left
// open (closed at test cleanup) so the member stays in the room and the next
// caller sees a non-empty one.
func rawJoin(t *testing.T, url, room, name string, tag byte) []byte {
	t.Helper()
	wsurl := strings.Replace(strings.Replace(url, "https://", "wss://", 1), "http://", "ws://", 1) + "/ws"

	dialCtx, cancelDial := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelDial()
	c, resp, err := websocket.Dial(dialCtx, wsurl, nil)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		t.Fatalf("%s dial: %v", name, err)
	}
	c.SetReadLimit(1 << 20)
	t.Cleanup(func() { _ = c.Close(websocket.StatusNormalClosure, "bye") })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	signPub, kxPub := fixedKeys(tag)
	hello, err := protocol.Encode(protocol.OpHello, protocol.Hello{
		ProtocolVersion: protocol.Version,
		Room:            room,
		DisplayName:     name,
		IdentityKey:     signPub,
		KXKey:           kxPub,
	})
	if err != nil {
		t.Fatalf("%s encode hello: %v", name, err)
	}
	if err := wsjson.Write(ctx, c, hello); err != nil {
		t.Fatalf("%s hello: %v", name, err)
	}

	for {
		_, data, err := c.Read(ctx)
		if err != nil {
			t.Fatalf("%s read: %v", name, err)
		}
		var env protocol.Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			t.Fatalf("%s frame is not valid json: %v", name, err)
		}
		if env.Type == protocol.OpWelcome {
			return data
		}
	}
}

// captureWelcomes returns the relay's raw Welcome bytes for the first joiner
// into an empty room and for the second joiner into that now non-empty room.
func captureWelcomes(t *testing.T) (empty, nonEmpty []byte) {
	t.Helper()
	ts := httptest.NewServer(server.Handler(config.Default(), quietLogger()))
	t.Cleanup(ts.Close)

	const room = "wirecap"
	empty = rawJoin(t, ts.URL, room, "first", 0x11)
	nonEmpty = rawJoin(t, ts.URL, room, "second", 0x22)
	return empty, nonEmpty
}

// framesFile is the shape written to web/src/net/testdata/frames.json. Frames
// are stored as strings holding the literal envelope JSON, not as nested
// objects: the consuming test must hand them to the client unparsed, and a
// nested object would let the reader's own types reshape them on the way in.
type framesFile struct {
	Comment   string            `json:"_comment"`
	Generator string            `json:"_generator"`
	Source    string            `json:"_source"`
	Frames    map[string]string `json:"frames"`
}

func TestGenWireFrames(t *testing.T) {
	if os.Getenv("GEN_INTEROP") == "" {
		t.Skip("set GEN_INTEROP=1 to regenerate web/src/net/testdata/frames.json")
	}

	empty, nonEmpty := captureWelcomes(t)

	out := framesFile{
		Comment: "Envelope bytes captured from a real Netherchat relay. Feed them to a " +
			"client verbatim; do not re-type them as literals in the consuming language.",
		Generator: "GEN_INTEROP=1 go test ./tui/e2e -run TestGenWireFrames -v",
		Source:    "tui/e2e/frames_gen_test.go, via server.Handler(config.Default()) over a raw WebSocket",
		Frames: map[string]string{
			"welcomeEmptyRoom":    string(empty),
			"welcomeNonEmptyRoom": string(nonEmpty),
		},
	}

	blob, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	blob = append(blob, '\n')

	path := filepath.Join("..", "..", "web", "src", "net", "testdata", "frames.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir testdata: %v", err)
	}
	if err := os.WriteFile(path, blob, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Logf("wrote %s\n  empty room   : %s\n  non-empty    : %s", path, empty, nonEmpty)
}

// TestWelcomeMembersIsNeverNull pins the invariant PROTOCOL.md states: welcome
// lists the members already present, and an empty list is an empty array. Go's
// own decoder accepts `null` into a slice and Go's `range` accepts a nil slice,
// so nothing on this side of the wire notices — which is exactly why the
// assertion has to be made against the marshalled bytes rather than against a
// decoded protocol.Welcome.
func TestWelcomeMembersIsNeverNull(t *testing.T) {
	empty, nonEmpty := captureWelcomes(t)

	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"empty room", empty},
		{"non-empty room", nonEmpty},
	} {
		var env struct {
			Type protocol.Op `json:"type"`
			Data struct {
				Members     json.RawMessage `json:"members"`
				YouAreFirst bool            `json:"you_are_first"`
			} `json:"data"`
		}
		if err := json.Unmarshal(tc.raw, &env); err != nil {
			t.Fatalf("%s: unmarshal welcome: %v", tc.name, err)
		}
		if env.Type != protocol.OpWelcome {
			t.Fatalf("%s: got frame type %q, want %q", tc.name, env.Type, protocol.OpWelcome)
		}
		if got := string(env.Data.Members); got == "null" {
			t.Errorf("%s (you_are_first=%v): welcome.members is JSON null; it must be an array so a "+
				"non-Go client can iterate it.\n  frame: %s", tc.name, env.Data.YouAreFirst, tc.raw)
		}
	}
}
