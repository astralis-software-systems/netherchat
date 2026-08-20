// Relay frames carrying an attestation, captured for the browser client's tests.
//
// frames.json holds Welcomes captured before this field existed and is left
// exactly as it was: those bytes are the pre-3b relay, and a browser bundle that
// stops surviving them has broken backward compatibility. This file is the other
// half — the same relay, now carrying a credential — written to its own file so
// the two cannot be confused and neither has to be regenerated to add the other.
//
//	GEN_INTEROP=1 go test ./tui/e2e -run TestGenPresenceFrames -v
//
// TestPresenceFramesMatchTheRelay is the ungated half: it captures fresh frames
// and asserts the committed file has the same SHAPE (the keys, the encoding, the
// attestation surviving verbatim), so the fixture cannot rot between
// regenerations. It cannot compare bytes — the relay assigns a random member id
// per connection — so it compares what the browser actually depends on.
package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
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

var presenceFramesPath = filepath.Join("..", "..", "web", "src", "net", "testdata", "presence-frames.json")

// rawJoinAttested dials the relay over a plain WebSocket with an attestation on
// the Hello, and returns the raw Welcome the relay replied with plus the
// connection, left open so the member stays in the room.
func rawJoinAttested(t *testing.T, url, room, name string, tag byte, attestation []byte) (*websocket.Conn, []byte) {
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
		Attestation:     attestation,
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
			return c, data
		}
	}
}

// readFrame reads until a frame of the given type arrives on an open connection.
func readFrame(t *testing.T, c *websocket.Conn, want protocol.Op) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		_, data, err := c.Read(ctx)
		if err != nil {
			t.Fatalf("read %s: %v", want, err)
		}
		var env protocol.Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			t.Fatalf("frame is not valid json: %v", err)
		}
		if env.Type == want {
			return data
		}
	}
}

// capturePresenceFrames stands up a relay, puts one attested member in a room,
// then joins as a second attested member — producing a Welcome that LISTS an
// attested member and a MemberJoined that IS one. Those are two different relay
// code paths and the browser has to survive both.
func capturePresenceFrames(t *testing.T) (welcome, joined, welcomeUnattested []byte) {
	t.Helper()
	ts := httptest.NewServer(server.Handler(config.Default(), quietLogger()))
	t.Cleanup(ts.Close)

	const room = "presencecap"
	first := fixedAttestation(t, "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"rosa.alvarez@acme.example", "Rosa Alvarez", []string{"incident-commander"}, true)
	second := fixedAttestation(t, "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
		"svc-deploybot@acme.example", "", []string{"deployer"}, true)

	firstConn, _ := rawJoinAttested(t, ts.URL, room, "rosa", 0x44, first)
	_, welcome = rawJoinAttested(t, ts.URL, room, "deploybot", 0x55, second)
	joined = readFrame(t, firstConn, protocol.OpMemberJoined)

	// And the control: a third joiner carrying nothing, so the browser tests have
	// a real relay's unattested Member beside the attested ones rather than an
	// assumption about what one looks like.
	_, welcomeUnattested = rawJoinAttested(t, ts.URL, room+"-plain", "plain", 0x66, nil)
	return welcome, joined, welcomeUnattested
}

func TestGenPresenceFrames(t *testing.T) {
	if os.Getenv("GEN_INTEROP") == "" {
		t.Skip("set GEN_INTEROP=1 to regenerate web/src/net/testdata/presence-frames.json")
	}
	welcome, joined, plain := capturePresenceFrames(t)
	out := framesFile{
		Comment: "Envelope bytes captured from a real Netherchat relay carrying identity attestations. " +
			"Feed them to a client verbatim; do not re-type them as literals in the consuming language. " +
			"frames.json holds the pre-3b captures and is deliberately untouched.",
		Generator: "GEN_INTEROP=1 go test ./tui/e2e -run TestGenPresenceFrames -v",
		Source:    "tui/e2e/presence_frames_gen_test.go, via server.Handler(config.Default()) over a raw WebSocket",
		Frames: map[string]string{
			"welcomeWithAttestedMember":  string(welcome),
			"memberJoinedAttested":       string(joined),
			"welcomeEmptyRoomUnattested": string(plain),
		},
	}
	blob, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	blob = append(blob, '\n')
	if err := os.MkdirAll(filepath.Dir(presenceFramesPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(presenceFramesPath, blob, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s\n  welcome : %s\n  joined  : %s\n  plain   : %s", presenceFramesPath, welcome, joined, plain)
}

// TestPresenceFramesMatchTheRelay is ungated: the fixture must keep describing
// the relay this build produces.
func TestPresenceFramesMatchTheRelay(t *testing.T) {
	raw, err := os.ReadFile(presenceFramesPath)
	if err != nil {
		t.Fatalf("the committed presence frames are missing: %v\n"+
			"Regenerate: GEN_INTEROP=1 go test ./tui/e2e -run TestGenPresenceFrames -v", err)
	}
	var committed framesFile
	if err := json.Unmarshal(raw, &committed); err != nil {
		t.Fatalf("committed frames: %v", err)
	}
	welcome, joined, plain := capturePresenceFrames(t)

	for _, tc := range []struct {
		key   string
		fresh []byte
	}{
		{"welcomeWithAttestedMember", welcome},
		{"memberJoinedAttested", joined},
		{"welcomeEmptyRoomUnattested", plain},
	} {
		if _, ok := committed.Frames[tc.key]; !ok {
			t.Errorf("the committed fixture has no %q frame", tc.key)
			continue
		}
		if a, b := attestationsIn(t, committed.Frames[tc.key]), attestationsIn(t, string(tc.fresh)); !equalByteSlices(a, b) {
			t.Errorf("%s: the committed fixture carries %d attestation(s) and this relay produces %d, "+
				"or their bytes differ. Regenerate.\n committed: %v\n     fresh: %v",
				tc.key, len(a), len(b), summarize(a), summarize(b))
		}
	}
	// The unattested control has to stay unattested, or it is not a control.
	if got := attestationsIn(t, committed.Frames["welcomeEmptyRoomUnattested"]); len(got) != 0 {
		t.Errorf("the unattested control carries %d attestation(s)", len(got))
	}
	// And the attested Welcome has to carry exactly what the sender sent, which is
	// the whole property the relay is on the hook for.
	want := fixedAttestation(t, "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"rosa.alvarez@acme.example", "Rosa Alvarez", []string{"incident-commander"}, true)
	got := attestationsIn(t, committed.Frames["welcomeWithAttestedMember"])
	if len(got) != 1 || !bytes.Equal(got[0], want) {
		t.Errorf("the committed Welcome does not carry rosa's credential verbatim:\n got: %s", summarize(got))
	}
}

// attestationsIn pulls every attestation out of an envelope, from either a
// Welcome's members list or a MemberJoined's member.
func attestationsIn(t *testing.T, frame string) [][]byte {
	t.Helper()
	var env struct {
		Type string `json:"type"`
		Data struct {
			Members []struct {
				Attestation []byte `json:"attestation"`
			} `json:"members"`
			Member struct {
				Attestation []byte `json:"attestation"`
			} `json:"member"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(frame), &env); err != nil {
		t.Fatalf("frame is not valid json: %v\n%s", err, frame)
	}
	var out [][]byte
	for _, m := range env.Data.Members {
		if len(m.Attestation) > 0 {
			out = append(out, m.Attestation)
		}
	}
	if len(env.Data.Member.Attestation) > 0 {
		out = append(out, env.Data.Member.Attestation)
	}
	return out
}

func equalByteSlices(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

func summarize(bs [][]byte) []string {
	out := make([]string, len(bs))
	for i, b := range bs {
		if len(b) > 48 {
			out[i] = base64.StdEncoding.EncodeToString(b[:48]) + "…"
			continue
		}
		out[i] = base64.StdEncoding.EncodeToString(b)
	}
	return out
}
