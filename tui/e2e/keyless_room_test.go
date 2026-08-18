// Harness C — what a room does when it outlives every holder of its key.
//
// Room lifetime at the relay is membership and nothing else: a room is created on
// the first Join and deleted the moment it empties (server/internal/hub). The
// relay holds no key material by construction, so "does anyone here still hold a
// key" is not a question it can answer, and `you_are_first` — the sole trigger for
// minting — is `len(members) == 0`. Put those together and a room that is never
// empty can never be re-founded, whatever happened to its key.
//
// These two tests PIN THAT AS IT IS. They are characterization tests, not a fix:
// nothing in this session implements the distributor self-heal (mint on a
// KeyRequest you cannot answer, deliver to every member) that would close it. They
// exist so the wedge cannot be closed by accident and unnoticed, and so the one
// recovery that does work today — /scuttle from a client with no key at all — is
// nailed down before anyone builds on it. When the self-heal lands, the first test
// is the one that must be rewritten, and its failure is the signal that it worked.
package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// deadFounder is a member that founds a room, genuinely mints epoch 0, and then
// loses its transport at the worst possible moment: on receipt of the KeyRequest
// naming it the distributor, before it can answer.
//
// It is a raw WebSocket rather than a client.Client because the timing has to be
// exact. client.Client answers a KeyRequest inside its own read loop with no event
// emitted in between, so a test driving one could only close the connection and
// hope to win the race. Everything the relay and the other members can observe is
// identical either way: the minted key never leaves this process, so whether it
// exists at all is unobservable to anyone else — which is precisely the property
// that makes the wedge possible.
type deadFounder struct {
	selfID string
	died   chan struct{} // closed once the KeyRequest arrived and the transport went away
}

func newDeadFounder(t *testing.T, url, room string) *deadFounder {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("founder identity: %v", err)
	}
	wsurl := strings.Replace(strings.Replace(url, "https://", "wss://", 1), "http://", "ws://", 1) + "/ws"

	dialCtx, cancelDial := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelDial()
	c, resp, err := websocket.Dial(dialCtx, wsurl, nil)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		t.Fatalf("founder dial: %v", err)
	}
	c.SetReadLimit(1 << 20)
	t.Cleanup(func() { c.CloseNow() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	hello, err := protocol.Encode(protocol.OpHello, protocol.Hello{
		ProtocolVersion: protocol.Version,
		Room:            room,
		DisplayName:     "founder",
		IdentityKey:     id.SignPub,
		KXKey:           id.KXPub[:],
	})
	if err != nil {
		t.Fatalf("founder encode hello: %v", err)
	}
	if err := wsjson.Write(ctx, c, hello); err != nil {
		t.Fatalf("founder hello: %v", err)
	}

	f := &deadFounder{died: make(chan struct{})}
	welcomed := make(chan protocol.Welcome, 1)
	failed := make(chan string, 1)

	go func() {
		for {
			_, data, err := c.Read(ctx)
			if err != nil {
				return
			}
			var env protocol.Envelope
			if err := json.Unmarshal(data, &env); err != nil {
				continue
			}
			switch env.Type {
			case protocol.OpWelcome:
				var w protocol.Welcome
				if err := env.Decode(&w); err != nil {
					failed <- "founder could not decode welcome: " + err.Error()
					return
				}
				welcomed <- w
			case protocol.OpKeyRequest:
				// The relay named us the distributor. Hold the key and die.
				c.CloseNow()
				close(f.died)
				return
			}
		}
	}()

	select {
	case w := <-welcomed:
		if !w.YouAreFirst {
			t.Fatalf("founder was not first into %q; the room already existed", room)
		}
		f.selfID = w.YourID
	case msg := <-failed:
		t.Fatal(msg)
	case <-time.After(5 * time.Second):
		t.Fatal("founder never received welcome")
	}

	// Mint epoch 0 exactly as a real founder does, so the room genuinely has a key
	// holder for as long as this connection lives. The key is deliberately never
	// used: it dies with the transport above, which is the whole point.
	if _, err := crypto.NewRoomKey(0); err != nil {
		t.Fatalf("founder mint epoch 0: %v", err)
	}
	return f
}

func (f *deadFounder) awaitDeath(t *testing.T) {
	t.Helper()
	select {
	case <-f.died:
	case <-time.After(5 * time.Second):
		t.Fatal("the relay never asked the founder to distribute the room key")
	}
}

// liveRooms reads the relay's own room list. Room existence is a relay-side fact,
// so it is asserted from the relay rather than inferred from what a client saw.
func liveRooms(t *testing.T, url string) map[string]int {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url+"/rooms", nil)
	if err != nil {
		t.Fatalf("build GET /rooms: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /rooms: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		Rooms []struct {
			Name    string `json:"name"`
			Members int    `json:"members"`
		} `json:"rooms"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode /rooms: %v", err)
	}
	out := make(map[string]int, len(body.Rooms))
	for _, r := range body.Rooms {
		out[r.Name] = r.Members
	}
	return out
}

// assertNoKeyReady fails if a key arrives within d. Absence needs a window, and
// the window is short on purpose: the claim is not "no key ever" but "no key from
// any mechanism the join itself sets in motion", and every such mechanism is
// synchronous with the join.
func assertNoKeyReady(t *testing.T, c *client.Client, name string, d time.Duration) {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case ev := <-c.Events():
			if kr, ok := ev.(client.EvKeyReady); ok {
				t.Fatalf("%s received a room key (epoch %d) in a room where nobody holds one", name, kr.Epoch)
			}
		case <-c.Done():
			t.Fatalf("%s was disconnected while waiting", name)
		case <-deadline:
			return
		}
	}
}

// wedgeRoom drives the room into the keyless state and returns the surviving,
// keyless member. The founder mints and dies on the KeyRequest; bob is left
// holding nothing in a room that still exists.
func wedgeRoom(t *testing.T, url, room string) *client.Client {
	t.Helper()
	founder := newDeadFounder(t, url, room)

	bob := connect(t, url, room, "bob", "")
	conn := waitMatch[client.EvConnected](t, bob, nil, 5*time.Second)
	if conn.YouAreFirst {
		t.Fatal("bob was told he founded the room; the founder's join did not register")
	}

	founder.awaitDeath(t)
	waitMatch[client.EvMemberLeft](t, bob, nil, 5*time.Second)
	return bob
}

// TestRoomOutlivesItsOnlyKeyHolder pins today's behaviour: the room survives, no
// re-mint happens, the surviving members cannot talk to each other or to anyone
// who joins later, and nothing is sent to the relay or to the newcomer to say so.
//
// If this test starts failing, read the failure before "fixing" it — the likely
// cause is that distributor self-heal landed, in which case the assertions here are
// the ones that are out of date.
func TestRoomOutlivesItsOnlyKeyHolder(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLogger()))
	defer ts.Close()
	const room = "wedged"

	bob := wedgeRoom(t, ts.URL, room)

	// Bob is alone in a room he did not found and holds no key. He cannot mint:
	// minting is gated on you_are_first, which he was not.
	assertNoKeyReady(t, bob, "bob", 300*time.Millisecond)
	if err := bob.Send("anyone there"); err == nil {
		t.Fatal("bob sent a message without a room key")
	} else if !strings.Contains(err.Error(), "room key not established") {
		t.Fatalf("bob's send failed with %q, want a room-key error", err)
	}

	// Carol joins. The room is non-empty, so she is not first either, and the relay
	// designates bob — the oldest member — as her distributor.
	carol := connect(t, ts.URL, room, "carol", "")
	cc := waitMatch[client.EvConnected](t, carol, nil, 5*time.Second)
	if cc.YouAreFirst {
		t.Fatal("carol was told she founded the room: the room did not persist, and this test no longer pins the wedge")
	}

	// Bob's whole response to being made distributor is a line in his own
	// transcript. Nothing goes back to the relay and nothing goes to carol.
	ev := waitMatch[client.EvError](t, bob, func(e client.EvError) bool {
		return strings.Contains(e.Err.Error(), "we don't hold one")
	}, 5*time.Second)
	if !strings.Contains(ev.Err.Error(), "asked to distribute room key") {
		t.Fatalf("distributor error = %q, want the 'asked to distribute' notice", ev.Err)
	}

	// Carol waits forever. That is the defect, stated as an assertion.
	assertNoKeyReady(t, carol, "carol", 500*time.Millisecond)

	// And the relay still has the room, with both of them in it.
	if got := liveRooms(t, ts.URL)[room]; got != 2 {
		t.Fatalf("relay reports %d members in %q, want 2 — the room should have persisted", got, room)
	}
}

// TestScuttleFromKeylessClientTearsTheRoomDown pins the one recovery that works
// today. It is the documented escape hatch from the state above, and it is worth
// pinning precisely because it works for a non-obvious reason: scuttleBurn tries to
// collect a signed scuttle receipt first, startReceiptRound refuses without a room
// key, and the refusal falls through to the raw burn. Nothing about that chain is
// self-evident, and a future change to the receipt round could quietly remove the
// only way out of a wedged room.
func TestScuttleFromKeylessClientTearsTheRoomDown(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLogger()))
	defer ts.Close()
	const room = "wedged-then-burned"

	bob := wedgeRoom(t, ts.URL, room)
	if got := liveRooms(t, ts.URL)[room]; got != 1 {
		t.Fatalf("relay reports %d members in %q before the scuttle, want 1", got, room)
	}

	if err := bob.ScuttleNow(); err != nil {
		t.Fatalf("/scuttle from a keyless client: %v", err)
	}

	// The burn comes back as a server-orchestrated control broadcast, exactly as it
	// does for a client that holds a key.
	ev := waitMatch[client.EvControl](t, bob, func(e client.EvControl) bool {
		return e.Action == protocol.ActionScuttle
	}, 5*time.Second)
	if ev.Action != protocol.ActionScuttle {
		t.Fatalf("control action = %q, want %q", ev.Action, protocol.ActionScuttle)
	}

	// The relay tears the room down within a short grace window.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, still := liveRooms(t, ts.URL)[room]; !still {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("room %q still exists after a scuttle from a keyless client", room)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
