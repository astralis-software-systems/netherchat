package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/eventlog"
)

// incidentRoomRE is the auto-war-room name shape: <prefix>-<8 hex>.
var incidentRoomRE = regexp.MustCompile(`^inc-[0-9a-f]{8}$`)

// routeConfig is a server config with a webhook intake room ("alerts") and a
// single critical → break-glass route, with web_url set so join links are
// absolute. Used by the auto-war-room tests (§1.3).
func routeConfig() config.Config {
	c := config.Default()
	c.Server.WebURL = "http://localhost:5173"
	c.Rooms = map[string]config.RoomConfig{
		"alerts": {Webhook: true, WebhookToken: "secret"},
	}
	c.Routes = []config.RouteConfig{{
		Match:  map[string]string{"severity": "critical"},
		Action: "break-glass",
		Invite: []string{"alice", "bob"},
		TTL:    config.Duration(time.Hour),
	}}
	return c
}

func postWebhook(t *testing.T, baseURL, room, token, body string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest("POST", baseURL+"/webhook/"+room, strings.NewReader(body))
	req.Header.Set("X-Netherchat-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("webhook post: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, b
}

// TestAutoWarRoomFires is the DEMO 1 acceptance test: a CRITICAL webhook matches
// a [[route]] and the HTTP response carries the spawned room and a per-invitee
// join link built from web_url.
func TestAutoWarRoomFires(t *testing.T) {
	ts := httptest.NewServer(server.Handler(routeConfig(), quietLogger()))
	defer ts.Close()

	resp, body := postWebhook(t, ts.URL, "alerts", "secret", `{"severity":"critical","text":"database down"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}

	var got struct {
		Room  string            `json:"room"`
		Links map[string]string `json:"links"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode response %s: %v", body, err)
	}
	if !incidentRoomRE.MatchString(got.Room) {
		t.Errorf("room = %q, want inc-<8 hex>", got.Room)
	}
	if len(got.Links) != 2 {
		t.Fatalf("links = %v, want one per invitee", got.Links)
	}
	for _, name := range []string{"alice", "bob"} {
		link, ok := got.Links[name]
		if !ok {
			t.Fatalf("no link for %s in %v", name, got.Links)
		}
		if !strings.HasPrefix(link, "http://localhost:5173/join?") {
			t.Errorf("%s link = %q, want web_url-based /join link", name, link)
		}
		if !strings.Contains(link, "room="+got.Room) || !strings.Contains(link, "token=") {
			t.Errorf("%s link = %q, want room+token query", name, link)
		}
	}
}

// TestWebhookFallThroughAndAuth covers the non-matching path and the auth gates:
// a non-matching payload is delivered as a normal plaintext message; a room
// without a webhook is 404; a bad token is 401.
func TestWebhookFallThroughAndAuth(t *testing.T) {
	ts := httptest.NewServer(server.Handler(routeConfig(), quietLogger()))
	defer ts.Close()

	watcher := connect(t, ts.URL, "alerts", "watcher", "")
	waitMatch[client.EvConnected](t, watcher, nil, 5*time.Second)

	// No severity field → no route matches → normal webhook delivery.
	resp, body := postWebhook(t, ts.URL, "alerts", "secret", `{"text":"just an fyi","from":"ci"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fallthrough status = %d, body=%s", resp.StatusCode, body)
	}
	sm := waitMatch[client.EvServerMessage](t, watcher, nil, 5*time.Second)
	if sm.Text != "just an fyi" || sm.From != "ci" {
		t.Fatalf("fallthrough message = %+v", sm)
	}

	// A room without a webhook configured is 404.
	resp404, _ := postWebhook(t, ts.URL, "general", "secret", `{"severity":"critical"}`)
	if resp404.StatusCode != http.StatusNotFound {
		t.Errorf("no-webhook room status = %d, want 404", resp404.StatusCode)
	}

	// A wrong token never reaches routing.
	resp401, _ := postWebhook(t, ts.URL, "alerts", "wrong", `{"severity":"critical"}`)
	if resp401.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad-token status = %d, want 401", resp401.StatusCode)
	}
}

// TestRouteFiredInTailStream proves the route_fired event reaches the structured
// event stream: an observer tailing the intake room sees a route_fired event
// (via the same Mapper `tail --json` uses) naming the spawned room.
func TestRouteFiredInTailStream(t *testing.T) {
	ts := httptest.NewServer(server.Handler(routeConfig(), quietLogger()))
	defer ts.Close()

	observer := connect(t, ts.URL, "alerts", "observer", "")
	waitMatch[client.EvConnected](t, observer, nil, 5*time.Second)

	resp, body := postWebhook(t, ts.URL, "alerts", "secret", `{"severity":"critical","text":"db down"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}

	mapper := eventlog.NewMapper("alerts", false)
	var fired *eventlog.Event
	deadline := time.After(5 * time.Second)
	for fired == nil {
		select {
		case ev := <-observer.Events():
			for _, e := range mapper.Map(ev) {
				if e.Type == "route_fired" {
					e := e
					fired = &e
				}
			}
		case <-observer.Done():
			t.Fatal("observer disconnected")
		case <-deadline:
			t.Fatal("timed out waiting for route_fired in the event stream")
		}
	}

	if !incidentRoomRE.MatchString(fired.Room) {
		t.Errorf("route_fired room = %q, want inc-<8 hex>", fired.Room)
	}
	if fired.TriggerRule == nil || *fired.TriggerRule != 0 {
		t.Errorf("trigger_rule = %v, want 0", fired.TriggerRule)
	}
	if strings.Join(fired.Invitees, ",") != "alice,bob" {
		t.Errorf("invitees = %v, want [alice bob]", fired.Invitees)
	}
	if fired.TTLSeconds != 3600 {
		t.Errorf("ttl_seconds = %d, want 3600", fired.TTLSeconds)
	}
	if fired.V != eventlog.SchemaVersion {
		t.Errorf("v = %d", fired.V)
	}
}

// TestRouteReplyURLFiresAsync proves the reply_url POST happens out of band: the
// reply target blocks, yet the webhook response still returns with the links —
// the response does not wait on the reply. The reply target receives the same
// JSON body.
func TestRouteReplyURLFiresAsync(t *testing.T) {
	gotReply := make(chan []byte, 1)
	release := make(chan struct{})
	replySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotReply <- b
		<-release // hold the reply open to prove the webhook response didn't wait
	}))
	defer replySrv.Close()
	defer close(release)

	cfg := routeConfig()
	cfg.Routes[0].ReplyURL = replySrv.URL
	ts := httptest.NewServer(server.Handler(cfg, quietLogger()))
	defer ts.Close()

	// The webhook response must return promptly even though the reply target is
	// blocked inside its handler.
	resp, body := postWebhook(t, ts.URL, "alerts", "secret", `{"severity":"critical","text":"db down"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}
	var got struct {
		Room  string            `json:"room"`
		Links map[string]string `json:"links"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	select {
	case rb := <-gotReply:
		var replied struct {
			Room  string            `json:"room"`
			Links map[string]string `json:"links"`
		}
		if err := json.Unmarshal(rb, &replied); err != nil {
			t.Fatalf("reply body not JSON: %v\n%s", err, rb)
		}
		if replied.Room != got.Room || len(replied.Links) != len(got.Links) {
			t.Errorf("reply body = %s, want same as response %s", rb, body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reply_url never received the POST")
	}
}
