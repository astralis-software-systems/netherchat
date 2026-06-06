package e2e

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// connect builds a client core connected to a specific room, optionally with an
// invite token.
func connect(t *testing.T, url, room, name, token string) *client.Client {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	c, err := client.NewWithIdentity(url, room, name, id)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if token != "" {
		c.UseInviteToken(token)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("connect %s: %v", name, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func featureConfig() config.Config {
	c := config.Default()
	c.Rooms = map[string]config.RoomConfig{
		"alerts": {Webhook: true, WebhookToken: "secret"},
		"vault":  {InviteOnly: true},
	}
	return c
}

func TestWebhookDeliversPlaintext(t *testing.T) {
	ts := httptest.NewServer(server.Handler(featureConfig(), quietLogger()))
	defer ts.Close()

	c := connect(t, ts.URL, "alerts", "watcher", "")
	waitMatch[client.EvConnected](t, c, nil, 5*time.Second)

	req, _ := http.NewRequest("POST", ts.URL+"/webhook/alerts", strings.NewReader(`{"text":"deploy done","from":"ci-bot"}`))
	req.Header.Set("X-Netherchat-Token", "secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("webhook post: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("webhook status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	sm := waitMatch[client.EvServerMessage](t, c, nil, 5*time.Second)
	if sm.Text != "deploy done" || sm.From != "ci-bot" || sm.Kind != "webhook" {
		t.Fatalf("server message = %+v", sm)
	}

	// A wrong token is rejected.
	bad, _ := http.NewRequest("POST", ts.URL+"/webhook/alerts", strings.NewReader(`{"text":"x"}`))
	bad.Header.Set("X-Netherchat-Token", "wrong")
	br, err := http.DefaultClient.Do(bad)
	if err != nil {
		t.Fatalf("bad webhook post: %v", err)
	}
	br.Body.Close()
	if br.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad-token status = %d, want 401", br.StatusCode)
	}
}

func TestInviteOnlyGating(t *testing.T) {
	ts := httptest.NewServer(server.Handler(featureConfig(), quietLogger()))
	defer ts.Close()

	// First member bootstraps the empty invite-only room.
	owner := connect(t, ts.URL, "vault", "owner", "")
	waitMatch[client.EvConnected](t, owner, nil, 5*time.Second)

	// Owner mints a one-time invite.
	owner.RequestInvite()
	inv := waitMatch[client.EvInvite](t, owner, nil, 5*time.Second)
	if inv.Token == "" {
		t.Fatal("expected an invite token")
	}

	// Without a token, joining the now-established room is rejected.
	intruder := connect(t, ts.URL, "vault", "intruder", "")
	e := waitMatch[client.EvError](t, intruder, nil, 5*time.Second)
	if !strings.Contains(e.Err.Error(), "invite") {
		t.Fatalf("expected invite error, got %v", e.Err)
	}

	// With the token, the guest is admitted.
	guest := connect(t, ts.URL, "vault", "guest", inv.Token)
	waitMatch[client.EvConnected](t, guest, nil, 5*time.Second)

	// The token is one-time: replaying it fails.
	replay := connect(t, ts.URL, "vault", "replay", inv.Token)
	e2 := waitMatch[client.EvError](t, replay, nil, 5*time.Second)
	if !strings.Contains(e2.Err.Error(), "invite") {
		t.Fatalf("expected one-time-token rejection, got %v", e2.Err)
	}
}

func TestBreakGlassWarRoom(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLogger()))
	defer ts.Close()

	// The commander is in an ordinary room and pulls the break-glass handle.
	commander := connect(t, ts.URL, "general", "commander", "")
	waitMatch[client.EvConnected](t, commander, nil, 5*time.Second)

	commander.BreakGlass([]string{"alice", "bob"}, 30) // server clamps up to its 1m floor
	bg := waitMatch[client.EvBreakGlass](t, commander, nil, 5*time.Second)

	if !strings.HasPrefix(bg.Room, "war-") {
		t.Fatalf("war room name = %q, want war-*", bg.Room)
	}
	if bg.HostToken == "" {
		t.Fatal("expected a host token")
	}
	if len(bg.Invites) != 2 || bg.Invites[0].Name != "alice" || bg.Invites[1].Name != "bob" {
		t.Fatalf("invites = %+v, want alice & bob", bg.Invites)
	}
	for _, in := range bg.Invites {
		if in.Token == "" {
			t.Fatalf("invite for %s has no token", in.Name)
		}
	}
	if bg.TTLSeconds <= 0 || bg.Expires.Before(time.Now()) {
		t.Fatalf("expected a future deadline, got ttl=%d expires=%s", bg.TTLSeconds, bg.Expires)
	}

	// The creator joins their own war room with the host token and bootstraps it.
	host := connect(t, ts.URL, bg.Room, "commander", bg.HostToken)
	waitMatch[client.EvKeyReady](t, host, nil, 5*time.Second)

	// alice joins with her one-time link and gets the room key via the distributor.
	alice := connect(t, ts.URL, bg.Room, "alice", bg.Invites[0].Token)
	waitMatch[client.EvKeyReady](t, alice, nil, 5*time.Second)

	// The war room is a real E2E room: host -> alice decrypts.
	if err := host.Send("the database is on fire"); err != nil {
		t.Fatalf("host send: %v", err)
	}
	got := waitMatch[client.EvMessage](t, alice, func(m client.EvMessage) bool { return !m.Self }, 5*time.Second)
	if got.Text != "the database is on fire" {
		t.Fatalf("alice decrypted %q", got.Text)
	}

	// alice's link is one-time: replaying it is rejected.
	replay := connect(t, ts.URL, bg.Room, "imposter", bg.Invites[0].Token)
	re := waitMatch[client.EvError](t, replay, nil, 5*time.Second)
	if !strings.Contains(re.Err.Error(), "invite") {
		t.Fatalf("expected one-time-token rejection, got %v", re.Err)
	}

	// The war room is invite-only: joining the now-populated room without a token
	// is rejected (no open bootstrap once it has members).
	crasher := connect(t, ts.URL, bg.Room, "crasher", "")
	ce := waitMatch[client.EvError](t, crasher, nil, 5*time.Second)
	if !strings.Contains(ce.Err.Error(), "invite") {
		t.Fatalf("expected invite-only rejection, got %v", ce.Err)
	}
}

// TestEdgeExecThroughBlindRelay proves the §0.1 redesign: an exec request is an
// E2E-signed message, the relay only routes ciphertext, and an agent (any room
// member) runs it on its own host and posts a signed result back — attributable
// by key fingerprint end to end.
func TestEdgeExecThroughBlindRelay(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLogger()))
	defer ts.Close()

	// The agent joins first and holds the room key.
	agent := connect(t, ts.URL, "ops", "agent@bastion", "")
	waitMatch[client.EvKeyReady](t, agent, nil, 5*time.Second)

	// An operator joins and requests a runbook action.
	op := connect(t, ts.URL, "ops", "alice", "")
	waitMatch[client.EvKeyReady](t, op, nil, 5*time.Second)

	id, err := op.RequestExec("drain")
	if err != nil {
		t.Fatalf("request exec: %v", err)
	}

	// The agent receives the signed request, attributed to alice by fingerprint.
	req := waitMatch[client.EvExecRequest](t, agent, func(e client.EvExecRequest) bool {
		return !e.Self && e.Cmd == "drain"
	}, 5*time.Second)
	if req.ID != id {
		t.Fatalf("request id mismatch: got %s want %s", req.ID, id)
	}
	if req.FromName != "alice" {
		t.Errorf("requester name = %q", req.FromName)
	}
	if !strings.HasPrefix(req.FromFingerprint, "SHA256:") {
		t.Errorf("requester fingerprint = %q (want ssh format)", req.FromFingerprint)
	}

	// The agent runs it locally (simulated here) and posts a signed result.
	if err := agent.PostExecResult(req.ID, req.Cmd, true, 0, "node drained"); err != nil {
		t.Fatalf("post exec result: %v", err)
	}

	// The operator receives the decrypted, attributed result.
	res := waitMatch[client.EvExecResult](t, op, func(e client.EvExecResult) bool { return e.ID == id }, 5*time.Second)
	if !res.Allowed || res.ExitCode != 0 || res.Output != "node drained" || res.Cmd != "drain" {
		t.Fatalf("exec result = %+v", res)
	}
	if !strings.HasPrefix(res.FromFingerprint, "SHA256:") {
		t.Errorf("result host fingerprint = %q", res.FromFingerprint)
	}
}

func TestHistoryReplay(t *testing.T) {
	cfg := config.Default()
	cfg.Persistence.Enabled = true // in-memory store (no path)
	cfg.Persistence.History = 50
	ts := httptest.NewServer(server.Handler(cfg, quietLogger()))
	defer ts.Close()

	a := connect(t, ts.URL, "general", "alice", "")
	waitMatch[client.EvKeyReady](t, a, nil, 5*time.Second)
	c := connect(t, ts.URL, "general", "carol", "")
	waitMatch[client.EvKeyReady](t, c, nil, 5*time.Second)

	a.Send("history one")
	a.Send("history two")
	// Confirm the server processed (hence stored) both before the next join.
	waitMatch[client.EvMessage](t, c, func(m client.EvMessage) bool { return m.Text == "history one" }, 5*time.Second)
	waitMatch[client.EvMessage](t, c, func(m client.EvMessage) bool { return m.Text == "history two" }, 5*time.Second)

	// A late joiner receives the replayed ciphertext history and decrypts it with
	// the still-live room key.
	b := connect(t, ts.URL, "general", "bob", "")
	waitMatch[client.EvKeyReady](t, b, nil, 5*time.Second)
	waitMatch[client.EvMessage](t, b, func(m client.EvMessage) bool { return m.Text == "history one" }, 5*time.Second)
	waitMatch[client.EvMessage](t, b, func(m client.EvMessage) bool { return m.Text == "history two" }, 5*time.Second)
}

func TestVanishKeepsClientsInSync(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLogger()))
	defer ts.Close()

	a := connect(t, ts.URL, "general", "alice", "")
	waitMatch[client.EvKeyReady](t, a, nil, 5*time.Second)
	b := connect(t, ts.URL, "general", "bob", "")
	waitMatch[client.EvKeyReady](t, b, nil, 5*time.Second)

	a.Send("before vanish")
	got := waitMatch[client.EvMessage](t, b, func(m client.EvMessage) bool { return !m.Self }, 5*time.Second)
	if got.Text != "before vanish" {
		t.Fatalf("pre-vanish = %q", got.Text)
	}

	a.Vanish()
	ctrl := waitMatch[client.EvControl](t, b, func(e client.EvControl) bool { return e.Action == "vanish" }, 5*time.Second)
	if ctrl.ByName != "alice" {
		t.Errorf("vanish by = %q", ctrl.ByName)
	}

	// After the vanish both sides have ratcheted to the new epoch deterministically,
	// so messaging still works without any re-keying.
	a.Send("after vanish")
	got2 := waitMatch[client.EvMessage](t, b, func(m client.EvMessage) bool { return !m.Self }, 5*time.Second)
	if got2.Text != "after vanish" {
		t.Fatalf("post-vanish = %q", got2.Text)
	}
}
