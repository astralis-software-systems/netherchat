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
	c.Exec.Enabled = true
	c.Exec.Allow = []string{"go version"}
	c.Rooms = map[string]config.RoomConfig{
		"alerts": {Webhook: true, WebhookToken: "secret"},
		"vault":  {InviteOnly: true},
		"ops":    {ExecEnabled: true},
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

func TestExecAllowlist(t *testing.T) {
	ts := httptest.NewServer(server.Handler(featureConfig(), quietLogger()))
	defer ts.Close()

	c := connect(t, ts.URL, "ops", "operator", "")
	waitMatch[client.EvConnected](t, c, nil, 5*time.Second)

	c.Exec("go version")
	r := waitMatch[client.EvExecResult](t, c, func(r client.EvExecResult) bool { return r.Command == "go version" }, 8*time.Second)
	if !r.Allowed {
		t.Fatalf("`go version` should be allowed: %+v", r)
	}
	if !strings.Contains(r.Output, "go version") {
		t.Errorf("exec output = %q", r.Output)
	}

	c.Exec("rm -rf /")
	bad := waitMatch[client.EvExecResult](t, c, func(r client.EvExecResult) bool { return r.Command == "rm -rf /" }, 8*time.Second)
	if bad.Allowed {
		t.Fatal("`rm -rf /` must be rejected — not on the allowlist")
	}
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
