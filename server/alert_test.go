package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/salehkreiner/netherchat/server/config"
)

// ingressConfig is a relay with one token source and a catch-all-on-severity route.
func ingressConfig() config.Config {
	cfg := config.Default()
	cfg.Sources = []config.SourceConfig{{Name: "scanner", Token: "tok"}}
	cfg.Routes = []config.RouteConfig{{
		Action:     "break-glass",
		Match:      map[string]string{"severity": "high"},
		Invite:     []string{"alice"},
		RoomPrefix: "inc",
	}}
	return cfg
}

type alertResp struct {
	Accepted bool              `json:"accepted"`
	Spawned  bool              `json:"spawned"`
	Room     string            `json:"room"`
	Links    map[string]string `json:"links"`
}

// TestIngressEndToEnd drives the generic ingress socket through the full Handler: a
// signed, schema-valid POST spawns a room with invites; an unauthenticated or
// malformed one does not.
func TestIngressEndToEnd(t *testing.T) {
	ts := httptest.NewServer(Handler(ingressConfig(), discardLog()))
	defer ts.Close()

	// Valid: spawns a room + an invite link per route invitee.
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/alert",
		strings.NewReader(`{"source":"scanner","severity":"high","kind":"finding","summary":"x"}`))
	req.Header.Set("X-Netherchat-Token", "tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("valid alert status = %d, want 200", resp.StatusCode)
	}
	var out alertResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.Spawned || out.Room == "" || out.Links["alice"] == "" {
		t.Fatalf("expected spawn + link: %+v", out)
	}

	// Unauthenticated → 401, malformed → 400.
	for _, c := range []struct {
		body, token string
		want        int
	}{
		{`{"source":"scanner","severity":"high","kind":"finding"}`, "nope", http.StatusUnauthorized},
		{`{"source":"scanner","severity":"high"}`, "tok", http.StatusBadRequest},
	} {
		r, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/alert", strings.NewReader(c.body))
		if c.token != "" {
			r.Header.Set("X-Netherchat-Token", c.token)
		}
		rr, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		rr.Body.Close()
		if rr.StatusCode != c.want {
			t.Errorf("body %q: status = %d, want %d", c.body, rr.StatusCode, c.want)
		}
	}
}

// TestIngressCannotAct is the second law at the HTTP boundary: an inbound source
// can open a room and post a notice, but there is NO server endpoint by which it
// could approve, seal, or execute. Those actions are end-to-end, client-signed,
// room-keyed messages a blind relay can never originate — so they have no HTTP
// surface at all, and probing for one returns 404.
func TestIngressCannotAct(t *testing.T) {
	ts := httptest.NewServer(Handler(ingressConfig(), discardLog()))
	defer ts.Close()

	for _, path := range []string{
		"/api/v1/seal", "/api/v1/approve", "/api/v1/action", "/api/v1/exec", "/api/v1/run",
	} {
		resp, err := http.Post(ts.URL+path, "application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatalf("post %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("POST %s = %d, want 404 (no act endpoint must exist)", path, resp.StatusCode)
		}
	}
}
