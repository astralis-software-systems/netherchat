package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/server/internal/alert"
	"github.com/salehkreiner/netherchat/server/internal/beacon"
	"github.com/salehkreiner/netherchat/server/internal/ephemeral"
	"github.com/salehkreiner/netherchat/server/internal/hub"
	"github.com/salehkreiner/netherchat/server/internal/invite"
)

func ingressFixture(t *testing.T) (*httptest.Server, *ephemeral.Registry) {
	t.Helper()
	cfg := config.Default()
	cfg.Sources = []config.SourceConfig{
		{Name: "scanner", Token: "tok"},
		{Name: "siem", HMACSecret: "s3cr3t"},
	}
	cfg.Routes = []config.RouteConfig{{
		Action:     "break-glass",
		Match:      map[string]string{"severity": "high"},
		Invite:     []string{"alice", "bob"},
		RoomPrefix: "inc",
	}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	eph := ephemeral.New(log)
	a := New(hub.New(cfg, log), cfg, invite.New(), eph, beacon.New(), alert.NewGuards(), log)
	mux := http.NewServeMux()
	a.Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts, eph
}

func postAlert(t *testing.T, base, body, token string) (int, alertResponse) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+"/api/v1/alert", strings.NewReader(body))
	if token != "" {
		req.Header.Set("X-Netherchat-Token", token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post alert: %v", err)
	}
	defer resp.Body.Close()
	var out alertResponse
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
	return resp.StatusCode, out
}

func hmacSig(secret string, a alert.AlertV1) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(protocol.AlertSigningBytes(a.Source, a.Severity, a.Kind, a.Summary, a.Ref, a.TS))
	return hex.EncodeToString(mac.Sum(nil))
}

// TestAlertSpawnsRoomAndInvites is the core NC-1 acceptance: a signed, schema-valid
// POST spawns a room and mints an invite per route, and the alert's metadata lands
// ONLY as a plaintext, ephemeral join notice — never anything more.
func TestAlertSpawnsRoomAndInvites(t *testing.T) {
	ts, eph := ingressFixture(t)
	body := `{"source":"scanner","severity":"high","kind":"finding","summary":"s3 bucket public","ref":"CIS-1.20"}`
	code, out := postAlert(t, ts.URL, body, "tok")
	if code != http.StatusOK || !out.Spawned {
		t.Fatalf("valid alert did not spawn: code=%d out=%+v", code, out)
	}
	if out.Room == "" || out.Links["alice"] == "" || out.Links["bob"] == "" {
		t.Fatalf("expected room + per-invitee links: %+v", out)
	}
	er, ok := eph.Get(out.Room)
	if !ok {
		t.Fatalf("spawned room %q not in registry", out.Room)
	}
	want := alert.AlertV1{Source: "scanner", Severity: "high", Kind: "finding", Summary: "s3 bucket public", Ref: "CIS-1.20"}.NoticeLine()
	if er.Notice != want {
		t.Fatalf("notice = %q, want %q", er.Notice, want)
	}
}

func TestAlertHMACSource(t *testing.T) {
	ts, _ := ingressFixture(t)
	a := alert.AlertV1{Source: "siem", Severity: "high", Kind: "correlation", Summary: "lateral movement"}
	a.Signature = hmacSig("s3cr3t", a)
	body, _ := json.Marshal(a)
	code, out := postAlert(t, ts.URL, string(body), "")
	if code != http.StatusOK || !out.Spawned {
		t.Fatalf("valid HMAC alert did not spawn: code=%d out=%+v", code, out)
	}
}

// TestAlertRejectsAndSpawnsNothing: every unauthenticated/malformed POST is
// rejected and spawns nothing.
func TestAlertRejectsAndSpawnsNothing(t *testing.T) {
	ts, _ := ingressFixture(t)
	cases := []struct {
		name, body, token string
		want              int
	}{
		{"bad token", `{"source":"scanner","severity":"high","kind":"finding"}`, "wrong", http.StatusUnauthorized},
		{"unknown source", `{"source":"ghost","severity":"high","kind":"finding"}`, "tok", http.StatusUnauthorized},
		{"missing hmac sig", `{"source":"siem","severity":"high","kind":"finding"}`, "", http.StatusUnauthorized},
		{"unknown field", `{"source":"scanner","severity":"high","kind":"finding","x":1}`, "tok", http.StatusBadRequest},
		{"not json", `nope`, "tok", http.StatusBadRequest},
	}
	for _, c := range cases {
		code, out := postAlert(t, ts.URL, c.body, c.token)
		if code != c.want {
			t.Errorf("%s: code = %d, want %d", c.name, code, c.want)
		}
		if out.Spawned || out.Room != "" {
			t.Errorf("%s: should not have spawned (%+v)", c.name, out)
		}
	}
}

func TestAlertNoRouteMatch(t *testing.T) {
	ts, _ := ingressFixture(t)
	// severity "low" matches no route; the alert is still accepted, just spawns nothing.
	code, out := postAlert(t, ts.URL, `{"source":"scanner","severity":"low","kind":"finding"}`, "tok")
	if code != http.StatusOK {
		t.Fatalf("code = %d, want 200", code)
	}
	if !out.Accepted || out.Spawned || out.Room != "" {
		t.Fatalf("no-match should be accepted but not spawned: %+v", out)
	}
}
