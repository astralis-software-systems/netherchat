package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/salehkreiner/netherchat/buildinfo"
	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/server/internal/alert"
	"github.com/salehkreiner/netherchat/server/internal/beacon"
	"github.com/salehkreiner/netherchat/server/internal/ephemeral"
	"github.com/salehkreiner/netherchat/server/internal/hub"
	"github.com/salehkreiner/netherchat/server/internal/invite"
)

// syncBuffer is a concurrency-safe sink for captured slog output.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// webhookCfg builds a config with the given rooms plus a catch-all severity=high
// break-glass route (so a matching payload spawns).
func webhookCfg(rooms map[string]config.RoomConfig) config.Config {
	c := config.Default()
	c.Rooms = rooms
	c.Routes = []config.RouteConfig{{
		Action:     "break-glass",
		Match:      map[string]string{"severity": "high"},
		Invite:     []string{"alice"},
		RoomPrefix: "inc",
	}}
	return c
}

// webhookServer wires an API over cfg with a FRESH guard set (so caps are isolated
// per test) and returns the test server plus a captured-log buffer.
func webhookServer(t *testing.T, cfg config.Config) (*httptest.Server, *syncBuffer) {
	t.Helper()
	buf := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	eph := ephemeral.New(log)
	a := New(hub.New(cfg, log), cfg, invite.New(), eph, beacon.New(), alert.NewGuards(), log)
	mux := http.NewServeMux()
	a.Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts, buf
}

func postHook(t *testing.T, base, room, token, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+"/webhook/"+room, strings.NewReader(body))
	if token != "" {
		req.Header.Set("X-Netherchat-Token", token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post webhook: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

const matchBody = `{"severity":"high","text":"db down"}` // matches the route → spawn
const plainBody = `{"text":"fyi","from":"ci"}`           // no match → plaintext delivery

// TestWebhookHappyPath: under the (generous) default caps, both a matching payload
// (spawns a room + links) and a non-matching payload (plaintext delivery) pass.
func TestWebhookHappyPath(t *testing.T) {
	ts, _ := webhookServer(t, webhookCfg(map[string]config.RoomConfig{
		"alerts": {Webhook: true, WebhookToken: "secretA"},
	}))

	code, body := postHook(t, ts.URL, "alerts", "secretA", matchBody)
	if code != http.StatusOK {
		t.Fatalf("matching webhook: code=%d body=%s", code, body)
	}
	var spawn struct {
		Room  string            `json:"room"`
		Links map[string]string `json:"links"`
	}
	if err := json.Unmarshal([]byte(body), &spawn); err != nil {
		t.Fatalf("decode spawn response: %v\n%s", err, body)
	}
	if spawn.Room == "" || spawn.Links["alice"] == "" {
		t.Fatalf("expected spawned room + per-invitee link: %s", body)
	}

	if code2, body2 := postHook(t, ts.URL, "alerts", "secretA", plainBody); code2 != http.StatusOK {
		t.Fatalf("non-matching webhook: code=%d body=%s", code2, body2)
	}
}

// TestWebhookRateTrip: a low per-token rate cap trips on the (burst+1)th request,
// 429 with the distinct per-token rate log reason. Non-matching body so the spawn
// guard is not involved — proving the RATE guard fired.
func TestWebhookRateTrip(t *testing.T) {
	ts, buf := webhookServer(t, webhookCfg(map[string]config.RoomConfig{
		"alerts": {Webhook: true, WebhookToken: "secretA", WebhookRatePerMinute: 3},
	}))

	for i := 0; i < 3; i++ {
		if code, b := postHook(t, ts.URL, "alerts", "secretA", plainBody); code != http.StatusOK {
			t.Fatalf("request %d should pass under burst 3: code=%d body=%s", i, code, b)
		}
	}
	code, b := postHook(t, ts.URL, "alerts", "secretA", plainBody)
	if code != http.StatusTooManyRequests {
		t.Fatalf("4th request should be 429, got %d body=%s", code, b)
	}
	if !strings.Contains(buf.String(), "rate limit (per-token)") {
		t.Errorf("expected per-token rate log reason; logs:\n%s", buf.String())
	}
}

// TestWebhookSpawnTrip: with a high rate cap but a low spawn cap, matching requests
// pass the rate guard and trip the SPAWN guard — 429 with the distinct spawn reason.
func TestWebhookSpawnTrip(t *testing.T) {
	ts, buf := webhookServer(t, webhookCfg(map[string]config.RoomConfig{
		"alerts": {Webhook: true, WebhookToken: "secretA", WebhookRatePerMinute: 100, WebhookSpawnPerHour: 2},
	}))

	for i := 0; i < 2; i++ {
		if code, b := postHook(t, ts.URL, "alerts", "secretA", matchBody); code != http.StatusOK {
			t.Fatalf("spawn %d should pass under spawn burst 2: code=%d body=%s", i, code, b)
		}
	}
	code, b := postHook(t, ts.URL, "alerts", "secretA", matchBody)
	if code != http.StatusTooManyRequests {
		t.Fatalf("3rd spawn should be 429, got %d body=%s", code, b)
	}
	logs := buf.String()
	if !strings.Contains(logs, "spawn cap (per-token)") {
		t.Errorf("expected per-token spawn log reason; logs:\n%s", logs)
	}
	if strings.Contains(logs, "rate limit (per-token)") {
		t.Errorf("rate guard should not have tripped (cap 100); logs:\n%s", logs)
	}
}

// TestWebhookPerTokenIsolation: exhausting one token's bucket does not affect a
// different token (different room) — proving the per-token (hashed) keying isolates.
func TestWebhookPerTokenIsolation(t *testing.T) {
	ts, _ := webhookServer(t, webhookCfg(map[string]config.RoomConfig{
		"alerts": {Webhook: true, WebhookToken: "secretA", WebhookRatePerMinute: 2},
		"ops":    {Webhook: true, WebhookToken: "secretB", WebhookRatePerMinute: 2},
	}))

	// Exhaust token A.
	postHook(t, ts.URL, "alerts", "secretA", plainBody)
	postHook(t, ts.URL, "alerts", "secretA", plainBody)
	if code, _ := postHook(t, ts.URL, "alerts", "secretA", plainBody); code != http.StatusTooManyRequests {
		t.Fatalf("token A should be rate-limited, got %d", code)
	}
	// Token B is unaffected.
	if code, b := postHook(t, ts.URL, "ops", "secretB", plainBody); code != http.StatusOK {
		t.Fatalf("token B should be unaffected, got %d body=%s", code, b)
	}
}

// TestWebhookPreAuthCannotLockOutLegit is THE availability invariant: with the
// pre-auth ceiling saturated by a bad-token flood, a VALID token still passes — the
// pre-auth bucket is consumed only on rejection, never on success.
func TestWebhookPreAuthCannotLockOutLegit(t *testing.T) {
	cfg := webhookCfg(map[string]config.RoomConfig{
		"alerts": {Webhook: true, WebhookToken: "secretA"},
	})
	cfg.Ingest.Webhook.UnauthRatePerMinute = 2 // tiny ceiling so we can saturate cheaply
	ts, buf := webhookServer(t, cfg)

	// Bad tokens: first 2 → 401, then the ceiling sheds → 429.
	if code, _ := postHook(t, ts.URL, "alerts", "wrong", plainBody); code != http.StatusUnauthorized {
		t.Fatalf("1st bad token should be 401, got %d", code)
	}
	if code, _ := postHook(t, ts.URL, "alerts", "wrong", plainBody); code != http.StatusUnauthorized {
		t.Fatalf("2nd bad token should be 401, got %d", code)
	}
	if code, _ := postHook(t, ts.URL, "alerts", "wrong", plainBody); code != http.StatusTooManyRequests {
		t.Fatalf("3rd bad token should be 429 (pre-auth ceiling), got %d", code)
	}
	if !strings.Contains(buf.String(), "flood (pre-auth)") {
		t.Errorf("expected pre-auth flood log reason; logs:\n%s", buf.String())
	}

	// THE KEY PROPERTY: a valid token still passes despite the saturated pre-auth bucket.
	if code, b := postHook(t, ts.URL, "alerts", "secretA", plainBody); code != http.StatusOK {
		t.Fatalf("valid token must still pass when pre-auth is saturated, got %d body=%s", code, b)
	}
}

// TestWebhookSuccessNeverConsumesPreAuth: with the pre-auth ceiling set to 1, many
// successful authenticated POSTs still pass — the success path never touches the
// global bucket.
func TestWebhookSuccessNeverConsumesPreAuth(t *testing.T) {
	cfg := webhookCfg(map[string]config.RoomConfig{
		"alerts": {Webhook: true, WebhookToken: "secretA"},
	})
	cfg.Ingest.Webhook.UnauthRatePerMinute = 1 // would 429 on the 2nd rejection
	ts, _ := webhookServer(t, cfg)

	for i := 0; i < 10; i++ {
		if code, b := postHook(t, ts.URL, "alerts", "secretA", plainBody); code != http.StatusOK {
			t.Fatalf("success #%d must not be throttled by pre-auth (ceiling=1): code=%d body=%s", i, code, b)
		}
	}
}

// TestWebhookAuthBehavior: the constant-time compare still authenticates correctly —
// right token passes, wrong/empty token 401s, a webhook room with no token rejects
// all, and a non-webhook room is 404.
func TestWebhookAuthBehavior(t *testing.T) {
	ts, _ := webhookServer(t, webhookCfg(map[string]config.RoomConfig{
		"alerts": {Webhook: true, WebhookToken: "secretA"},
		"silent": {Webhook: true}, // webhook on, no token → rejects all
	}))

	if code, _ := postHook(t, ts.URL, "alerts", "secretA", plainBody); code != http.StatusOK {
		t.Errorf("correct token should pass, got %d", code)
	}
	if code, _ := postHook(t, ts.URL, "alerts", "nope", plainBody); code != http.StatusUnauthorized {
		t.Errorf("wrong token should be 401, got %d", code)
	}
	if code, _ := postHook(t, ts.URL, "alerts", "", plainBody); code != http.StatusUnauthorized {
		t.Errorf("empty token should be 401, got %d", code)
	}
	if code, _ := postHook(t, ts.URL, "silent", "", plainBody); code != http.StatusUnauthorized {
		t.Errorf("no-token room should reject, got %d", code)
	}
	if code, _ := postHook(t, ts.URL, "general", "secretA", plainBody); code != http.StatusNotFound {
		t.Errorf("non-webhook room should be 404, got %d", code)
	}
}

// TestVersionCarriesSourceOffer: /version keeps every field it has always served
// (the Docker CI smoke test curls it) and additionally carries the AGPL-3.0 §13
// source offer, so a user can find the code the relay is actually running.
func TestVersionCarriesSourceOffer(t *testing.T) {
	ts, _ := webhookServer(t, config.Default())

	resp, err := http.Get(ts.URL + "/version")
	if err != nil {
		t.Fatalf("get /version: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/version should be 200, got %d", resp.StatusCode)
	}
	var got struct {
		Version  string `json:"version"`
		Protocol int    `json:"protocol"`
		Product  string `json:"product"`
		Source   string `json:"source"`
		License  string `json:"license"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode /version: %v", err)
	}

	// Pre-existing fields — removing or renaming any of these breaks the smoke test.
	if got.Version != buildinfo.Version {
		t.Errorf("version = %q, want %q", got.Version, buildinfo.Version)
	}
	if got.Protocol != protocol.Version {
		t.Errorf("protocol = %d, want %d", got.Protocol, protocol.Version)
	}
	if got.Product != "netherchat" {
		t.Errorf("product = %q, want %q", got.Product, "netherchat")
	}
	// The §13 addition.
	if got.Source != buildinfo.SourceURL {
		t.Errorf("source = %q, want %q", got.Source, buildinfo.SourceURL)
	}
	if got.License != buildinfo.License {
		t.Errorf("license = %q, want %q", got.License, buildinfo.License)
	}
}

// TestSourceRedirects: GET /source is the AGPL-3.0 §13 source offer — a 302 to
// buildinfo.SourceURL, which an operator of a modified relay overrides at link
// time. The client must not follow the redirect: the target is off-host and this
// test makes no outbound request.
func TestSourceRedirects(t *testing.T) {
	ts, _ := webhookServer(t, config.Default())

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Get(ts.URL + "/source")
	if err != nil {
		t.Fatalf("get /source: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Errorf("/source should be %d, got %d", http.StatusFound, resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != buildinfo.SourceURL {
		t.Errorf("Location = %q, want %q", loc, buildinfo.SourceURL)
	}
}
