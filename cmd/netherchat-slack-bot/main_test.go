package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/connector"
)

var fixedNow = time.Unix(1_700_000_000, 0)

// captureRelay returns a stub NC-1 relay that records the last alert body and
// replies with a spawned-room result.
func captureRelay(t *testing.T) (url string, body *[]byte) {
	t.Helper()
	var captured []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = io.ReadAll(r.Body)
		_, _ = io.WriteString(w, `{"accepted":true,"spawned":true,"room":"inc-xyz","links":{"bob":"https://relay/join?room=inc-xyz&token=B","alice":"https://relay/join?room=inc-xyz&token=A"}}`)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &captured
}

func newBot(relayURL string, secret []byte) *bot {
	return &bot{
		client:     &connector.Client{Server: relayURL, Token: "nc1-token"},
		signingKey: secret,
		source:     "slack-bot",
		defaultTTL: "2h",
		now:        func() time.Time { return fixedNow },
	}
}

// slackForm encodes a slash-command body the way Slack does (form-encoded).
func slackForm(text string, extra map[string]string) []byte {
	v := url.Values{}
	v.Set("command", "/netherchat")
	v.Set("text", text)
	v.Set("trigger_id", "13345224609.738474920.8088930838d88f008e0")
	for k, val := range extra {
		v.Set(k, val)
	}
	return []byte(v.Encode())
}

// signV0 produces a valid Slack v0 signature header for body at time fixedNow.
func signV0(secret, body []byte) (ts, sig string) {
	ts = strconv.FormatInt(fixedNow.Unix(), 10)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("v0:" + ts + ":"))
	mac.Write(body)
	return ts, "v0=" + hex.EncodeToString(mac.Sum(nil))
}

func post(t *testing.T, b *bot, body []byte, ts, sig string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if ts != "" {
		req.Header.Set("X-Slack-Request-Timestamp", ts)
	}
	if sig != "" {
		req.Header.Set("X-Slack-Signature", sig)
	}
	rec := httptest.NewRecorder()
	b.handle(rec, req)
	return rec
}

func TestValidSignatureOpensRoom(t *testing.T) {
	relayURL, relayBody := captureRelay(t)
	secret := []byte("slack-signing-secret")
	b := newBot(relayURL, secret)

	body := slackForm("sev1 database is down", nil)
	ts, sig := signV0(secret, body)
	rec := post(t, b, body, ts, sig)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200\n%s", rec.Code, rec.Body.String())
	}
	reply := rec.Body.String()
	if !strings.Contains(reply, "inc-xyz") || !strings.Contains(reply, "token=A") {
		t.Errorf("reply missing room or join link:\n%s", reply)
	}
	if !strings.Contains(reply, `"response_type": "ephemeral"`) {
		t.Errorf("slash-command reply must be ephemeral:\n%s", reply)
	}
	if !bytes.Contains(*relayBody, []byte(`"severity":"critical"`)) {
		t.Errorf("relay did not get severity critical: %s", *relayBody)
	}
}

func TestInvalidSignatureRejected(t *testing.T) {
	relayURL, relayBody := captureRelay(t)
	b := newBot(relayURL, []byte("the-real-secret"))

	body := slackForm("sev1 break in", nil)
	// Signed with the WRONG secret.
	ts, sig := signV0([]byte("attacker-secret"), body)
	rec := post(t, b, body, ts, sig)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if len(*relayBody) != 0 {
		t.Fatal("a room must NOT be opened for an invalid signature")
	}
	// Missing signature headers → also 401.
	if rec2 := post(t, b, body, "", ""); rec2.Code != http.StatusUnauthorized {
		t.Errorf("missing signature status = %d, want 401", rec2.Code)
	}
}

func TestStaleTimestampRejected(t *testing.T) {
	relayURL, relayBody := captureRelay(t)
	secret := []byte("s")
	b := newBot(relayURL, secret)
	body := slackForm("sev1 old replay", nil)

	// A correct signature, but over a timestamp from an hour ago → replay, reject.
	staleTS := strconv.FormatInt(fixedNow.Add(-time.Hour).Unix(), 10)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("v0:" + staleTS + ":"))
	mac.Write(body)
	sig := "v0=" + hex.EncodeToString(mac.Sum(nil))

	if rec := post(t, b, body, staleTS, sig); rec.Code != http.StatusUnauthorized {
		t.Fatalf("stale timestamp status = %d, want 401", rec.Code)
	}
	if len(*relayBody) != 0 {
		t.Fatal("a stale (replayed) request must not open a room")
	}
}

func TestParseCommand(t *testing.T) {
	cases := []struct {
		in       string
		severity string
		summary  string
		ok       bool
	}{
		{"sev1 database down", "critical", "database down", true},
		{"sev2 latency spike", "high", "latency spike", true},
		{"sev3 disk warning", "medium", "disk warning", true},
		{"incident pager storm", "high", "pager storm", true},
		{"drill quarterly test", "low", "quarterly test", true},
		{"hello there", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		sev, sum, ok := parseCommand(c.in)
		if ok != c.ok || sev != c.severity || (c.ok && sum != c.summary) {
			t.Errorf("parseCommand(%q) = (%q,%q,%v), want (%q,%q,%v)", c.in, sev, sum, ok, c.severity, c.summary, c.ok)
		}
	}
}

func TestSummaryTruncation(t *testing.T) {
	relayURL, relayBody := captureRelay(t)
	secret := []byte("k")
	b := newBot(relayURL, secret)
	long := strings.Repeat("x", 400)
	body := slackForm("sev2 "+long, nil)
	ts, sig := signV0(secret, body)
	if rec := post(t, b, body, ts, sig); rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var sent connector.Alert
	if err := json.Unmarshal(*relayBody, &sent); err != nil {
		t.Fatal(err)
	}
	if len([]rune(sent.Summary)) > connector.SummaryMax {
		t.Errorf("summary length %d exceeds %d", len([]rune(sent.Summary)), connector.SummaryMax)
	}
}

// TestBoundaryLaw is mandatory: the NC-1 body must contain only the seven allowed
// fields, and the Slack user/channel data must never be forwarded.
func TestBoundaryLaw(t *testing.T) {
	relayURL, relayBody := captureRelay(t)
	secret := []byte("k")
	b := newBot(relayURL, secret)
	body := slackForm("sev1 prod outage", map[string]string{
		"user_name":    "ALICE_SENDER",
		"user_id":      "U_SECRET",
		"channel_name": "SECRET_CHANNEL",
		"channel_id":   "C_SECRET",
		"team_domain":  "SECRET_TEAM",
		"response_url": "https://hooks.slack.com/SECRET_RESPONSE",
	})
	ts, sig := signV0(secret, body)
	if rec := post(t, b, body, ts, sig); rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	extra, err := connector.UnexpectedFields(*relayBody)
	if err != nil {
		t.Fatalf("decode forwarded body: %v", err)
	}
	if len(extra) != 0 {
		t.Fatalf("boundary violated: unexpected fields %v in %s", extra, *relayBody)
	}
	for _, leak := range []string{"ALICE_SENDER", "U_SECRET", "SECRET_CHANNEL", "C_SECRET", "SECRET_TEAM", "SECRET_RESPONSE", "user_name", "channel_name", "response_url"} {
		if bytes.Contains(*relayBody, []byte(leak)) {
			t.Fatalf("boundary violated: %q forwarded to the relay: %s", leak, *relayBody)
		}
	}
}
