package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/salehkreiner/netherchat/connector"
)

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

func sign(key, body []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return "HMAC " + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func newBot(relayURL string, key []byte) *bot {
	return &bot{
		client:     &connector.Client{Server: relayURL, Token: "nc1-token"},
		hmacKey:    key,
		source:     "teams-bot",
		defaultTTL: "2h",
	}
}

func post(t *testing.T, b *bot, body []byte, auth string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	b.handle(rec, req)
	return rec
}

func TestValidHMACOpensRoom(t *testing.T) {
	relayURL, relayBody := captureRelay(t)
	key := []byte("teams-shared-secret")
	b := newBot(relayURL, key)

	body := []byte(`{"text":"@netherchat sev1 database is down","id":"msg-1"}`)
	rec := post(t, b, body, sign(key, body))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	reply := rec.Body.String()
	if !strings.Contains(reply, "inc-xyz") || !strings.Contains(reply, "token=A") {
		t.Errorf("reply missing room or join link:\n%s", reply)
	}
	// The relay received a critical alert (sev1).
	if !bytes.Contains(*relayBody, []byte(`"severity":"critical"`)) {
		t.Errorf("relay did not get severity critical: %s", *relayBody)
	}
}

func TestInvalidHMACRejected(t *testing.T) {
	relayURL, relayBody := captureRelay(t)
	b := newBot(relayURL, []byte("the-real-secret"))

	body := []byte(`{"text":"@netherchat sev1 break in","id":"m"}`)
	// Signed with the WRONG key.
	rec := post(t, b, body, sign([]byte("attacker-secret"), body))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if len(*relayBody) != 0 {
		t.Fatal("a room must NOT be opened for an invalid signature")
	}
	// Missing header → also 401.
	if rec2 := post(t, b, body, ""); rec2.Code != http.StatusUnauthorized {
		t.Errorf("missing auth status = %d, want 401", rec2.Code)
	}
}

func TestParseCommand(t *testing.T) {
	cases := []struct {
		in       string
		severity string
		summary  string
		ok       bool
	}{
		{"@netherchat sev1 database down", "critical", "database down", true},
		{"@netherchat sev2 latency spike", "high", "latency spike", true},
		{"@netherchat sev3 disk warning", "medium", "disk warning", true},
		{"@netherchat incident pager storm", "high", "pager storm", true},
		{"@netherchat drill quarterly test", "low", "quarterly test", true},
		{"<at>netherchat</at> sev1 with mention tag", "critical", "with mention tag", true},
		{"@netherchat hello there", "", "", false},
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
	key := []byte("k")
	b := newBot(relayURL, key)
	long := strings.Repeat("x", 400)
	body := []byte(`{"text":"@netherchat sev2 ` + long + `","id":"m"}`)
	if rec := post(t, b, body, sign(key, body)); rec.Code != http.StatusOK {
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
// fields, and the Teams thread/sender/channel data must never be forwarded.
func TestBoundaryLaw(t *testing.T) {
	relayURL, relayBody := captureRelay(t)
	key := []byte("k")
	b := newBot(relayURL, key)
	// A rich Teams payload with sender + channel data that must NOT cross.
	body := []byte(`{"text":"@netherchat sev1 prod outage","id":"msg-99","from":{"name":"ALICE_SENDER"},"channelData":{"channel":{"name":"SECRET_CHANNEL"}},"conversation":{"id":"THREAD_ID"}}`)
	if rec := post(t, b, body, sign(key, body)); rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	extra, err := connector.UnexpectedFields(*relayBody)
	if err != nil {
		t.Fatalf("decode forwarded body: %v", err)
	}
	if len(extra) != 0 {
		t.Fatalf("boundary violated: unexpected fields %v in %s", extra, *relayBody)
	}
	for _, leak := range []string{"ALICE_SENDER", "SECRET_CHANNEL", "THREAD_ID", "from", "channelData", "conversation"} {
		if bytes.Contains(*relayBody, []byte(leak)) {
			t.Fatalf("boundary violated: %q forwarded to the relay: %s", leak, *relayBody)
		}
	}
}
