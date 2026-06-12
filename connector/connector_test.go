package connector

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/salehkreiner/netherchat/protocol"
)

// captureServer returns an httptest server that records the last request body and
// token header, and replies with the given Result JSON.
func captureServer(t *testing.T, reply string) (*httptest.Server, *[]byte, *string) {
	t.Helper()
	var body []byte
	var token string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		token = r.Header.Get("X-Netherchat-Token")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, reply)
	}))
	t.Cleanup(srv.Close)
	return srv, &body, &token
}

func TestSendTokenAndBody(t *testing.T) {
	srv, body, token := captureServer(t, `{"accepted":true,"spawned":true,"room":"inc-abc","links":{"alice":"http://x/join?room=inc-abc&token=tok"}}`)
	c := &Client{Server: srv.URL, Token: "secret"}
	res, err := c.Send(context.Background(), Alert{Source: "s", Severity: "high", Kind: "k", Summary: "hi", Ref: "r1", TS: 123})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if !res.Spawned || res.Room != "inc-abc" || res.Links["alice"] == "" {
		t.Fatalf("result mismatch: %+v", res)
	}
	if *token != "secret" {
		t.Errorf("token header = %q, want secret", *token)
	}
	// The body must decode to exactly the alert we sent, with no signature (no HMAC).
	var got Alert
	if err := json.Unmarshal(*body, &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got.Source != "s" || got.Severity != "high" || got.Kind != "k" || got.Summary != "hi" || got.Ref != "r1" || got.TS != 123 {
		t.Fatalf("body alert mismatch: %+v", got)
	}
	if got.Signature != "" {
		t.Errorf("no HMAC configured, but signature present: %q", got.Signature)
	}
}

func TestSendHMAC(t *testing.T) {
	srv, body, _ := captureServer(t, `{"accepted":true,"spawned":false}`)
	c := &Client{Server: srv.URL, HMACSecret: "s3cr3t"}
	a := Alert{Source: "siem", Severity: "high", Kind: "siem-alert", Summary: "rule triggered", Ref: "r", TS: 99}
	if _, err := c.Send(context.Background(), a); err != nil {
		t.Fatalf("send: %v", err)
	}
	var got Alert
	if err := json.Unmarshal(*body, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	mac := hmac.New(sha256.New, []byte("s3cr3t"))
	mac.Write(protocol.AlertSigningBytes(a.Source, a.Severity, a.Kind, a.Summary, a.Ref, a.TS))
	want := hex.EncodeToString(mac.Sum(nil))
	if got.Signature != want {
		t.Fatalf("signature = %q, want %q", got.Signature, want)
	}
}

func TestSendRejectsNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()
	c := &Client{Server: srv.URL, Token: "x"}
	if _, err := c.Send(context.Background(), Alert{Source: "s", Severity: "high", Kind: "k"}); err == nil {
		t.Fatal("expected error on 401")
	}
}

func TestSendValidates(t *testing.T) {
	c := &Client{Server: "http://x"}
	if _, err := c.Send(context.Background(), Alert{Severity: "high", Kind: "k"}); err == nil {
		t.Error("missing source should error before any POST")
	}
	if _, err := (&Client{}).Send(context.Background(), Alert{Source: "s", Severity: "h", Kind: "k"}); err == nil {
		t.Error("missing server should error")
	}
}

func TestTruncate(t *testing.T) {
	if got := Truncate("hello", 200); got != "hello" {
		t.Errorf("short string changed: %q", got)
	}
	long := ""
	for i := 0; i < 250; i++ {
		long += "x"
	}
	got := Truncate(long, SummaryMax)
	if len([]rune(got)) != SummaryMax {
		t.Errorf("truncated length = %d, want %d", len([]rune(got)), SummaryMax)
	}
	if got[len(got)-3:] != "..." {
		t.Errorf("truncated string should end with ellipsis: %q", got[len(got)-5:])
	}
}

func TestSeverityFilter(t *testing.T) {
	if !MeetsMin("critical", "high") || !MeetsMin("high", "high") {
		t.Error("critical/high should meet min high")
	}
	if MeetsMin("medium", "high") || MeetsMin("low", "high") {
		t.Error("medium/low should NOT meet min high")
	}
	if !MeetsMin("anything", "") {
		t.Error("empty min disables filtering")
	}
	if !MeetsMin("weird-unknown", "high") {
		t.Error("unrecognized severity should fail-open (pass)")
	}
}

func TestUnexpectedFields(t *testing.T) {
	clean, _ := json.Marshal(Alert{Source: "s", Severity: "h", Kind: "k", Summary: "x"})
	extra, err := UnexpectedFields(clean)
	if err != nil || len(extra) != 0 {
		t.Fatalf("clean alert flagged fields %v (err %v)", extra, err)
	}
	dirty := []byte(`{"source":"s","severity":"h","kind":"k","description":"LEAK","raw":"LEAK"}`)
	extra, err = UnexpectedFields(dirty)
	if err != nil {
		t.Fatal(err)
	}
	if len(extra) != 2 {
		t.Fatalf("expected 2 unexpected fields, got %v", extra)
	}
}
