package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/salehkreiner/netherchat/connector"
)

func sampleEvent() egressEvent {
	return egressEvent{
		EventID:    "e-001",
		Severity:   "Critical",
		EventType:  "credential_leak",
		Tool:       "ChatGPT",
		ScrubCount: 3,
		Categories: []string{"api_key", "email"},
		TS:         "2026-06-12T10:00:00Z",
	}
}

func TestTranslateSchema(t *testing.T) {
	a, err := translate(sampleEvent(), "ai-egress-monitor")
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if a.Source != "ai-egress-monitor" || a.Severity != "critical" || a.Kind != "egress-signal" {
		t.Fatalf("schema mismatch: %+v", a)
	}
	if a.Summary != "credential_leak detected in ChatGPT: 3 items (api_key, email)" {
		t.Fatalf("summary = %q", a.Summary)
	}
	if a.Ref != "e-001" || a.TS == 0 {
		t.Errorf("ref/ts wrong: ref=%q ts=%d", a.Ref, a.TS)
	}
}

// TestBoundaryLaw is mandatory: only the seven allowed alert fields may cross, and
// none of the signal's own field names leak as top-level keys (they are folded into
// summary/ref, which are metadata).
func TestBoundaryLaw(t *testing.T) {
	var captured []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = io.ReadAll(r.Body)
		_, _ = io.WriteString(w, `{"accepted":true,"spawned":false}`)
	}))
	defer srv.Close()

	c := &connector.Client{Server: srv.URL, Token: "t"}
	a, err := translate(sampleEvent(), "ai-egress-monitor")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Send(context.Background(), a); err != nil {
		t.Fatalf("send: %v", err)
	}

	extra, err := connector.UnexpectedFields(captured)
	if err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(extra) != 0 {
		t.Fatalf("boundary violated: unexpected fields %v in %s", extra, captured)
	}
	for _, key := range []string{`"event_type"`, `"event_id"`, `"tool"`, `"scrub_count"`, `"categories"`} {
		if bytes.Contains(captured, []byte(key)) {
			t.Fatalf("boundary violated: raw input key %s present in body %s", key, captured)
		}
	}
}

func TestSummaryTruncation(t *testing.T) {
	e := sampleEvent()
	e.Tool = strings.Repeat("T", 300)
	a, err := translate(e, "s")
	if err != nil {
		t.Fatal(err)
	}
	if len([]rune(a.Summary)) != connector.SummaryMax || !strings.HasSuffix(a.Summary, "...") {
		t.Fatalf("truncation wrong: len=%d suffix=%q", len([]rune(a.Summary)), a.Summary[len(a.Summary)-5:])
	}
}

func TestMinSeverityFilterSendsNothing(t *testing.T) {
	posted := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posted = true
		_, _ = io.WriteString(w, `{"accepted":true}`)
	}))
	defer srv.Close()

	c := &connector.Client{Server: srv.URL, Token: "t"}
	e := sampleEvent()
	e.Severity = "low"
	raw, _ := json.Marshal(e)
	if err := processOne(c, raw, "s", "high"); err != nil {
		t.Fatalf("processOne: %v", err)
	}
	if posted {
		t.Fatal("an event below min severity must not be POSTed")
	}
}

// TestRejectsSmuggledContent: a strict decode rejects any field not in the signal
// schema, so a stray "detected_value" (raw content) fails loudly and sends nothing.
func TestRejectsSmuggledContent(t *testing.T) {
	posted := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posted = true
	}))
	defer srv.Close()

	c := &connector.Client{Server: srv.URL, Token: "t"}
	smuggled := `{"event_id":"e","severity":"high","detected_value":"AKIA_SECRET_KEY"}`
	if err := processOne(c, []byte(smuggled), "s", ""); err == nil {
		t.Fatal("smuggled content field should be rejected")
	}
	if posted {
		t.Fatal("nothing should be POSTed when input is rejected")
	}
}

func TestHMACAuth(t *testing.T) {
	var captured []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = io.ReadAll(r.Body)
		_, _ = io.WriteString(w, `{"accepted":true}`)
	}))
	defer srv.Close()

	c := &connector.Client{Server: srv.URL, HMACSecret: "s3cr3t"}
	a, _ := translate(sampleEvent(), "s")
	if _, err := c.Send(context.Background(), a); err != nil {
		t.Fatalf("send: %v", err)
	}
	var got connector.Alert
	if err := json.Unmarshal(captured, &got); err != nil {
		t.Fatal(err)
	}
	if got.Signature != connector.Sign("s3cr3t", a) {
		t.Errorf("HMAC mismatch: %q", got.Signature)
	}
}
