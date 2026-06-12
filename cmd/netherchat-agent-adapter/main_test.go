package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/salehkreiner/netherchat/connector"
)

func TestTranslateArtifactProduced(t *testing.T) {
	e := agentEvent{
		EventID: "evt-1", Severity: "high", Kind: "artifact_produced",
		Source: "requirements-agent", ArtifactRef: "Q3-plan",
		ArtifactHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Summary:      "draft requirements ready for review", TS: "2026-06-12T10:00:00Z",
	}
	a, err := translate(e, "requirements-agent")
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if a.Source != "requirements-agent" || a.Severity != "high" || a.Kind != "artifact_produced" {
		t.Fatalf("schema mismatch: %+v", a)
	}
	if a.Ref != "evt-1" || a.TS == 0 {
		t.Fatalf("ref/ts wrong: %+v", a)
	}
	// The artifact hash (first 8) is surfaced in the summary so reviewers can cross-check.
	if !strings.Contains(a.Summary, "[hash: 01234567]") {
		t.Fatalf("summary missing hash tag: %q", a.Summary)
	}
	if len([]rune(a.Summary)) > connector.SummaryMax {
		t.Fatalf("summary exceeds %d: %d", connector.SummaryMax, len([]rune(a.Summary)))
	}
}

func TestTranslateNoHash(t *testing.T) {
	a, err := translate(agentEvent{EventID: "e", Severity: "low", Kind: "anomaly_detected", Source: "s", Summary: "odd behavior"}, "s")
	if err != nil {
		t.Fatal(err)
	}
	if a.Summary != "odd behavior" {
		t.Fatalf("summary = %q", a.Summary)
	}
	if strings.Contains(a.Summary, "hash:") {
		t.Fatal("no hash tag should appear when no artifact_hash is present")
	}
}

func TestUnknownKindRejected(t *testing.T) {
	if _, err := translate(agentEvent{Severity: "high", Kind: "made_up", Source: "s"}, "s"); err == nil {
		t.Fatal("an unknown kind must be rejected")
	}
	if _, err := translate(agentEvent{Severity: "", Kind: "artifact_produced", Source: "s"}, "s"); err == nil {
		t.Fatal("a missing severity must be rejected")
	}
}

// captureRelay returns a stub NC-1 relay recording every forwarded body.
func captureRelay(t *testing.T) (url string, bodies *[][]byte) {
	t.Helper()
	var got [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, b)
		_, _ = io.WriteString(w, `{"accepted":true,"spawned":true,"room":"inc-x"}`)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &got
}

// TestBoundaryLaw is mandatory: only the seven allowed alert fields cross, and an
// input carrying a content-like field is rejected (the schema has no content field).
func TestBoundaryLaw(t *testing.T) {
	url, bodies := captureRelay(t)
	client := &connector.Client{Server: url, Token: "t"}

	raw := `{"event_id":"e1","severity":"critical","kind":"artifact_produced","source":"agent","artifact_ref":"plan","artifact_hash":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789","summary":"ready","ts":"2026-06-12T10:00:00Z"}`
	if err := processOne(client, []byte(raw), "agent", ""); err != nil {
		t.Fatalf("processOne: %v", err)
	}
	if len(*bodies) != 1 {
		t.Fatalf("expected one forwarded alert, got %d", len(*bodies))
	}
	body := (*bodies)[0]
	extra, err := connector.UnexpectedFields(body)
	if err != nil {
		t.Fatalf("decode forwarded body: %v", err)
	}
	if len(extra) != 0 {
		t.Fatalf("boundary violated: unexpected fields %v in %s", extra, body)
	}
	// The artifact hash (metadata) crosses; an artifact_ref/content does not leak as a field.
	if !bytes.Contains(body, []byte("abcdef01")) {
		t.Fatalf("the artifact hash should be present in the summary: %s", body)
	}
	for _, f := range []string{`"artifact_hash"`, `"artifact_ref"`, `"content"`, `"event_id"`} {
		if bytes.Contains(body, []byte(f)) {
			t.Fatalf("boundary violated: input field %q leaked into the alert body %s", f, body)
		}
	}

	// An input carrying a raw content field is rejected outright (nothing sent).
	before := len(*bodies)
	if err := processOne(client, []byte(`{"event_id":"e2","severity":"high","kind":"artifact_produced","source":"agent","content":"THE RAW ARTIFACT"}`), "agent", ""); err == nil {
		t.Fatal("an event with a content field must be rejected")
	}
	if len(*bodies) != before {
		t.Fatal("a rejected event must forward nothing")
	}
}

func TestMinSeverityFilters(t *testing.T) {
	url, bodies := captureRelay(t)
	client := &connector.Client{Server: url, Token: "t"}
	raw := `{"event_id":"e","severity":"low","kind":"sensitive_ingest","source":"agent","summary":"fyi"}`
	if err := processOne(client, []byte(raw), "agent", "high"); err != nil {
		t.Fatalf("processOne: %v", err)
	}
	if len(*bodies) != 0 {
		t.Fatalf("below-min event must not be forwarded, got %d", len(*bodies))
	}
}

func TestPipeSequence(t *testing.T) {
	url, bodies := captureRelay(t)
	client := &connector.Client{Server: url, Token: "t"}
	lines := []string{
		`{"event_id":"e1","severity":"high","kind":"artifact_produced","source":"agent","artifact_ref":"a","artifact_hash":"aa11","summary":"one"}`,
		`{"event_id":"e2","severity":"critical","kind":"anomaly_detected","source":"agent","summary":"two"}`,
		`{"event_id":"e3","severity":"medium","kind":"decision_proposed","source":"agent","summary":"three"}`,
	}
	for _, l := range lines {
		if err := processOne(client, []byte(l), "agent", ""); err != nil {
			t.Fatalf("processOne: %v", err)
		}
	}
	if len(*bodies) != 3 {
		t.Fatalf("expected 3 forwarded alerts in sequence, got %d", len(*bodies))
	}
}

func TestMalformedRejected(t *testing.T) {
	url, bodies := captureRelay(t)
	client := &connector.Client{Server: url, Token: "t"}
	if err := processOne(client, []byte(`{"event_id":`), "agent", ""); err == nil {
		t.Fatal("malformed JSON must be rejected")
	}
	if len(*bodies) != 0 {
		t.Fatal("malformed input must forward nothing")
	}
}
