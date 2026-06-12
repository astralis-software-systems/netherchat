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

func TestTranslateSplunk(t *testing.T) {
	raw := `{"search_name":"Brute Force Detected","severity":"high","result":{"host":"web-01","_time":"1700000000.500","_raw":"raw log line"}}`
	a, err := translateSplunk([]byte(raw), "siem-splunk")
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if a.Source != "siem-splunk" || a.Severity != "high" || a.Kind != "siem-alert" {
		t.Fatalf("schema mismatch: %+v", a)
	}
	if a.Summary != "Brute Force Detected triggered on web-01" {
		t.Fatalf("summary = %q", a.Summary)
	}
	if a.Ref != "Brute Force Detected_1700000000.500" {
		t.Fatalf("ref = %q", a.Ref)
	}
	if a.TS != 1700000000 {
		t.Errorf("ts = %d, want 1700000000", a.TS)
	}
}

func TestTranslateSentinel(t *testing.T) {
	raw := `{"alertRule":"Suspicious sign-in","severity":"Sev1","firedDateTime":"2026-06-12T10:00:00Z","alertContext":{"ip":"1.2.3.4"}}`
	a, err := translateSentinel([]byte(raw), "siem-sentinel")
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if a.Source != "siem-sentinel" || a.Severity != "high" || a.Kind != "siem-alert" {
		t.Fatalf("schema mismatch: %+v", a)
	}
	if a.Summary != "Suspicious sign-in triggered" {
		t.Fatalf("summary = %q", a.Summary)
	}
	if a.Ref != "Suspicious sign-in_2026-06-12T10:00:00Z" || a.TS == 0 {
		t.Errorf("ref/ts wrong: ref=%q ts=%d", a.Ref, a.TS)
	}
}

func TestSeverityMaps(t *testing.T) {
	splunk := map[string]string{"critical": "critical", "fatal": "critical", "error": "high", "high": "high", "warning": "medium", "5": "critical", "1": "info", "weird": "medium"}
	for in, want := range splunk {
		if got := mapSplunkSeverity(in); got != want {
			t.Errorf("splunk %q → %q, want %q", in, got, want)
		}
	}
	sentinel := map[string]string{"Sev0": "critical", "Sev1": "high", "Sev2": "medium", "Sev3": "low", "Sev4": "info", "High": "high", "weird": "medium"}
	for in, want := range sentinel {
		if got := mapSentinelSeverity(in); got != want {
			t.Errorf("sentinel %q → %q, want %q", in, got, want)
		}
	}
}

// runHandle drives the adapter's HTTP handler against a capture "relay", returning
// the forwarded body (nil if nothing was forwarded) and the handler status.
func runHandle(t *testing.T, siem, minSev, payload string) (forwarded []byte, status int) {
	t.Helper()
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded, _ = io.ReadAll(r.Body)
		_, _ = io.WriteString(w, `{"accepted":true,"spawned":true,"room":"inc-x"}`)
	}))
	defer relay.Close()
	ad := &adapter{client: &connector.Client{Server: relay.URL, Token: "t"}, siem: siem, source: "siem-" + siem, minSeverity: minSev}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(payload))
	rec := httptest.NewRecorder()
	ad.handle(rec, req)
	return forwarded, rec.Code
}

// TestBoundaryLawSplunk is mandatory: raw log content and any field beyond the seven
// allowed alert fields must never reach the forwarded body.
func TestBoundaryLawSplunk(t *testing.T) {
	payload := `{"search_name":"BF","severity":"high","result":{"host":"h1","_time":"1700000000","_raw":"SENTINEL_RAWLOG","user":"admin","password":"SENTINEL_SECRET"}}`
	body, code := runHandle(t, "splunk", "", payload)
	if code != http.StatusOK || body == nil {
		t.Fatalf("expected forward, code=%d body=%s", code, body)
	}
	assertBoundary(t, body, "SENTINEL_RAWLOG", "SENTINEL_SECRET", `"result"`, `"_raw"`, `"host"`, `"search_name"`)
}

// TestBoundaryLawSentinel is mandatory: alertContext must never reach the body.
func TestBoundaryLawSentinel(t *testing.T) {
	payload := `{"alertRule":"R","severity":"Sev1","firedDateTime":"2026-06-12T10:00:00Z","alertContext":{"secret":"SENTINEL_CONTEXT","raw":"SENTINEL_LOG"}}`
	body, code := runHandle(t, "sentinel", "", payload)
	if code != http.StatusOK || body == nil {
		t.Fatalf("expected forward, code=%d body=%s", code, body)
	}
	assertBoundary(t, body, "SENTINEL_CONTEXT", "SENTINEL_LOG", `"alertContext"`, `"firedDateTime"`, `"alertRule"`)
}

func assertBoundary(t *testing.T, body []byte, forbidden ...string) {
	t.Helper()
	extra, err := connector.UnexpectedFields(body)
	if err != nil {
		t.Fatalf("decode forwarded body: %v", err)
	}
	if len(extra) != 0 {
		t.Fatalf("boundary violated: unexpected fields %v in %s", extra, body)
	}
	for _, f := range forbidden {
		if bytes.Contains(body, []byte(f)) {
			t.Fatalf("boundary violated: %q present in forwarded body %s", f, body)
		}
	}
}

func TestMinSeverityForwardsNothing(t *testing.T) {
	// Sev3 → low; min medium → must not forward.
	payload := `{"alertRule":"noise","severity":"Sev3","firedDateTime":"2026-06-12T10:00:00Z"}`
	body, code := runHandle(t, "sentinel", "medium", payload)
	if code != http.StatusOK {
		t.Fatalf("code = %d", code)
	}
	if body != nil {
		t.Fatalf("below-min alert must not be forwarded, got %s", body)
	}
}

func TestMalformedWebhook(t *testing.T) {
	body, code := runHandle(t, "splunk", "", `{"search_name":`)
	if code != http.StatusBadRequest {
		t.Errorf("malformed webhook code = %d, want 400", code)
	}
	if body != nil {
		t.Error("malformed webhook must not forward anything")
	}
}
