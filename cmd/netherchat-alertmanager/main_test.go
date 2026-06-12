package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/salehkreiner/netherchat/connector"
)

func TestTranslateAlert(t *testing.T) {
	al := amAlert{
		Status:      "firing",
		Labels:      map[string]string{"alertname": "HighCPU", "severity": "warning", "instance": "web-01:9100", "job": "node"},
		Annotations: map[string]string{"summary": "CPU above 90%", "description": "long detail NOT forwarded"},
		StartsAt:    "2026-06-12T10:00:00Z",
	}
	a, ok := translateAlert(al, "alertmanager")
	if !ok {
		t.Fatal("translate returned not-ok for a valid alert")
	}
	if a.Source != "alertmanager" || a.Kind != "infra-alert" || a.Severity != "high" {
		t.Fatalf("schema mismatch: %+v", a)
	}
	if a.Summary != "HighCPU on web-01:9100: CPU above 90%" {
		t.Fatalf("summary = %q", a.Summary)
	}
	if a.Ref != "HighCPU_2026-06-12T10:00:00Z" || a.TS == 0 {
		t.Errorf("ref/ts wrong: ref=%q ts=%d", a.Ref, a.TS)
	}
}

func TestMapSeverity(t *testing.T) {
	cases := map[string]string{
		"critical": "critical", "crit": "critical", "page": "critical",
		"warning": "high", "warn": "high", "high": "high",
		"info": "low", "none": "low", "medium": "medium", "low": "low",
		"weird": "medium",
	}
	for in, want := range cases {
		if got := mapSeverity(in); got != want {
			t.Errorf("mapSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

// runHandle drives the handler against a capture relay, returning every forwarded
// body, the response status, and the decoded {forwarded,skipped} counts.
func runHandle(t *testing.T, minSev, payload string) (forwarded [][]byte, status int, counts map[string]int) {
	t.Helper()
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		forwarded = append(forwarded, b)
		_, _ = io.WriteString(w, `{"accepted":true,"spawned":true,"room":"inc-x"}`)
	}))
	defer relay.Close()
	ad := &adapter{client: &connector.Client{Server: relay.URL, Token: "t"}, source: "alertmanager", minSeverity: minSev}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(payload))
	rec := httptest.NewRecorder()
	ad.handle(rec, req)
	if rec.Code == http.StatusOK {
		counts = map[string]int{}
		_ = json.Unmarshal(rec.Body.Bytes(), &counts)
	}
	return forwarded, rec.Code, counts
}

func TestFiringForwardedResolvedNot(t *testing.T) {
	payload := `{"alerts":[
		{"status":"firing","labels":{"alertname":"A","severity":"critical","instance":"h1"},"annotations":{"summary":"down"},"startsAt":"2026-06-12T10:00:00Z"},
		{"status":"resolved","labels":{"alertname":"A","severity":"critical","instance":"h1"},"annotations":{"summary":"ok"},"startsAt":"2026-06-12T10:05:00Z"}
	]}`
	fwd, code, counts := runHandle(t, "", payload)
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if len(fwd) != 1 {
		t.Fatalf("expected exactly 1 forwarded (firing only), got %d", len(fwd))
	}
	if counts["forwarded"] != 1 || counts["skipped"] != 1 {
		t.Errorf("counts = %v, want forwarded=1 skipped=1", counts)
	}
}

// TestBoundaryLaw is mandatory: the description annotation and any extra label must
// never reach the forwarded body.
func TestBoundaryLaw(t *testing.T) {
	payload := `{"alerts":[{"status":"firing","labels":{"alertname":"A","severity":"critical","instance":"h1","secret_label":"SENTINEL_LABEL"},"annotations":{"summary":"db down","description":"SENTINEL_DESCRIPTION with secrets"},"startsAt":"2026-06-12T10:00:00Z"}]}`
	fwd, code, _ := runHandle(t, "", payload)
	if code != http.StatusOK || len(fwd) != 1 {
		t.Fatalf("expected forward, code=%d n=%d", code, len(fwd))
	}
	body := fwd[0]
	extra, err := connector.UnexpectedFields(body)
	if err != nil {
		t.Fatalf("decode forwarded body: %v", err)
	}
	if len(extra) != 0 {
		t.Fatalf("boundary violated: unexpected fields %v in %s", extra, body)
	}
	for _, leak := range []string{"SENTINEL_DESCRIPTION", "SENTINEL_LABEL", "description", "secret_label", "annotations", "labels"} {
		if bytes.Contains(body, []byte(leak)) {
			t.Fatalf("boundary violated: %q present in forwarded body %s", leak, body)
		}
	}
}

func TestMinSeverityFilters(t *testing.T) {
	// info → low; min medium → nothing forwarded.
	payload := `{"alerts":[{"status":"firing","labels":{"alertname":"Noise","severity":"info"},"annotations":{"summary":"fyi"},"startsAt":"2026-06-12T10:00:00Z"}]}`
	fwd, code, counts := runHandle(t, "medium", payload)
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if len(fwd) != 0 {
		t.Fatalf("below-min alert must not be forwarded, got %d", len(fwd))
	}
	if counts["skipped"] != 1 {
		t.Errorf("counts = %v, want skipped=1", counts)
	}
}

func TestMalformedWebhook(t *testing.T) {
	fwd, code, _ := runHandle(t, "", `{"alerts":`)
	if code != http.StatusBadRequest {
		t.Errorf("malformed webhook code = %d, want 400", code)
	}
	if len(fwd) != 0 {
		t.Error("malformed webhook must not forward anything")
	}
}
