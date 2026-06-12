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

func TestTranslatePagerDuty(t *testing.T) {
	raw := `{"event":{"event_type":"incident.triggered","data":{"id":"PABC123","title":"API latency critical","urgency":"high","html_url":"https://acme.pagerduty.com/incidents/PABC123"}}}`
	a, forward, err := translatePagerDuty([]byte(raw), "paging-pd")
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if !forward {
		t.Fatal("incident.triggered should be forwarded")
	}
	if a.Source != "paging-pd" || a.Kind != "page" || a.Severity != "critical" {
		t.Fatalf("schema mismatch: %+v", a)
	}
	if a.Summary != "API latency critical" || a.Ref != "PABC123" {
		t.Fatalf("summary/ref = %q / %q", a.Summary, a.Ref)
	}
}

func TestPagerDutyOnlyTriggered(t *testing.T) {
	for _, et := range []string{"incident.acknowledged", "incident.resolved", "incident.escalated"} {
		raw := `{"event":{"event_type":"` + et + `","data":{"id":"P1","title":"x","urgency":"high"}}}`
		_, forward, err := translatePagerDuty([]byte(raw), "s")
		if err != nil {
			t.Fatalf("%s: %v", et, err)
		}
		if forward {
			t.Errorf("%s must NOT be forwarded", et)
		}
	}
}

func TestTranslateOpsgenie(t *testing.T) {
	raw := `{"action":"Create","alert":{"alertId":"og-9","message":"Disk full on db-1","priority":"P2","source":"prometheus"}}`
	a, forward, err := translateOpsgenie([]byte(raw), "paging-opsgenie")
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if !forward {
		t.Fatal("Create should be forwarded")
	}
	if a.Kind != "page" || a.Severity != "high" || a.Summary != "Disk full on db-1" || a.Ref != "og-9" {
		t.Fatalf("schema mismatch: %+v", a)
	}
}

func TestOpsgenieOnlyCreate(t *testing.T) {
	for _, action := range []string{"Acknowledge", "Close", "AddNote"} {
		raw := `{"action":"` + action + `","alert":{"alertId":"og-1","message":"m","priority":"P1"}}`
		_, forward, err := translateOpsgenie([]byte(raw), "s")
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		if forward {
			t.Errorf("%s must NOT be forwarded", action)
		}
	}
}

func TestSeverityMaps(t *testing.T) {
	pd := map[string]string{"high": "critical", "low": "medium", "weird": "medium"}
	for in, want := range pd {
		if got := mapPDUrgency(in); got != want {
			t.Errorf("pd urgency %q → %q, want %q", in, got, want)
		}
	}
	og := map[string]string{"P1": "critical", "P2": "high", "P3": "medium", "P4": "low", "P5": "low", "P9": "medium"}
	for in, want := range og {
		if got := mapOGPriority(in); got != want {
			t.Errorf("opsgenie %q → %q, want %q", in, got, want)
		}
	}
}

// runHandle drives the handler against a capture relay.
func runHandle(t *testing.T, pager, minSev, payload string) (forwarded []byte, status int) {
	t.Helper()
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded, _ = io.ReadAll(r.Body)
		_, _ = io.WriteString(w, `{"accepted":true,"spawned":true,"room":"inc-x"}`)
	}))
	defer relay.Close()
	ad := &adapter{client: &connector.Client{Server: relay.URL, Token: "t"}, pager: pager, source: "paging-" + pager, minSeverity: minSev}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(payload))
	rec := httptest.NewRecorder()
	ad.handle(rec, req)
	return forwarded, rec.Code
}

// TestBoundaryLawPagerDuty is mandatory: html_url, custom_details, and any field
// beyond the seven allowed alert fields must never reach the forwarded body.
func TestBoundaryLawPagerDuty(t *testing.T) {
	payload := `{"event":{"event_type":"incident.triggered","data":{"id":"P1","title":"outage","urgency":"high","html_url":"https://SECRET_URL","custom_details":{"runbook":"SECRET_RUNBOOK"}}}}`
	body, code := runHandle(t, "pd", "", payload)
	if code != http.StatusOK || body == nil {
		t.Fatalf("expected forward, code=%d body=%s", code, body)
	}
	assertBoundary(t, body, "SECRET_URL", "SECRET_RUNBOOK", "html_url", "custom_details", "urgency", "event")
}

func TestBoundaryLawOpsgenie(t *testing.T) {
	payload := `{"action":"Create","alert":{"alertId":"og-1","message":"outage","priority":"P1","source":"SECRET_SOURCE","details":{"k":"SECRET_DETAIL"},"description":"SECRET_DESC"}}`
	body, code := runHandle(t, "opsgenie", "", payload)
	if code != http.StatusOK || body == nil {
		t.Fatalf("expected forward, code=%d body=%s", code, body)
	}
	assertBoundary(t, body, "SECRET_SOURCE", "SECRET_DETAIL", "SECRET_DESC", "priority", "details", "description", "alert")
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

func TestNonOpeningEventNotForwarded(t *testing.T) {
	body, code := runHandle(t, "pd", "", `{"event":{"event_type":"incident.resolved","data":{"id":"P1","title":"x","urgency":"high"}}}`)
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if body != nil {
		t.Fatalf("a non-opening event must not be forwarded, got %s", body)
	}
}

func TestMinSeverityFilters(t *testing.T) {
	// P4 → low; min high → nothing forwarded.
	body, code := runHandle(t, "opsgenie", "high", `{"action":"Create","alert":{"alertId":"og-1","message":"minor","priority":"P4"}}`)
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if body != nil {
		t.Fatalf("below-min page must not be forwarded, got %s", body)
	}
}

func TestMalformedWebhook(t *testing.T) {
	body, code := runHandle(t, "pd", "", `{"event":`)
	if code != http.StatusBadRequest {
		t.Errorf("malformed webhook code = %d, want 400", code)
	}
	if body != nil {
		t.Error("malformed webhook must not forward anything")
	}
}
