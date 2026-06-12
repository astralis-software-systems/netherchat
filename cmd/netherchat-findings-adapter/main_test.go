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

func sampleFinding() finding {
	return finding{
		FindingID:   "f-001",
		Severity:    "High",
		CheckID:     "CIS-1.20",
		Resource:    "arn:aws:s3:::public-bucket",
		Region:      "us-east-1",
		Title:       "S3 bucket allows public read",
		Description: "SENTINEL_DESCRIPTION_MUST_NOT_CROSS",
		Remediation: "SENTINEL_REMEDIATION_MUST_NOT_CROSS",
		TS:          "2026-06-12T10:00:00Z",
	}
}

func TestTranslateSchema(t *testing.T) {
	a, err := translate(sampleFinding(), "my-scanner")
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if a.Source != "my-scanner" || a.Severity != "high" || a.Kind != "security-finding" {
		t.Fatalf("schema mismatch: %+v", a)
	}
	if a.Summary != "CIS-1.20: S3 bucket allows public read (arn:aws:s3:::public-bucket)" {
		t.Fatalf("summary = %q", a.Summary)
	}
	if a.Ref != "f-001" {
		t.Errorf("ref = %q, want f-001", a.Ref)
	}
	if a.TS == 0 {
		t.Error("ts should be parsed from RFC3339")
	}
}

// TestBoundaryLaw is mandatory: no field from the input beyond the seven allowed
// alert fields may appear in the POSTed body, and the never-forwarded
// description/remediation must be absent entirely.
func TestBoundaryLaw(t *testing.T) {
	var captured []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = io.ReadAll(r.Body)
		_, _ = io.WriteString(w, `{"accepted":true,"spawned":false}`)
	}))
	defer srv.Close()

	c := &connector.Client{Server: srv.URL, Token: "t"}
	a, err := translate(sampleFinding(), "my-scanner")
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
		t.Fatalf("boundary violated: unexpected fields %v in body %s", extra, captured)
	}
	for _, sentinel := range []string{"SENTINEL_DESCRIPTION", "SENTINEL_REMEDIATION", "description", "remediation", "region"} {
		if bytes.Contains(captured, []byte(sentinel)) {
			t.Fatalf("boundary violated: %q present in posted body %s", sentinel, captured)
		}
	}
}

func TestSummaryTruncation(t *testing.T) {
	f := sampleFinding()
	f.Title = strings.Repeat("A", 300)
	a, err := translate(f, "s")
	if err != nil {
		t.Fatal(err)
	}
	if len([]rune(a.Summary)) != connector.SummaryMax {
		t.Fatalf("summary length = %d, want %d", len([]rune(a.Summary)), connector.SummaryMax)
	}
	if !strings.HasSuffix(a.Summary, "...") {
		t.Errorf("truncated summary must end with ellipsis: %q", a.Summary[len(a.Summary)-5:])
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
	f := sampleFinding()
	f.Severity = "low"
	raw, _ := json.Marshal(f)
	if err := processOne(c, raw, "s", "high"); err != nil {
		t.Fatalf("processOne: %v", err)
	}
	if posted {
		t.Fatal("a finding below min severity must not be POSTed")
	}
}

func TestMalformedInputSendsNothing(t *testing.T) {
	posted := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posted = true
	}))
	defer srv.Close()

	c := &connector.Client{Server: srv.URL, Token: "t"}
	// Unknown field → strict decode rejects it; nothing is sent.
	if err := processOne(c, []byte(`{"finding_id":"x","severity":"high","bogus":1}`), "s", ""); err == nil {
		t.Fatal("malformed finding should error")
	}
	if posted {
		t.Fatal("malformed input must not POST anything")
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
	a, _ := translate(sampleFinding(), "s")
	if _, err := c.Send(context.Background(), a); err != nil {
		t.Fatalf("send: %v", err)
	}
	var got connector.Alert
	if err := json.Unmarshal(captured, &got); err != nil {
		t.Fatal(err)
	}
	if got.Signature != connector.Sign("s3cr3t", a) {
		t.Errorf("HMAC signature mismatch: %q", got.Signature)
	}
}
