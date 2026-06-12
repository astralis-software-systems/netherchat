package itsm

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// sampleRecord stands in for a marshaled sealed record. Its entry body is a sealed
// DECISION (allowed in the attachment, which is the authoritative artifact).
var sampleRecord = []byte(`{"netherchat_record":"v1","room":"ops","head_hash":"deadbeefdeadbeefdeadbeef","entries":[{"kind":"decision","body":"SEALED_DECISION_OK"}],"signatures":{"SHA256:abc":"sig"}}`)

// transcriptSentinel is room content that is NOT part of the sealed record. It must
// never appear in anything sent to the ITSM system.
const transcriptSentinel = "RAW_TRANSCRIPT_NEVER_SEALED"

type capturedReq struct {
	method  string
	path    string
	headers http.Header
	body    []byte
}

// captureServer records every request and returns statuses in order (repeating the
// last once exhausted, so captureServer(t,500) always 500s).
func captureServer(t *testing.T, statuses ...int) (*httptest.Server, *[]capturedReq) {
	t.Helper()
	var mu sync.Mutex
	var reqs []capturedReq
	i := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		reqs = append(reqs, capturedReq{method: r.Method, path: r.URL.Path, headers: r.Header.Clone(), body: b})
		s := http.StatusOK
		if len(statuses) > 0 {
			if i < len(statuses) {
				s = statuses[i]
			} else {
				s = statuses[len(statuses)-1]
			}
		}
		i++
		mu.Unlock()
		w.WriteHeader(s)
	}))
	t.Cleanup(srv.Close)
	return srv, &reqs
}

func testCfg(srv *httptest.Server) Config {
	return Config{
		URL: srv.URL, User: "admin", Token: "tok",
		HTTPClient: srv.Client(),
		Backoff:    []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond},
	}
}

func testProv() Provenance {
	return Provenance{Room: "ops", Fpr: "SHA256:abc", Sig: "YmFzZTY0c2ln", Ts: "2026-06-12T10:00:00Z"}
}

func parseMultipart(t *testing.T, r capturedReq) (fields map[string]string, file []byte, fileName string) {
	t.Helper()
	_, params, err := mime.ParseMediaType(r.headers.Get("Content-Type"))
	if err != nil {
		t.Fatalf("content-type: %v", err)
	}
	mr := multipart.NewReader(bytes.NewReader(r.body), params["boundary"])
	fields = map[string]string{}
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("multipart: %v", err)
		}
		data, _ := io.ReadAll(part)
		if part.FileName() != "" {
			file, fileName = data, part.FileName()
		} else {
			fields[part.FormName()] = string(data)
		}
	}
	return fields, file, fileName
}

func assertProvenance(t *testing.T, r capturedReq) {
	t.Helper()
	for _, h := range []string{"X-Netherchat-Room", "X-Netherchat-Fpr", "X-Netherchat-Sig", "X-Netherchat-Ts"} {
		if r.headers.Get(h) == "" {
			t.Errorf("missing provenance header %s", h)
		}
	}
	if r.headers.Get("Authorization") == "" {
		t.Error("missing Authorization (basic auth)")
	}
}

func TestServiceNowAttach(t *testing.T) {
	srv, reqs := captureServer(t, 200)
	c, _ := New("servicenow", testCfg(srv), testProv())
	if err := c.Attach("SYS123", sampleRecord, "rec.json"); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if len(*reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(*reqs))
	}
	r := (*reqs)[0]
	if r.method != http.MethodPost || r.path != "/api/now/table/sys_attachment" {
		t.Fatalf("wrong endpoint: %s %s", r.method, r.path)
	}
	assertProvenance(t, r)
	fields, file, name := parseMultipart(t, r)
	if fields["table_name"] != "incident" || fields["table_sys_id"] != "SYS123" || fields["file_name"] != "rec.json" || fields["content_type"] != "application/json" {
		t.Errorf("wrong form fields: %+v", fields)
	}
	if name != "rec.json" {
		t.Errorf("file name = %q", name)
	}
	if !bytes.Equal(file, sampleRecord) {
		t.Errorf("attached file is not the record verbatim:\n%s", file)
	}
}

func TestServiceNowComment(t *testing.T) {
	srv, reqs := captureServer(t, 200)
	c, _ := New("servicenow", testCfg(srv), testProv())
	if err := c.Comment("SYS123", "the summary"); err != nil {
		t.Fatalf("comment: %v", err)
	}
	r := (*reqs)[0]
	if r.method != http.MethodPatch || r.path != "/api/now/table/incident/SYS123" {
		t.Fatalf("wrong endpoint: %s %s", r.method, r.path)
	}
	assertProvenance(t, r)
	var body map[string]string
	if err := json.Unmarshal(r.body, &body); err != nil {
		t.Fatalf("body: %v", err)
	}
	if body["work_notes"] != "the summary" {
		t.Errorf("work_notes = %q", body["work_notes"])
	}
}

// TestServiceNowBoundary is mandatory: the attachment is the record verbatim and
// nothing else; no unsealed transcript crosses; the work note is metadata-only.
func TestServiceNowBoundary(t *testing.T) {
	srv, reqs := captureServer(t, 200, 200)
	c, _ := New("servicenow", testCfg(srv), testProv())
	res := AttachResult{TicketID: "SYS123", Filename: "rec.json", HeadHash: "deadbeefdeadbeef", Signers: 2, VerifyCmd: "netherchat verify rec.json"}
	if err := Deliver(c, res, sampleRecord, io.Discard); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if len(*reqs) != 2 {
		t.Fatalf("expected attach + comment, got %d requests", len(*reqs))
	}
	_, file, _ := parseMultipart(t, (*reqs)[0])
	if !bytes.Equal(file, sampleRecord) {
		t.Fatal("attachment is not the record verbatim")
	}
	if bytes.Contains((*reqs)[0].body, []byte(transcriptSentinel)) {
		t.Fatal("boundary violated: unsealed transcript present in the attachment request")
	}
	if bytes.Contains((*reqs)[1].body, []byte("SEALED_DECISION_OK")) {
		t.Fatal("boundary violated: the work note echoed decision text (must be metadata only)")
	}
}

func TestFormatSummary(t *testing.T) {
	s := FormatSummary(AttachResult{Signers: 3, HeadHash: "0123456789abcdefZZZZ", Elapsed: "18m4s", VerifyCmd: "netherchat verify rec.json"})
	for _, want := range []string{
		"Incident record sealed by 3 member(s).",
		"Head hash: 0123456789abcdef...",
		"Duration: 18m4s",
		"Verify: netherchat verify rec.json",
		"Provenance: X-Netherchat-Sig present",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("summary missing %q\n%s", want, s)
		}
	}
}

func TestRetrySucceedsAfter500s(t *testing.T) {
	srv, reqs := captureServer(t, 500, 500, 200)
	c, _ := New("servicenow", testCfg(srv), testProv())
	if err := c.Attach("SYS123", sampleRecord, "rec.json"); err != nil {
		t.Fatalf("should have succeeded on the 3rd attempt: %v", err)
	}
	if len(*reqs) != 3 {
		t.Errorf("expected 3 attempts (500,500,200), got %d", len(*reqs))
	}
}

func TestFailureFallbackWritesRecord(t *testing.T) {
	srv, _ := captureServer(t, 500) // always 500
	c, _ := New("servicenow", testCfg(srv), testProv())
	var out bytes.Buffer
	res := AttachResult{TicketID: "SYS123", Filename: "rec.json", VerifyCmd: "netherchat verify rec.json"}
	if err := Deliver(c, res, sampleRecord, &out); err == nil {
		t.Fatal("expected an error when every attempt fails")
	}
	if !bytes.Contains(out.Bytes(), sampleRecord) {
		t.Fatal("the record JSON must be written to the fallback output for manual attach")
	}
	if !strings.Contains(out.String(), "ATTACH FAILED") {
		t.Error("fallback output missing its header")
	}
}

// TestNoFilesWritten asserts the in-memory-only guarantee: retries and the failure
// fallback never write to disk.
func TestNoFilesWritten(t *testing.T) {
	before := lsDir(t)
	srv, _ := captureServer(t, 500)
	c, _ := New("servicenow", testCfg(srv), testProv())
	_ = Deliver(c, AttachResult{TicketID: "X", VerifyCmd: "v"}, sampleRecord, io.Discard)
	if after := lsDir(t); !equalStrings(before, after) {
		t.Errorf("files changed on disk:\nbefore=%v\nafter =%v", before, after)
	}
}

func TestUnknownBackend(t *testing.T) {
	if _, err := New("zendesk", Config{URL: "http://x"}, Provenance{}); err == nil {
		t.Error("unknown backend should error")
	}
}

func lsDir(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
