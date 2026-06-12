package siemout

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// captured records the last request a sink made.
type captured struct {
	path    string
	query   string
	headers http.Header
	body    []byte
}

// captureServer returns an httptest server that records each request and replies 200.
func captureServer(t *testing.T, cap *captured) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap.path = r.URL.Path
		cap.query = r.URL.RawQuery
		cap.headers = r.Header.Clone()
		cap.body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

var sampleEvents = []Event{
	{Type: "join", Room: "inc-1", Actor: "alice", Fpr: "SHA256:aaa", TS: "2026-06-12T10:00:00Z", RoomEpoch: 1},
	{Type: "ack", Room: "inc-1", Actor: "bob", Fpr: "SHA256:bbb", TS: "2026-06-12T10:01:00Z", RoomEpoch: 2},
}

func TestEventOnlyAllowedFields(t *testing.T) {
	b, _ := json.Marshal(sampleEvents[0])
	extra, err := UnexpectedFields(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(extra) != 0 {
		t.Fatalf("event serialized unexpected fields: %v", extra)
	}
	// Sanity: the keys we expect are present.
	for _, k := range []string{`"netherchat_event"`, `"room"`, `"actor"`, `"fpr"`, `"ts"`, `"room_epoch"`} {
		if !bytes.Contains(b, []byte(k)) {
			t.Errorf("event missing key %s\n%s", k, b)
		}
	}
}

func TestNewSinkRejectsEmptyURL(t *testing.T) {
	if _, err := NewSink("splunk", "", "tok", nil); err == nil {
		t.Fatal("an empty siem_url must be rejected (no default endpoint)")
	}
	if _, err := NewSink("nope", "http://x", "tok", nil); err == nil {
		t.Fatal("an unknown siem must be rejected")
	}
}

func TestSplunkSinkEncoding(t *testing.T) {
	var cap captured
	srv := captureServer(t, &cap)
	sink, err := NewSink("splunk", srv.URL, "hec-token", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Send(context.Background(), sampleEvents); err != nil {
		t.Fatalf("send: %v", err)
	}
	if cap.path != "/services/collector/event" {
		t.Errorf("path = %q, want /services/collector/event", cap.path)
	}
	if got := cap.headers.Get("Authorization"); got != "Splunk hec-token" {
		t.Errorf("authorization = %q, want Splunk hec-token", got)
	}
	// HEC body is newline-delimited {"time":...,"event":{...}} envelopes.
	lines := splitNonEmpty(string(cap.body))
	if len(lines) != len(sampleEvents) {
		t.Fatalf("expected %d HEC envelopes, got %d:\n%s", len(sampleEvents), len(lines), cap.body)
	}
	for _, line := range lines {
		var env struct {
			Time  int64           `json:"time"`
			Event json.RawMessage `json:"event"`
		}
		if err := json.Unmarshal([]byte(line), &env); err != nil {
			t.Fatalf("bad HEC envelope: %v\n%s", err, line)
		}
		if env.Time == 0 {
			t.Errorf("HEC envelope missing time: %s", line)
		}
		assertEventBoundary(t, env.Event)
	}
}

func TestSentinelSinkEncoding(t *testing.T) {
	var cap captured
	srv := captureServer(t, &cap)
	sink, err := NewSink("sentinel", srv.URL, "c2VjcmV0a2V5", srv.Client()) // base64("secretkey")
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Send(context.Background(), sampleEvents); err != nil {
		t.Fatalf("send: %v", err)
	}
	if !strings.HasPrefix(cap.path, "/api/logs") {
		t.Errorf("path = %q, want /api/logs...", cap.path)
	}
	if auth := cap.headers.Get("Authorization"); !strings.HasPrefix(auth, "SharedKey ") {
		t.Errorf("authorization = %q, want SharedKey ...", auth)
	}
	if cap.headers.Get("Log-Type") != "NetherchatRoomEvent" {
		t.Errorf("missing Log-Type header: %v", cap.headers.Get("Log-Type"))
	}
	if cap.headers.Get("X-Ms-Date") == "" {
		t.Error("missing x-ms-date header")
	}
	assertArrayBoundary(t, cap.body, len(sampleEvents))
}

func TestGenericSinkEncoding(t *testing.T) {
	var cap captured
	srv := captureServer(t, &cap)
	sink, err := NewSink("generic", srv.URL+"/ingest", "bearer-tok", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Send(context.Background(), sampleEvents); err != nil {
		t.Fatalf("send: %v", err)
	}
	if cap.path != "/ingest" {
		t.Errorf("path = %q, want /ingest", cap.path)
	}
	if got := cap.headers.Get("Authorization"); got != "Bearer bearer-tok" {
		t.Errorf("authorization = %q, want Bearer bearer-tok", got)
	}
	assertArrayBoundary(t, cap.body, len(sampleEvents))
}

// TestContentNeverInBatch is mandatory: even when the upstream events carried content
// (they cannot — Event has no content field), nothing but the allowed metadata keys
// may appear in any sink's batch body.
func TestContentNeverInBatch(t *testing.T) {
	// An adversarial event: every metadata field is a marker we can search for. There
	// is structurally no content field to populate.
	ev := []Event{{Type: "action_request", Room: "inc-9", Actor: "MARK_ACTOR", Fpr: "MARK_FPR", TS: "2026-06-12T10:00:00Z", RoomEpoch: 7}}
	for _, siem := range []string{"splunk", "sentinel", "generic"} {
		var cap captured
		srv := captureServer(t, &cap)
		sink, err := NewSink(siem, srv.URL, "dG9r", srv.Client())
		if err != nil {
			t.Fatalf("%s: %v", siem, err)
		}
		if err := sink.Send(context.Background(), ev); err != nil {
			t.Fatalf("%s send: %v", siem, err)
		}
		// The metadata is present (it is allowed to cross)...
		for _, want := range []string{"MARK_ACTOR", "MARK_FPR", "action_request", "inc-9"} {
			if !bytes.Contains(cap.body, []byte(want)) {
				t.Errorf("%s: expected metadata %q in body\n%s", siem, want, cap.body)
			}
		}
		// ...and no key beyond the allowed set ever appears.
		for _, line := range eventObjects(t, siem, cap.body) {
			assertEventBoundary(t, line)
		}
	}
}

func TestBatcherSizeFlush(t *testing.T) {
	var mu sync.Mutex
	var batches [][]Event
	b := NewBatcher(3, time.Hour, func(ev []Event) {
		mu.Lock()
		batches = append(batches, ev)
		mu.Unlock()
	})
	b.Add(Event{Type: "join"})
	b.Add(Event{Type: "ack"})
	if len(batches) != 0 {
		t.Fatalf("must not flush before the size cap, got %d batches", len(batches))
	}
	b.Add(Event{Type: "leave"}) // third → size cap reached
	mu.Lock()
	defer mu.Unlock()
	if len(batches) != 1 || len(batches[0]) != 3 {
		t.Fatalf("size flush wrong: %d batches, first len %d", len(batches), lenFirst(batches))
	}
}

func TestBatcherTimeFlush(t *testing.T) {
	got := make(chan []Event, 4)
	b := NewBatcher(100, 20*time.Millisecond, func(ev []Event) { got <- ev })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.Run(ctx)
	b.Add(Event{Type: "join"}) // one event, well under the size cap
	select {
	case batch := <-got:
		if len(batch) != 1 {
			t.Fatalf("time flush sent %d events, want 1", len(batch))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("time flush did not fire within 2s")
	}
}

func TestBatcherRunFinalFlush(t *testing.T) {
	got := make(chan []Event, 1)
	b := NewBatcher(100, time.Hour, func(ev []Event) { got <- ev })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { b.Run(ctx); close(done) }()
	b.Add(Event{Type: "seal"})
	cancel() // shutdown → final flush of the buffered event
	select {
	case batch := <-got:
		if len(batch) != 1 {
			t.Fatalf("final flush sent %d, want 1", len(batch))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("final flush did not fire")
	}
	<-done
}

// --- helpers --------------------------------------------------------------------

func assertEventBoundary(t *testing.T, eventObject []byte) {
	t.Helper()
	extra, err := UnexpectedFields(eventObject)
	if err != nil {
		t.Fatalf("decode event object: %v\n%s", err, eventObject)
	}
	if len(extra) != 0 {
		t.Fatalf("boundary violated: unexpected fields %v in %s", extra, eventObject)
	}
}

func assertArrayBoundary(t *testing.T, body []byte, want int) {
	t.Helper()
	var arr []json.RawMessage
	if err := json.Unmarshal(body, &arr); err != nil {
		t.Fatalf("body is not a JSON array: %v\n%s", err, body)
	}
	if len(arr) != want {
		t.Fatalf("array has %d events, want %d", len(arr), want)
	}
	for _, e := range arr {
		assertEventBoundary(t, e)
	}
}

// eventObjects pulls the individual event JSON objects out of a sink body for the
// given siem shape (HEC envelopes for splunk, a JSON array for the others).
func eventObjects(t *testing.T, siem string, body []byte) [][]byte {
	t.Helper()
	if siem == "splunk" {
		var out [][]byte
		for _, line := range splitNonEmpty(string(body)) {
			var env struct {
				Event json.RawMessage `json:"event"`
			}
			if err := json.Unmarshal([]byte(line), &env); err != nil {
				t.Fatalf("bad HEC line: %v", err)
			}
			out = append(out, env.Event)
		}
		return out
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(body, &arr); err != nil {
		t.Fatalf("body not array: %v", err)
	}
	out := make([][]byte, len(arr))
	for i := range arr {
		out[i] = arr[i]
	}
	return out
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

func lenFirst(b [][]Event) int {
	if len(b) == 0 {
		return 0
	}
	return len(b[0])
}
