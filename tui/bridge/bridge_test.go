package bridge

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// countingRT is an http.RoundTripper that counts calls and always fails, standing
// in for an unreachable callback endpoint (connection refused) without a real
// closed port — so the retry schedule is exercised deterministically.
type countingRT struct {
	mu  sync.Mutex
	n   int
	err error
}

func (rt *countingRT) RoundTrip(*http.Request) (*http.Response, error) {
	rt.mu.Lock()
	rt.n++
	rt.mu.Unlock()
	return nil, rt.err
}

func (rt *countingRT) count() int {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.n
}

// okServer is a callback endpoint that always 200s.
func okServer(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return lines[len(lines)-1]
}

func sampleCallback() Callback {
	return Callback{
		Room: "ops", Event: "ack", Actor: "alice", ActorFpr: "SHA256:abc",
		Text: "drain-complete", When: time.Date(2026, 6, 10, 3, 14, 22, 0, time.UTC),
		Sig: []byte("raw-signature-bytes"), Raw: []byte(`{"tag":"drain-complete"}`),
	}
}

// TestParseEvents covers the default, a custom set, and rejection of unknown types.
func TestParseEvents(t *testing.T) {
	def, err := ParseEvents(DefaultEvents)
	if err != nil {
		t.Fatalf("default: %v", err)
	}
	for _, e := range []string{"decision", "action", "ack"} {
		if !def[e] {
			t.Fatalf("default --on missing %q", e)
		}
	}
	if def["seal"] || def["vanish"] || def["scuttle"] {
		t.Fatal("default --on must not include seal/vanish/scuttle")
	}
	if _, err := ParseEvents("decision, ack , scuttle"); err != nil {
		t.Fatalf("whitespace-tolerant parse failed: %v", err)
	}
	if _, err := ParseEvents("decision,bogus"); err == nil {
		t.Fatal("expected an error for an unknown event type")
	}
	if _, err := ParseEvents("  ,  "); err == nil {
		t.Fatal("expected an error for an empty --on list")
	}
}

// TestDefaultTemplateRendersValidJSON proves the built-in template produces valid
// JSON carrying every field — and stays valid when a value contains a quote (the
// reason the default uses the json helper rather than bare substitution).
func TestDefaultTemplateRendersValidJSON(t *testing.T) {
	br := mustBridge(t, Config{Room: "ops", On: set("ack"), PostURL: "http://x", Out: io.Discard})
	cb := sampleCallback()
	cb.Text = `he said "drain it"` // a quote that would break naive string interpolation

	body, err := br.render(cb)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !json.Valid(body) {
		t.Fatalf("default template produced invalid JSON: %s", body)
	}
	var got struct {
		Room     string `json:"room"`
		Event    string `json:"event"`
		Actor    string `json:"actor"`
		ActorFpr string `json:"actor_fpr"`
		Text     string `json:"text"`
		Ts       string `json:"ts"`
		Sig      string `json:"sig"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Room != "ops" || got.Event != "ack" || got.Actor != "alice" || got.ActorFpr != "SHA256:abc" {
		t.Fatalf("default template fields wrong: %+v", got)
	}
	if got.Text != cb.Text {
		t.Fatalf("text = %q, want %q (quote not preserved/escaped)", got.Text, cb.Text)
	}
	if got.Ts != "2026-06-10T03:14:22Z" {
		t.Fatalf("ts = %q", got.Ts)
	}
	if got.Sig != base64.StdEncoding.EncodeToString(cb.Sig) {
		t.Fatalf("sig = %q, want base64 of the raw signature", got.Sig)
	}
}

// TestCustomTemplateRendersAllVariables proves every documented variable — including
// .Raw (the raw decrypted event JSON) — is available to a custom template.
func TestCustomTemplateRendersAllVariables(t *testing.T) {
	tmpl, err := ParseTemplate(`{` +
		`"room":{{json .Room}},"event":{{json .Event}},"actor":{{json .Actor}},` +
		`"fpr":{{json .ActorFpr}},"text":{{json .Text}},"ts":{{json .Ts}},` +
		`"sig":{{json .Sig}},"raw":{{.Raw}}}`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	br := mustBridge(t, Config{Room: "ops", On: set("ack"), PostURL: "http://x", Template: tmpl, Out: io.Discard})
	cb := sampleCallback()

	body, err := br.render(cb)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var got struct {
		Room, Event, Actor, Fpr, Text, Ts, Sig string
		Raw                                    struct {
			Tag string `json:"tag"`
		}
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	if got.Room != "ops" || got.Event != "ack" || got.Actor != "alice" || got.Fpr != "SHA256:abc" ||
		got.Text != "drain-complete" || got.Ts != "2026-06-10T03:14:22Z" {
		t.Fatalf("rendered fields wrong: %+v", got)
	}
	if got.Sig != base64.StdEncoding.EncodeToString(cb.Sig) {
		t.Fatalf("sig = %q", got.Sig)
	}
	if got.Raw.Tag != "drain-complete" {
		t.Fatalf(".Raw did not embed the decrypted event JSON: %s", body)
	}
}

// TestInMemoryRetryFiresThenStops proves a callback to an unreachable endpoint is
// retried in memory and then abandoned: one initial attempt plus three retries
// (the 1s/2s/4s schedule), four POSTs in all, and a final bridge_failed carrying
// retries=3 — matching the ndjson schema. Nothing is queued to disk.
func TestInMemoryRetryFiresThenStops(t *testing.T) {
	rt := &countingRT{err: errors.New("connection refused")}
	var buf bytes.Buffer
	br := mustBridge(t, Config{
		Room: "ops", On: set("ack"), PostURL: "http://callback.invalid/x",
		HTTPClient: &http.Client{Transport: rt},
		Backoff:    []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond},
		JSON:       true, Out: &buf,
	})

	br.Fire(context.Background(), sampleCallback())

	// 1 initial attempt + 3 retries = 4 POSTs.
	if got := rt.count(); got != 4 {
		t.Fatalf("transport attempts = %d, want 4 (1 initial + 3 retries)", got)
	}
	ev := decodeStream(t, lastLine(buf.String()))
	if ev.Type != "bridge_failed" {
		t.Fatalf("final event type = %q, want bridge_failed", ev.Type)
	}
	if ev.Retries != 3 {
		t.Fatalf("retries = %d, want 3", ev.Retries)
	}
	if !strings.Contains(ev.Error, "connection refused") {
		t.Fatalf("error = %q, want it to mention connection refused", ev.Error)
	}
}

// TestNoDurableQueueAcrossRestart documents the ephemerality guard: undelivered
// callbacks die with the process. A freshly constructed bridge has no knowledge of
// a previous one's failed delivery — there is no on-disk queue to replay — so it
// makes zero callbacks until it observes its own event.
func TestNoDurableQueueAcrossRestart(t *testing.T) {
	tiny := []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}

	rt1 := &countingRT{err: errors.New("connection refused")}
	br1 := mustBridge(t, Config{Room: "ops", On: set("ack"), PostURL: "http://callback.invalid/x",
		HTTPClient: &http.Client{Transport: rt1}, Backoff: tiny, JSON: true, Out: io.Discard})
	br1.Fire(context.Background(), sampleCallback())
	if rt1.count() != 4 {
		t.Fatalf("first bridge attempts = %d, want 4", rt1.count())
	}

	// "Restart": a brand-new process/bridge. It must not replay br1's lost callback.
	rt2 := &countingRT{err: errors.New("connection refused")}
	_ = mustBridge(t, Config{Room: "ops", On: set("ack"), PostURL: "http://callback.invalid/x",
		HTTPClient: &http.Client{Transport: rt2}, Backoff: tiny, JSON: true, Out: io.Discard})
	time.Sleep(20 * time.Millisecond)
	if rt2.count() != 0 {
		t.Fatalf("restarted bridge replayed %d callbacks; there must be no durable queue", rt2.count())
	}
}

// TestJSONStreamParsesStrict proves both stream lines decode under
// DisallowUnknownFields — the schema carries no stray fields.
func TestJSONStreamParsesStrict(t *testing.T) {
	// Success line.
	var ok bytes.Buffer
	brOK := mustBridge(t, Config{Room: "ops", On: set("ack"), PostURL: okServer(t), JSON: true, Out: &ok})
	brOK.Fire(context.Background(), sampleCallback())
	got := decodeStream(t, lastLine(ok.String()))
	if got.V != StreamVersion || got.Type != "bridge_fired" || got.Status != 200 || got.Retries != 0 {
		t.Fatalf("fired event = %+v", got)
	}
	if got.Room != "ops" || got.Event != "ack" || got.Actor != "alice" {
		t.Fatalf("fired event metadata = %+v", got)
	}

	// Failure line (no retries: a 4xx is terminal, not retried).
	var bad bytes.Buffer
	brBad := mustBridge(t, Config{Room: "ops", On: set("ack"),
		PostURL: clientErrServer(t), JSON: true, Out: &bad})
	brBad.Fire(context.Background(), sampleCallback())
	fail := decodeStream(t, lastLine(bad.String()))
	if fail.Type != "bridge_failed" || fail.Retries != 0 {
		t.Fatalf("failed event = %+v", fail)
	}
	if !strings.Contains(fail.Error, "400") {
		t.Fatalf("failed event error = %q, want it to mention the 400 status", fail.Error)
	}
}

// clientErrServer always returns 400 — a terminal failure the bridge does not retry.
func clientErrServer(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// --- helpers ---

func set(events ...string) map[string]bool {
	m := make(map[string]bool, len(events))
	for _, e := range events {
		m[e] = true
	}
	return m
}

func mustBridge(t *testing.T, cfg Config) *Bridge {
	t.Helper()
	br, err := New(cfg)
	if err != nil {
		t.Fatalf("new bridge: %v", err)
	}
	return br
}

func decodeStream(t *testing.T, line string) streamEvent {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(line))
	dec.DisallowUnknownFields()
	var ev streamEvent
	if err := dec.Decode(&ev); err != nil {
		t.Fatalf("strict decode of %q: %v", line, err)
	}
	return ev
}
