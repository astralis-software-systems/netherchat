// Package siemout streams metadata-only room events from a Netherchat war room to a
// SIEM, for one unified, tamper-evident audit trail (NC-5). It is the outbound twin
// of the NC-2 inbound SIEM adapter: inbound, a SIEM correlation opens a room;
// outbound, the room's lifecycle events are mirrored back to the SIEM.
//
// THE BOUNDARY LAW IS STRUCTURAL HERE. The only shape that crosses is Event, whose
// fields are EXACTLY the metadata that may leave a room — an event type, the room,
// an actor display name, a fingerprint, a timestamp, and the room epoch. There is no
// field for a message body, decision text, a tag, a reason, or any content, so a
// batch cannot carry any. The SIEM sees who did what and when; never what was said.
//
// Plain HTTPS + stdlib only; no vendor SDK. Batching is in-memory with NO on-disk
// queue — the same ephemerality guarantee as the room itself.
package siemout

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Event is the metadata-only room event that crosses to a SIEM. Its JSON keys are
// the complete, fixed set that may leave a room — there is no field for content.
type Event struct {
	Type      string `json:"netherchat_event"` // join|leave|ack|vanish|seal|scuttle|clock_start|clock_stop|action_request|action_executed|action_vetoed
	Room      string `json:"room"`
	Actor     string `json:"actor,omitempty"`
	Fpr       string `json:"fpr,omitempty"`
	TS        string `json:"ts"` // RFC3339
	RoomEpoch uint64 `json:"room_epoch"`
}

// AllowedFields is the complete set of keys an Event may serialize to — the boundary
// law as a list. Tests assert nothing else ever appears in a posted event object.
var AllowedFields = []string{"netherchat_event", "room", "actor", "fpr", "ts", "room_epoch"}

// UnexpectedFields returns any top-level JSON keys in a single event object that are
// not allowed. A non-empty result means the boundary law was violated.
func UnexpectedFields(eventObject []byte) ([]string, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(eventObject, &m); err != nil {
		return nil, err
	}
	allowed := make(map[string]bool, len(AllowedFields))
	for _, f := range AllowedFields {
		allowed[f] = true
	}
	var extra []string
	for k := range m {
		if !allowed[k] {
			extra = append(extra, k)
		}
	}
	return extra, nil
}

// --- sinks ----------------------------------------------------------------------

// Sink delivers a batch of metadata-only events to a SIEM over plain HTTPS.
type Sink interface {
	Send(ctx context.Context, events []Event) error
}

// NewSink builds a sink for the named SIEM ("splunk" | "sentinel" | "generic"). An
// empty siemURL is rejected: per the zero-telemetry invariant there is no default
// external endpoint — a destination must be configured explicitly.
func NewSink(siem, siemURL, siemToken string, hc *http.Client) (Sink, error) {
	if strings.TrimSpace(siemURL) == "" {
		return nil, errors.New("siemout: siem_url is required (there is no default external endpoint)")
	}
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	switch strings.ToLower(strings.TrimSpace(siem)) {
	case "splunk":
		return &splunkSink{url: siemURL, token: siemToken, hc: hc}, nil
	case "sentinel":
		return &sentinelSink{url: siemURL, sharedKey: siemToken, logType: "NetherchatRoomEvent", hc: hc}, nil
	case "generic":
		return &genericSink{url: siemURL, token: siemToken, hc: hc}, nil
	default:
		return nil, fmt.Errorf("siemout: unknown siem %q (use splunk, sentinel, or generic)", siem)
	}
}

// splunkSink posts to a Splunk HTTP Event Collector. Each event is wrapped as an HEC
// envelope {"time":<unix>,"event":<metadata-only-object>}; a batch is the envelopes
// newline-delimited, which HEC accepts in one request.
type splunkSink struct {
	url   string
	token string
	hc    *http.Client
}

type hecEnvelope struct {
	Time  int64 `json:"time"`
	Event Event `json:"event"`
}

func (s *splunkSink) endpoint() string {
	u := strings.TrimRight(s.url, "/")
	if strings.HasSuffix(u, "/services/collector/event") || strings.HasSuffix(u, "/services/collector") {
		return u
	}
	return u + "/services/collector/event"
}

func (s *splunkSink) Send(ctx context.Context, events []Event) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, e := range events {
		if err := enc.Encode(hecEnvelope{Time: eventUnix(e.TS), Event: e}); err != nil {
			return err
		}
	}
	return post(ctx, s.hc, s.endpoint(), buf.Bytes(), map[string]string{
		"Authorization": "Splunk " + s.token,
		"Content-Type":  "application/json",
	})
}

// sentinelSink posts to the Azure Monitor / Microsoft Sentinel HTTP Data Collector
// API: a JSON array of events, authenticated with the workspace SharedKey scheme.
type sentinelSink struct {
	url       string // workspace base or full /api/logs URL
	sharedKey string // base64 workspace primary/secondary key
	logType   string
	hc        *http.Client
}

func (s *sentinelSink) endpoint() string {
	u := strings.TrimRight(s.url, "/")
	if strings.Contains(u, "/api/logs") {
		return s.url
	}
	return u + "/api/logs?api-version=2016-04-01"
}

func (s *sentinelSink) Send(ctx context.Context, events []Event) error {
	body, err := json.Marshal(events)
	if err != nil {
		return err
	}
	date := time.Now().UTC().Format(http.TimeFormat) // RFC1123 GMT
	return post(ctx, s.hc, s.endpoint(), body, map[string]string{
		"Content-Type":         "application/json",
		"Authorization":        s.signature(len(body), date),
		"Log-Type":             s.logType,
		"x-ms-date":            date,
		"time-generated-field": "ts",
	})
}

// signature builds the Sentinel "SharedKey <workspace>:<sig>" Authorization header.
// The signed string is the documented Azure HTTP Data Collector canonical form. The
// workspace id is taken from the configured URL's first host label.
func (s *sentinelSink) signature(contentLength int, date string) string {
	stringToSign := "POST\n" + strconv.Itoa(contentLength) + "\napplication/json\n" + "x-ms-date:" + date + "\n/api/logs"
	key, err := base64.StdEncoding.DecodeString(s.sharedKey)
	if err != nil || len(key) == 0 {
		key = []byte(s.sharedKey) // tolerate a raw (non-base64) key
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(stringToSign))
	encoded := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return "SharedKey " + workspaceFromURL(s.url) + ":" + encoded
}

// genericSink posts a JSON array of events to a configured URL, optionally with a
// bearer token. The lowest-common-denominator target for any HTTP log collector.
type genericSink struct {
	url   string
	token string
	hc    *http.Client
}

func (g *genericSink) Send(ctx context.Context, events []Event) error {
	body, err := json.Marshal(events)
	if err != nil {
		return err
	}
	headers := map[string]string{"Content-Type": "application/json"}
	if g.token != "" {
		headers["Authorization"] = "Bearer " + g.token
	}
	return post(ctx, g.hc, g.url, body, headers)
}

// post performs one HTTPS POST with the given headers and checks for a 2xx. There is
// no retry and no on-disk queue: a failed batch is dropped (the caller logs it), in
// keeping with the room's ephemerality.
func post(ctx context.Context, hc *http.Client, endpoint string, body []byte, headers map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("siem returned %s: %s", resp.Status, strings.TrimSpace(string(rb)))
	}
	return nil
}

// --- batching -------------------------------------------------------------------

// Batcher buffers events in memory and flushes them when the buffer reaches a size
// cap OR a flush interval elapses, whichever comes first. There is NO on-disk queue;
// a process exit loses any unflushed events (by design — they are ephemeral).
type Batcher struct {
	size     int
	interval time.Duration
	flush    func([]Event)

	mu  sync.Mutex
	buf []Event
}

// NewBatcher returns a Batcher that calls flush with a non-empty slice of events. A
// size <= 0 defaults to 100; an interval <= 0 defaults to 5s.
func NewBatcher(size int, interval time.Duration, flush func([]Event)) *Batcher {
	if size <= 0 {
		size = 100
	}
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &Batcher{size: size, interval: interval, flush: flush}
}

// Size returns the effective batch-size cap (after defaulting).
func (b *Batcher) Size() int { return b.size }

// Add appends an event, flushing synchronously if the size cap is reached.
func (b *Batcher) Add(e Event) {
	b.mu.Lock()
	b.buf = append(b.buf, e)
	if len(b.buf) >= b.size {
		batch := b.buf
		b.buf = nil
		b.mu.Unlock()
		b.flush(batch)
		return
	}
	b.mu.Unlock()
}

// Flush sends whatever is buffered now (a no-op when empty).
func (b *Batcher) Flush() {
	b.mu.Lock()
	if len(b.buf) == 0 {
		b.mu.Unlock()
		return
	}
	batch := b.buf
	b.buf = nil
	b.mu.Unlock()
	b.flush(batch)
}

// Run flushes on the interval until ctx is cancelled, then performs a final flush.
func (b *Batcher) Run(ctx context.Context) {
	t := time.NewTicker(b.interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			b.Flush()
		case <-ctx.Done():
			b.Flush()
			return
		}
	}
}

// --- helpers --------------------------------------------------------------------

func eventUnix(ts string) int64 {
	if t, err := time.Parse(time.RFC3339, ts); err == nil {
		return t.Unix()
	}
	return time.Now().Unix()
}

// workspaceFromURL extracts the first host label of a URL (the Sentinel workspace id
// in https://<workspace>.ods.opinsights.azure.com), or "" when it cannot be derived
// (e.g. an IP or localhost in tests).
func workspaceFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	if i := strings.Index(host, "."); i > 0 {
		label := host[:i]
		if label != "www" {
			return label
		}
	}
	return ""
}
