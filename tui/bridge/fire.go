package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Fire delivers one callback: it renders the body, POSTs it with the provenance
// headers, and retries on transient failure with bounded, in-memory exponential
// backoff (the schedule in Config.Backoff). When every attempt fails it logs and
// returns — there is no on-disk queue, so an undelivered callback is gone (the
// ephemerality guard; see the package doc). Fire blocks for the duration of the
// retry schedule, so the daemon runs each delivery in its own goroutine.
//
// Retry accounting matches the ndjson schema: "retries" is the number of retries
// performed (0 on first-try success). With the default 3-entry backoff there is
// one initial attempt plus up to three retries — four POSTs at most.
func (b *Bridge) Fire(ctx context.Context, cb Callback) {
	body, err := b.render(cb)
	if err != nil {
		// A template that cannot render is a configuration error, not transient —
		// report it once and move on.
		b.reportFailure(cb, 0, 0, fmt.Errorf("template render: %w", err))
		return
	}

	attempt := 0 // number of retries performed so far
	for {
		status, perr := b.post(ctx, cb, body)
		if perr == nil && status >= 200 && status < 300 {
			b.reportSuccess(cb, status, attempt)
			return
		}
		// Retry only what might succeed on a repeat: a transport error or a 5xx.
		// A 4xx/3xx is the receiver rejecting the request — retrying won't fix it.
		retryable := perr != nil || status >= 500
		if !retryable || attempt >= len(b.cfg.Backoff) {
			b.reportFailure(cb, status, attempt, deliveryErr(status, perr))
			return
		}
		b.reportRetry(cb, attempt+1, len(b.cfg.Backoff), deliveryErr(status, perr))
		select {
		case <-time.After(b.cfg.Backoff[attempt]):
		case <-ctx.Done():
			b.reportFailure(cb, status, attempt, ctx.Err())
			return
		}
		attempt++
	}
}

// render executes the configured template against the callback's data.
func (b *Bridge) render(cb Callback) ([]byte, error) {
	data := tmplData{
		Room: cb.Room, Event: cb.Event, Actor: cb.Actor, ActorFpr: cb.ActorFpr,
		Text: cb.Text, Ts: cb.When.Format(time.RFC3339), Sig: cb.sigB64(), Raw: string(cb.Raw),
	}
	var buf bytes.Buffer
	if err := b.cfg.Template.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// post performs a single POST with the §1.6 provenance headers. It returns the
// HTTP status (0 on a transport error). The X-Netherchat-Fpr / X-Netherchat-Sig
// headers are omitted for events that carry no signer/signature (unsigned control
// frames, seal) rather than sent empty.
func (b *Bridge) post(ctx context.Context, cb Callback, body []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.cfg.PostURL, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Netherchat-Room", cb.Room)
	req.Header.Set("X-Netherchat-Event", cb.Event)
	req.Header.Set("X-Netherchat-Actor", cb.Actor)
	if cb.ActorFpr != "" {
		req.Header.Set("X-Netherchat-Fpr", cb.ActorFpr)
	}
	if s := cb.sigB64(); s != "" {
		req.Header.Set("X-Netherchat-Sig", s)
	}
	req.Header.Set("X-Netherchat-Ts", cb.When.Format(time.RFC3339))

	resp, err := b.cfg.HTTPClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body) // drain so the connection can be reused
	return resp.StatusCode, nil
}

// --- reporting --------------------------------------------------------------

// streamEvent is one line of the --json bridge stream. bridge_fired carries the
// final status; bridge_failed carries the error and the retry count. status is
// omitted when there is none (a transport error); error is omitted on success.
type streamEvent struct {
	V       int    `json:"v"`
	Ts      string `json:"ts"`
	Type    string `json:"type"` // bridge_fired | bridge_failed
	Room    string `json:"room"`
	Event   string `json:"event"`
	Actor   string `json:"actor"`
	Fpr     string `json:"fpr"`
	URL     string `json:"url"`
	Status  int    `json:"status,omitempty"`
	Retries int    `json:"retries"`
	Error   string `json:"error,omitempty"`
}

func (b *Bridge) reportSuccess(cb Callback, status, retries int) {
	if b.cfg.JSON {
		b.emitStream(streamEvent{
			V: StreamVersion, Ts: b.nowRFC(), Type: "bridge_fired",
			Room: cb.Room, Event: cb.Event, Actor: cb.Actor, Fpr: cb.ActorFpr,
			URL: b.cfg.PostURL, Status: status, Retries: retries,
		})
		return
	}
	note := fmt.Sprintf("%d %s", status, http.StatusText(status))
	if retries > 0 {
		note += fmt.Sprintf(" after %d %s", retries, plural(retries, "retry", "retries"))
	}
	b.writeLine(fmt.Sprintf("[%s] %s fired → %s (%s)", b.nowClock(), cb.label(), b.cfg.PostURL, note))
}

func (b *Bridge) reportRetry(cb Callback, n, max int, err error) {
	if b.cfg.JSON {
		return // the ndjson stream is one line per callback — only the final outcome
	}
	b.writeLine(fmt.Sprintf("[%s] %s fired → %s (retry %d/%d: %s)",
		b.nowClock(), cb.label(), b.cfg.PostURL, n, max, errStr(err)))
}

func (b *Bridge) reportFailure(cb Callback, status, retries int, err error) {
	if b.cfg.JSON {
		b.emitStream(streamEvent{
			V: StreamVersion, Ts: b.nowRFC(), Type: "bridge_failed",
			Room: cb.Room, Event: cb.Event, Actor: cb.Actor, Fpr: cb.ActorFpr,
			URL: b.cfg.PostURL, Status: status, Retries: retries, Error: errStr(err),
		})
		return
	}
	b.writeLine(fmt.Sprintf("[%s] %s failed → %s (gave up after %d %s: %s)",
		b.nowClock(), cb.label(), b.cfg.PostURL, retries, plural(retries, "retry", "retries"), errStr(err)))
}

// emitStream marshals and writes one ndjson line.
func (b *Bridge) emitStream(e streamEvent) {
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	b.writeLine(string(line))
}

// writeLine writes one line to the output sink, serialized so concurrent
// deliveries never interleave.
func (b *Bridge) writeLine(s string) {
	b.outMu.Lock()
	defer b.outMu.Unlock()
	fmt.Fprintln(b.cfg.Out, s)
}

func (b *Bridge) nowClock() string { return b.cfg.Now().Format("15:04:05") }
func (b *Bridge) nowRFC() string   { return b.cfg.Now().UTC().Format(time.RFC3339) }

// deliveryErr describes a failed attempt: the transport error if any, else the
// non-2xx HTTP status.
func deliveryErr(status int, perr error) error {
	if perr != nil {
		return perr
	}
	return fmt.Errorf("HTTP %d %s", status, http.StatusText(status))
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
