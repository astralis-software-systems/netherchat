// Package itsm attaches a Netherchat sealed record to an incident ticket in a
// system of record (ServiceNow or Jira) as the authoritative, offline-verifiable
// artifact (NC-4). It is the outbound system-of-record half of the connector
// design: on /seal, the deliberately-retained attestation — and ONLY that — is
// filed to the ticket.
//
// THE BOUNDARY LAW: the only thing sent is the sealed record JSON (the same bytes
// `netherchat verify` validates) plus its metadata in a human work note — the head
// hash, signer count, elapsed time, and the verify command. The record's entries
// are the decisions/actions that were EXPLICITLY promoted and sealed; the ephemeral
// room transcript and unsealed message content were never in the record and never
// cross. The work note carries metadata only — never decision text.
//
// Plain HTTPS + stdlib only; no vendor SDK. Both backends share the provenance
// headers (Ed25519, checkable against the record) and an in-memory, bounded retry
// with NO on-disk queue — same ephemerality guarantee as the bridge.
package itsm

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Config is the static connection config for an ITSM backend.
type Config struct {
	URL        string
	User       string
	Token      string
	HTTPClient *http.Client    // default: 15s-timeout client
	Backoff    []time.Duration // retry schedule; default {1s,2s,4s}
}

func (c Config) withDefaults() Config {
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	if c.Backoff == nil {
		c.Backoff = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}
	}
	return c
}

// Provenance is the Ed25519 attribution attached to every ITSM request. For a seal
// it is the sealer's signature over the record head (already in the record's
// Signatures), so a receiver can attribute the artifact and check the signature
// against the record's SignerKeys — provenance, not a server's say-so.
type Provenance struct {
	Room string
	Fpr  string // sealer fingerprint (SHA256:...)
	Sig  string // base64 Ed25519 signature over the sealed head
	Ts   string // RFC3339 (sealed_at)
}

// apply sets the X-Netherchat-* headers, omitting Fpr/Sig when absent rather than
// sending empty values.
func (p Provenance) apply(req *http.Request) {
	if p.Room != "" {
		req.Header.Set("X-Netherchat-Room", p.Room)
	}
	if p.Fpr != "" {
		req.Header.Set("X-Netherchat-Fpr", p.Fpr)
	}
	if p.Sig != "" {
		req.Header.Set("X-Netherchat-Sig", p.Sig)
	}
	if p.Ts != "" {
		req.Header.Set("X-Netherchat-Ts", p.Ts)
	}
}

// Client files a sealed record to one ITSM backend.
type Client interface {
	// Attach uploads the record bytes as a ticket attachment named filename.
	Attach(ticketID string, record []byte, filename string) error
	// Comment adds a human work note / comment with the summary text.
	Comment(ticketID string, summary string) error
}

// AttachResult is the metadata for the work-note summary (never content).
type AttachResult struct {
	TicketID  string
	Filename  string
	HeadHash  string
	Signers   int
	Elapsed   string
	VerifyCmd string
}

// backends is the registry of ITSM drivers; each backend registers itself in an
// init (the database/sql driver pattern). New looks a backend up here, so adding a
// backend is adding a file — no change to this dispatch.
var backends = map[string]func(Config, Provenance) Client{}

func register(name string, build func(Config, Provenance) Client) { backends[name] = build }

// New returns a Client for the named backend ("servicenow" | "jira").
func New(backend string, cfg Config, prov Provenance) (Client, error) {
	cfg = cfg.withDefaults()
	if build, ok := backends[strings.ToLower(strings.TrimSpace(backend))]; ok {
		return build(cfg, prov), nil
	}
	return nil, fmt.Errorf("unknown itsm backend %q (use servicenow or jira)", backend)
}

// FormatSummary builds the work-note / comment text — identical for both backends.
// It contains ONLY metadata: signer count, the head hash (shortened), elapsed
// time, the verify command, and a note that provenance is attached. Never any
// decision text or transcript.
func FormatSummary(r AttachResult) string {
	verify := r.VerifyCmd
	if verify == "" {
		verify = "netherchat verify record.json"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Incident record sealed by %d member(s).\n", r.Signers)
	fmt.Fprintf(&b, "Head hash: %s\n", shortHash(r.HeadHash, 16))
	if r.Elapsed != "" {
		fmt.Fprintf(&b, "Duration: %s\n", r.Elapsed)
	}
	fmt.Fprintf(&b, "Verify: %s\n", verify)
	b.WriteString("Provenance: X-Netherchat-Sig present")
	return b.String()
}

// Deliver attaches the record and adds the summary work note. The record bytes
// must be the marshaled sealed record and nothing else. On a failed attach (after
// retries), it writes the record JSON to out — the ONLY fallback persistence, and
// an operator action (manual re-attach), never an automatic on-disk write. A failed
// comment is reported but is not record-loss (the record is already attached).
func Deliver(c Client, res AttachResult, record []byte, out io.Writer) error {
	if err := c.Attach(res.TicketID, record, res.Filename); err != nil {
		writeFallback(out, res, record, err)
		return fmt.Errorf("attach record to %s: %w", res.TicketID, err)
	}
	if err := c.Comment(res.TicketID, FormatSummary(res)); err != nil {
		return fmt.Errorf("record attached to %s, but the work note failed: %w", res.TicketID, err)
	}
	return nil
}

// do performs an HTTP request with bounded, in-memory retries. makeReq must build a
// FRESH request each call (the body is consumed per attempt). It retries only what
// might succeed on a repeat — a transport error or a 5xx — never a 4xx (the
// receiver rejecting the request). There is NO on-disk queue.
func (c Config) do(makeReq func() (*http.Request, error)) error {
	attempts := len(c.Backoff) + 1
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			time.Sleep(c.Backoff[i-1])
		}
		req, err := makeReq()
		if err != nil {
			return err // a request-build error is not transient
		}
		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		resp.Body.Close()
		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			return nil
		case resp.StatusCode >= 500:
			lastErr = fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
		default: // 4xx / 3xx — not retryable
			return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
		}
	}
	return fmt.Errorf("failed after %d attempts: %w", attempts, lastErr)
}

func writeFallback(out io.Writer, res AttachResult, record []byte, cause error) {
	fmt.Fprintf(out, "\n=== netherchat-itsm: ATTACH FAILED — attach this record to %s manually ===\n", res.TicketID)
	fmt.Fprintf(out, "reason: %v\n", cause)
	fmt.Fprintf(out, "verify with: %s\n", res.VerifyCmd)
	fmt.Fprintln(out, "--- BEGIN SEALED RECORD ---")
	_, _ = out.Write(record)
	fmt.Fprintln(out, "\n--- END SEALED RECORD ---")
}

func shortHash(h string, n int) string {
	if len(h) <= n {
		return h
	}
	return h[:n] + "..."
}
