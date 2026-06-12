// Package connector is the shared client for Netherchat's typed inbound adapters
// (NC-2). Every adapter — security findings, AI-egress signals, SIEM — translates
// its source tool's output into the SAME generic NC-1 alert (a fixed seven-field
// metadata shape) and POSTs it to a relay's ingress socket (POST /api/v1/alert).
//
// Centralizing the wire shape and the POST here is what makes the boundary law
// structural rather than aspirational: an Alert has EXACTLY the fields that may
// cross the boundary, so an adapter cannot leak raw content even by mistake — the
// only way to send anything is to populate an Alert, and an Alert has no field for
// raw content. UnexpectedFields makes that checkable in a test.
//
// It depends only on the standard library and the pure `protocol` package (for the
// HMAC preimage). It never imports the client crypto or any server-internal
// package, so adapters stay blind metadata forwarders and the server-blind
// boundary is untouched.
package connector

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
)

// Alert is the generic NC-1 metadata alert — the ONLY shape that crosses the
// boundary. Its fields are exactly those POST /api/v1/alert accepts; nothing an
// adapter reads from its source may be added here. (It mirrors
// server/internal/alert.AlertV1, which an adapter cannot import because it is
// server-internal — so the shape is duplicated deliberately and pinned by tests.)
type Alert struct {
	Source    string `json:"source"`
	Severity  string `json:"severity"`
	Kind      string `json:"kind"`
	Summary   string `json:"summary,omitempty"`
	Ref       string `json:"ref,omitempty"`
	TS        int64  `json:"ts,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// SummaryMax is the adapter-side cap on the summary line (NC-2). It is far below
// the relay's hard limit; adapters truncate to it so the in-room notice stays a
// one-liner and "metadata only" is obvious at a glance.
const SummaryMax = 200

// AllowedFields is the complete set of keys that may appear in a posted alert —
// the boundary law expressed as a list. Adapters' boundary tests check the actual
// POST body against it.
var AllowedFields = []string{"source", "severity", "kind", "summary", "ref", "ts", "signature"}

// Result is the relay's response to an accepted alert.
type Result struct {
	Accepted bool              `json:"accepted"`
	Spawned  bool              `json:"spawned"`
	Room     string            `json:"room,omitempty"`
	Links    map[string]string `json:"links,omitempty"`
}

// Client posts alerts to a relay's ingress socket. The zero value is unusable; set
// Server. Token and/or HMACSecret authenticate per the registered [[source]].
type Client struct {
	Server     string       // relay origin, e.g. https://relay.example.com
	Token      string       // bearer token (sent as X-Netherchat-Token)
	HMACSecret string       // if set, the alert is signed (signature field)
	HTTP       *http.Client // optional; a 10s-timeout client is used when nil
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// Send signs (if configured), serializes, and POSTs one Alert to
// {Server}/api/v1/alert, returning the relay's Result. It marshals ONLY the Alert
// struct, so the request body can never contain a field the adapter did not put
// there — the structural half of the boundary guarantee.
func (c *Client) Send(ctx context.Context, a Alert) (Result, error) {
	if c.Server == "" {
		return Result{}, errors.New("connector: server URL is required")
	}
	if a.Source == "" || a.Severity == "" || a.Kind == "" {
		return Result{}, errors.New("connector: source, severity, and kind are required")
	}
	if c.HMACSecret != "" {
		a.Signature = Sign(c.HMACSecret, a)
	}
	body, err := json.Marshal(a)
	if err != nil {
		return Result{}, err
	}
	url := strings.TrimRight(c.Server, "/") + "/api/v1/alert"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		req.Header.Set("X-Netherchat-Token", c.Token)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("relay rejected alert: %s: %s", resp.Status, strings.TrimSpace(string(rb)))
	}
	var res Result
	if err := json.Unmarshal(rb, &res); err != nil {
		return Result{}, fmt.Errorf("decode relay response: %w", err)
	}
	return res, nil
}

// Sign returns the per-source HMAC (hex) the relay verifies: HMAC-SHA256 over the
// domain-separated protocol.AlertSigningBytes preimage. It binds every metadata
// field, so an alert is tamper-evident in transit.
func Sign(secret string, a Alert) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(protocol.AlertSigningBytes(a.Source, a.Severity, a.Kind, a.Summary, a.Ref, a.TS))
	return hex.EncodeToString(mac.Sum(nil))
}

// UnexpectedFields returns any top-level JSON keys in body that are NOT allowed
// alert fields. A non-empty result means the boundary law was violated — a raw
// field from the source leaked into the wire shape. It is the runtime companion to
// each adapter's boundary test.
func UnexpectedFields(body []byte) ([]string, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
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
