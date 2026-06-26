// Package alert implements the generic signed ingress socket (NC-1): the schema,
// per-source authentication, and rate/spawn hardening for inbound metadata alerts
// that POST /api/v1/alert accepts. It is the keystone every inbound connector
// rides — the scanner, an AI-egress monitor, and SIEMs (NC-2) are thin adapters that emit
// this exact shape; no app-specific code lives here.
//
// Everything an alert carries is METADATA ONLY (the boundary law): a source, a
// severity, a finding kind, a short summary, a reference, and a timestamp — never
// raw regulated content. The package is pure and side-effect-free (like the route
// package): creating the room and minting invites is the caller's job, so the
// validation, auth, and hardening semantics can be pinned down precisely in tests.
package alert

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/server/config"
	"golang.org/x/time/rate"
)

// Field-length bounds keep an alert to metadata: a blind relay must never become a
// channel for raw content, so oversized fields are rejected outright.
const (
	MaxSummaryBytes = 1 << 10 // 1 KiB
	MaxFieldBytes   = 256
)

// Default per-source hardening limits, used when a [[source]] leaves them at 0.
const (
	defaultRatePerMinute = 60
	defaultSpawnPerHour  = 20
)

// AlertV1 is the generic inbound alert (NC-1). Source/Severity/Kind are required;
// the rest are optional metadata. Signature is the per-source HMAC (hex) over
// protocol.AlertSigningBytes — present only for hmac_secret sources.
type AlertV1 struct {
	Source    string `json:"source"`
	Severity  string `json:"severity"`
	Kind      string `json:"kind"`
	Summary   string `json:"summary,omitempty"`
	Ref       string `json:"ref,omitempty"`
	TS        int64  `json:"ts,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// Parse strictly decodes an alert: unknown fields are rejected (so a typo or a
// smuggled extra field fails loudly rather than being silently admitted), trailing
// data is rejected, and the result is validated.
func Parse(raw []byte) (AlertV1, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var a AlertV1
	if err := dec.Decode(&a); err != nil {
		return AlertV1{}, fmt.Errorf("parse alert: %w", err)
	}
	if dec.More() {
		return AlertV1{}, errors.New("parse alert: trailing data after JSON object")
	}
	if err := a.Validate(); err != nil {
		return AlertV1{}, err
	}
	return a, nil
}

// Validate enforces the required fields and the metadata-only length bounds.
func (a AlertV1) Validate() error {
	if a.Source == "" || a.Severity == "" || a.Kind == "" {
		return errors.New("alert: source, severity, and kind are required")
	}
	if len(a.Source) > MaxFieldBytes {
		return fmt.Errorf("alert: source exceeds %d bytes", MaxFieldBytes)
	}
	if len(a.Severity) > MaxFieldBytes {
		return fmt.Errorf("alert: severity exceeds %d bytes", MaxFieldBytes)
	}
	if len(a.Kind) > MaxFieldBytes {
		return fmt.Errorf("alert: kind exceeds %d bytes", MaxFieldBytes)
	}
	if len(a.Ref) > MaxFieldBytes {
		return fmt.Errorf("alert: ref exceeds %d bytes", MaxFieldBytes)
	}
	if len(a.Summary) > MaxSummaryBytes {
		return fmt.Errorf("alert: summary exceeds %d bytes", MaxSummaryBytes)
	}
	return nil
}

// ToMatchMap renders the alert as the flat map the route matcher consumes, so the
// existing [[route]] mechanism routes on source/severity/kind/summary/ref with no
// new matching code.
func (a AlertV1) ToMatchMap() map[string]any {
	return map[string]any{
		"source":   a.Source,
		"severity": a.Severity,
		"kind":     a.Kind,
		"summary":  a.Summary,
		"ref":      a.Ref,
	}
}

// NoticeLine renders the marked-plaintext, metadata-only summary posted into a
// spawned war room. It contains only alert metadata — never raw content.
func (a AlertV1) NoticeLine() string {
	s := fmt.Sprintf("[%s] %s/%s", a.Severity, a.Source, a.Kind)
	if a.Summary != "" {
		s += ": " + a.Summary
	}
	if a.Ref != "" {
		s += " (ref " + a.Ref + ")"
	}
	return s
}

// Authenticate verifies an alert against its registered source. The socket
// supports both mechanisms: a source declares a Token, an HMACSecret, or both, and
// EVERY declared credential must pass (defense in depth). A source with neither is
// rejected — there is no default-open ingress. headerToken is the bearer token the
// caller pulled from the request (X-Netherchat-Token / ?token).
func Authenticate(src config.SourceConfig, a AlertV1, headerToken string) error {
	declared := false
	if src.HMACSecret != "" {
		declared = true
		if err := verifyHMAC(src.HMACSecret, a); err != nil {
			return err
		}
	}
	if src.Token != "" {
		declared = true
		if subtle.ConstantTimeCompare([]byte(headerToken), []byte(src.Token)) != 1 {
			return errors.New("alert: invalid source token")
		}
	}
	if !declared {
		return errors.New("alert: source has no credentials configured")
	}
	return nil
}

// verifyHMAC recomputes the per-source HMAC over the canonical alert bytes and
// constant-time-compares it to the supplied signature.
func verifyHMAC(secret string, a AlertV1) error {
	if a.Signature == "" {
		return errors.New("alert: missing signature for hmac source")
	}
	got, err := hex.DecodeString(a.Signature)
	if err != nil {
		return errors.New("alert: signature is not valid hex")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(protocol.AlertSigningBytes(a.Source, a.Severity, a.Kind, a.Summary, a.Ref, a.TS))
	if !hmac.Equal(got, mac.Sum(nil)) {
		return errors.New("alert: signature does not verify")
	}
	return nil
}

// Guards holds the per-source ingress hardening: a token-bucket rate limit on
// inbound alerts and a separate cap on war-room spawns, both keyed by source name
// and built lazily from each [[source]]'s configured limits (or the defaults). It
// is concurrency-safe.
type Guards struct {
	mu    sync.Mutex
	rate  map[string]*rate.Limiter
	spawn map[string]*rate.Limiter
}

// NewGuards returns an empty guard set.
func NewGuards() *Guards {
	return &Guards{rate: map[string]*rate.Limiter{}, spawn: map[string]*rate.Limiter{}}
}

// AllowRequest reports whether another inbound alert from src is within its rate
// limit (rate_per_minute, default 60). A nil receiver allows everything.
func (g *Guards) AllowRequest(src config.SourceConfig) bool {
	if g == nil {
		return true
	}
	per := src.RatePerMinute
	if per <= 0 {
		per = defaultRatePerMinute
	}
	return g.limiter(g.rate, src.Name, float64(per)/60.0, per).Allow()
}

// AllowSpawn reports whether src may spawn another war room within its spawn cap
// (spawn_per_hour, default 20). A nil receiver allows everything.
func (g *Guards) AllowSpawn(src config.SourceConfig) bool {
	if g == nil {
		return true
	}
	per := src.SpawnPerHour
	if per <= 0 {
		per = defaultSpawnPerHour
	}
	return g.limiter(g.spawn, src.Name, float64(per)/3600.0, per).Allow()
}

// limiter lazily builds (and caches) the named limiter with the given refill rate
// (tokens/sec) and burst.
func (g *Guards) limiter(into map[string]*rate.Limiter, name string, perSec float64, burst int) *rate.Limiter {
	if burst < 1 {
		burst = 1
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	l := into[name]
	if l == nil {
		l = rate.NewLimiter(rate.Limit(perSec), burst)
		into[name] = l
	}
	return l
}
