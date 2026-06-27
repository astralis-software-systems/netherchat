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
	"time"

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
	mu     sync.Mutex
	rate   map[string]*rate.Limiter
	spawn  map[string]*rate.Limiter
	warned map[string]bool  // per-source: ts==0 "freshness inactive" logged once
	now    func() time.Time // nil ⇒ time.Now (injectable in tests)
}

// NewGuards returns an empty guard set. Its signature is intentionally arg-less:
// the freshness fields are zero-value-safe (a nil warned-set is lazily built; a nil
// clock defaults to time.Now), so no call site changes when freshness is added.
func NewGuards() *Guards {
	return &Guards{
		rate:   map[string]*rate.Limiter{},
		spawn:  map[string]*rate.Limiter{},
		warned: map[string]bool{},
	}
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

// tokenKey hashes a webhook token to a stable, non-secret limiter key. The raw token
// never becomes a map key, a log field, or an error string — only this digest does,
// so a memory dump of the limiter maps cannot recover the secret.
func tokenKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// AllowWebhookUnauth reports whether another REJECTED webhook request (a non-webhook
// room, or a failed/empty token) is within the global pre-auth ceiling — the coarse
// Tier-1 guard for POST /webhook/{room}. It is a single GLOBAL bucket (fixed key
// "wh-unauth") that callers must consult ONLY on the rejection paths: an
// authenticated request never calls it, so a flood of bad tokens can never lock out
// a legitimate token-holder. perMin is the configured unauth_rate_per_minute (a
// non-positive value falls back to the built-in). A nil receiver allows everything.
func (g *Guards) AllowWebhookUnauth(perMin int) bool {
	if g == nil {
		return true
	}
	if perMin <= 0 {
		perMin = config.DefaultWebhookUnauthRatePerMinute
	}
	return g.limiter(g.rate, "wh-unauth", float64(perMin)/60.0, perMin).Allow()
}

// AllowWebhookRequest reports whether another AUTHENTICATED webhook POST for this
// token is within its per-token rate cap (Tier 2). The token is hashed into the
// bucket key ("wh-rate:"+sha256hex) and never stored raw. This guard is the only
// cover for the route-non-matching hub.Broadcast flood, so callers consult it on
// every authenticated request, before the body read. perMin is the effective
// per-room rate (override or global default), resolved by the caller; a non-positive
// value falls back to the built-in. A nil receiver allows everything.
func (g *Guards) AllowWebhookRequest(token string, perMin int) bool {
	if g == nil {
		return true
	}
	if perMin <= 0 {
		perMin = config.DefaultWebhookRatePerMinute
	}
	return g.limiter(g.rate, "wh-rate:"+tokenKey(token), float64(perMin)/60.0, perMin).Allow()
}

// AllowWebhookSpawn reports whether this token may spawn another war room within its
// per-token spawn cap (Tier 2), keyed "wh-spawn:"+sha256hex. It bounds the
// room-spawn/invite/reply_url vector and is consulted only on a route match. perHour
// is the effective per-room spawn cap; a non-positive value falls back to the
// built-in. A nil receiver allows everything.
func (g *Guards) AllowWebhookSpawn(token string, perHour int) bool {
	if g == nil {
		return true
	}
	if perHour <= 0 {
		perHour = config.DefaultWebhookSpawnPerHour
	}
	return g.limiter(g.spawn, "wh-spawn:"+tokenKey(token), float64(perHour)/3600.0, perHour).Allow()
}

// AllowFresh reports whether an alert's already-HMAC-verified timestamp ts (unix
// seconds) is within the source's acceptance window — the replay/freshness gate
// (NC-1). The ts rides inside the signed preimage (protocol.AlertSigningBytes), so
// a replayed alert carries an old, signed ts that this gate rejects; an attacker can
// neither alter it (breaks the HMAC) nor forge a fresh one (no secret).
//
// It is meaningful ONLY for HMAC sources: a token-only source's ts is unsigned
// (attacker-controllable), so the window is inert there and AllowFresh returns
// (true, "", "").
//
// Policy (enforce-if-present baseline + optional strict). For an HMAC source:
//   - ts == 0  → inactive under the baseline: (true, "", warn), where warn is a
//     one-time-per-source "freshness inactive" message the caller logs; REJECTED as
//     (false, "missing timestamp", "") when src.RequireFresh.
//   - ts older than the window          → (false, "stale timestamp", "").
//   - ts further ahead than future skew → (false, "future timestamp", "").
//   - otherwise                         → (true, "", "").
//
// def is the resolved global default ([ingest.freshness]); per-source overrides
// (FreshnessWindow / FreshnessFutureSkew, 0 = use def) win, falling back to the
// built-in config defaults if both are unset. The window/skew arithmetic is pure;
// the only mutable state touched is the warned-set used to log a ts==0 source once.
// A nil receiver allows everything.
func (g *Guards) AllowFresh(src config.SourceConfig, ts int64, def config.FreshnessConfig) (ok bool, reason, warn string) {
	if g == nil {
		return true, "", ""
	}
	// Token-only sources: the ts is not in any signed preimage, so a window over it
	// would be theater. Enforcement is gated on a configured HMAC secret.
	if src.HMACSecret == "" {
		return true, "", ""
	}
	if ts == 0 {
		// enforce-if-present: no signed timestamp → pass under the baseline (but say
		// so once), reject under the per-source strict mandate.
		if src.RequireFresh {
			return false, "missing timestamp", ""
		}
		return true, "", g.warnOnce(src.Name)
	}
	window := resolveDuration(src.FreshnessWindow, def.Window, config.DefaultFreshnessWindow)
	skew := resolveDuration(src.FreshnessFutureSkew, def.FutureSkew, config.DefaultFreshnessFutureSkew)
	age := g.clock()().Unix() - ts // >0 = ts is in the past, <0 = ts leads the clock
	if age > int64(window/time.Second) {
		return false, "stale timestamp", ""
	}
	if -age > int64(skew/time.Second) {
		return false, "future timestamp", ""
	}
	return true, "", ""
}

// resolveDuration applies the "0 = use the next level down" override precedent: a
// positive per-source override wins, else the (normalized) global default, else the
// built-in fallback so the gate is never accidentally disabled.
func resolveDuration(override, global config.Duration, builtin time.Duration) time.Duration {
	if d := override.Std(); d > 0 {
		return d
	}
	if d := global.Std(); d > 0 {
		return d
	}
	return builtin
}

// warnOnce returns the "freshness inactive" warning the first time a ts==0 HMAC
// source is seen this process, then "" — so the caller logs it exactly once.
func (g *Guards) warnOnce(name string) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.warned == nil {
		g.warned = map[string]bool{}
	}
	if g.warned[name] {
		return ""
	}
	g.warned[name] = true
	return "freshness inactive: source sends no timestamp"
}

// clock returns the time source: the injected now (tests) or time.Now.
func (g *Guards) clock() func() time.Time {
	if g.now != nil {
		return g.now
	}
	return time.Now
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
