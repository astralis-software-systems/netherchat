// Package config loads the Netherchat server configuration from netherchat.toml
// (config-as-code, R4). Everything policy-related — room access, webhooks,
// /exec, TTL, rate limits, persistence — is driven from here so the server's
// behavior is auditable in one file checked into the operator's repo.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/salehkreiner/netherchat/protocol"
)

// Config is the full server configuration. The [[trust]] table is the one
// exception to "server config": it is read only by CLIENTS for identity pinning
// (/whois). The relay never reads, forwards, or participates in trust decisions —
// trust is evaluated entirely client-side.
type Config struct {
	Server      ServerConfig            `toml:"server"`
	Limits      LimitsConfig            `toml:"limits"`
	Persistence PersistenceConfig       `toml:"persistence"`
	Rooms       map[string]RoomConfig   `toml:"rooms"`
	Routes      []RouteConfig           `toml:"route"`
	Sources     []SourceConfig          `toml:"source"`
	Ingest      IngestConfig            `toml:"ingest"`
	Actions     map[string]ActionPolicy `toml:"action"`
	Trust       []TrustEntry            `toml:"trust"`
	Direct      DirectConfig            `toml:"direct"`
	Notify      NotifyConfig            `toml:"notify"`
	Macros      map[string]string       `toml:"macros"`
}

// NotifyConfig is the CLIENT-side desktop-notification policy (§2.1): which in-room
// events fire a native OS notification. Read only by the TUI; the relay never sees
// it. Valid events: mention, decision, ack, break_glass.
type NotifyConfig struct {
	On []string `toml:"on"`
}

// DirectConfig holds Sneakernet Mode (§1.1) defaults read CLIENT-side by
// `netherchat pair`: the listening port for direct peer connections and whether to
// advertise on the LAN via mDNS. Like [[trust]] and [action.*], the relay never
// reads it — relay-less pairing involves no server.
type DirectConfig struct {
	Port         int  `toml:"port"`          // 0 = a free port
	LANDiscovery bool `toml:"lan_discovery"` // advertise/discover on the LAN via mDNS
}

// ActionPolicy is a per-action quorum policy: the Two-Person Rule. The table key
// is the action name, e.g. [action.runbook]. Enforcement is CLIENT-SIDE and
// cryptographic: a privileged action does not fire until `quorum` distinct
// authorized members (the requester counts as one, via their signed request)
// co-sign the same request hash. quorum 1 (or an absent entry) is single-actor
// behavior; quorum 0 disables the action.
//
// This is a CLIENT-evaluated policy, like [[trust]]: the connecting client and the
// edge agent read it from netherchat.toml and gate the action over Ed25519
// approvals the relay only ever sees as ciphertext. The relay itself does not
// enforce or even read it.
type ActionPolicy struct {
	Quorum int `toml:"quorum"`
}

// ActionQuorum returns the configured quorum for an action: the value as written
// when present (including 0, which disables the action), else 1 (single-actor).
func (c Config) ActionQuorum(action string) int {
	if p, ok := c.Actions[action]; ok {
		return p.Quorum
	}
	return 1
}

// TrustEntry pins a handle to a fingerprint and/or a published key source. Both
// fields are independently optional: fpr-only warns on mismatch and never
// fetches; keys_url-only fetches on /whois and never auto-pins; both does both;
// neither is just a display-name alias. Evaluated client-side only.
type TrustEntry struct {
	Handle  string `toml:"handle"`
	Fpr     string `toml:"fpr"`      // optional: a pinned "SHA256:…" fingerprint
	KeysURL string `toml:"keys_url"` // optional: e.g. https://github.com/<handle>.keys
}

// SourceConfig registers an inbound alert source for the generic ingress socket
// (NC-1, POST /api/v1/alert). Each source authenticates with a bearer Token, an
// HMACSecret (HMAC-SHA256 over the canonical alert), or both. A source with
// neither credential is rejected — there is no default-open ingress. Like
// [[route]], this is server-side ingress policy and never involves message
// content; the relay stays blind.
type SourceConfig struct {
	Name          string `toml:"name"`
	Token         string `toml:"token"`           // bearer-token auth (X-Netherchat-Token / ?token)
	HMACSecret    string `toml:"hmac_secret"`     // HMAC-SHA256 signature auth (the alert's `signature` field)
	RatePerMinute int    `toml:"rate_per_minute"` // inbound alert rate cap per source (0 = default)
	SpawnPerHour  int    `toml:"spawn_per_hour"`  // war-room spawn cap per source (0 = default)

	// Freshness (replay/timestamp-window) overrides for the signed-alert socket
	// (NC-1). The window validates the already-signed `ts` an HMAC source carries;
	// it is inert for a token-only source (whose `ts` is unsigned, attacker-
	// controllable). RequireFresh escalates the always-on enforce-if-present
	// baseline to strict — a missing (ts==0) or out-of-window timestamp is rejected.
	// Setting require_fresh without an hmac_secret is a fail-closed config error.
	// The two override durations follow the `0 = use the [ingest.freshness] global`
	// precedent.
	RequireFresh        bool     `toml:"require_fresh"`
	FreshnessWindow     Duration `toml:"freshness_window"`      // past tolerance (0 = global)
	FreshnessFutureSkew Duration `toml:"freshness_future_skew"` // future skew (0 = global)
}

// Source returns the registered alert source with this name (NC-1), if any.
func (c Config) Source(name string) (SourceConfig, bool) {
	for _, s := range c.Sources {
		if s.Name == name {
			return s, true
		}
	}
	return SourceConfig{}, false
}

// Default freshness-window parameters for the signed-alert ingest socket (NC-1).
// The 5m past tolerance is deliberately anchored to the ~300s artifact-proposal
// expiry so the product has a single, easy-to-reason-about freshness horizon; the
// 60s future-skew tolerance is standard NTP slack (and matches the per-minute rate
// granularity). Asymmetric on purpose: legitimate past latency (retries/queues)
// routinely exceeds legitimate future drift.
const (
	DefaultFreshnessWindow     = 5 * time.Minute
	DefaultFreshnessFutureSkew = 60 * time.Second
)

// IngestConfig groups server-side ingress hardening that is not per-source. Today
// it holds only the freshness (timestamp-window) defaults for the signed-alert
// socket; it never involves message content (the relay stays blind).
type IngestConfig struct {
	Freshness FreshnessConfig `toml:"freshness"`
	Webhook   WebhookConfig   `toml:"webhook"`
}

// FreshnessConfig is the global default timestamp-acceptance window for signed
// alerts (NC-1). It validates the `ts` that is already inside an HMAC source's
// signed preimage (protocol.AlertSigningBytes) — so a replayed alert carries an
// old, signed `ts` and is rejected. Per-source overrides on [[source]]
// (freshness_window / freshness_future_skew) take precedence; a non-positive value
// at either level falls back to the built-in default above.
type FreshnessConfig struct {
	Window     Duration `toml:"window"`      // max age of a signed ts (past tolerance, default 5m)
	FutureSkew Duration `toml:"future_skew"` // max lead of a signed ts over server time (default 60s)
}

// Default webhook guard caps for the per-room webhook socket (POST /webhook/{room}),
// the token-authenticated ingress twin of [[source]] alerts. They are deliberately
// MORE forgiving than the alert path's per-source 60/min + 20/hr because the webhook
// is a designed fan-in (CI, monitoring, deploy bots under one token): throttling a
// legitimate burst is worse than the bounded noise it prevents. The pre-auth ceiling
// is a coarse, global last-resort that meters only REJECTED requests.
const (
	DefaultWebhookRatePerMinute       = 120 // per-token authenticated rate
	DefaultWebhookSpawnPerHour        = 60  // per-token war-room spawn cap
	DefaultWebhookUnauthRatePerMinute = 600 // global pre-auth ceiling (rejected requests only)
)

// WebhookConfig is the global default rate/spawn guard for the webhook socket.
// RatePerMinute and SpawnPerHour are PER-TOKEN caps (overridable per room);
// UnauthRatePerMinute is a single GLOBAL pre-auth ceiling — deliberately not
// per-room, so it can never be a bucket an attacker targets to deny a specific
// sender. A non-positive value at any level falls back to the built-in default.
type WebhookConfig struct {
	RatePerMinute       int `toml:"rate_per_minute"`        // per-token rate (default 120)
	SpawnPerHour        int `toml:"spawn_per_hour"`         // per-token spawn (default 60)
	UnauthRatePerMinute int `toml:"unauth_rate_per_minute"` // global pre-auth ceiling (default 600)
}

// WebhookRate / WebhookSpawn resolve the effective PER-TOKEN webhook caps for a
// room: the per-room override if set (>0), else the global [ingest.webhook] default,
// else the built-in. WebhookUnauthRate resolves the GLOBAL pre-auth ceiling. All
// fall back to the built-in so the guard is never accidentally disabled by a zero.
func (c Config) WebhookRate(room RoomConfig) int {
	return resolveWebhookCap(room.WebhookRatePerMinute, c.Ingest.Webhook.RatePerMinute, DefaultWebhookRatePerMinute)
}

func (c Config) WebhookSpawn(room RoomConfig) int {
	return resolveWebhookCap(room.WebhookSpawnPerHour, c.Ingest.Webhook.SpawnPerHour, DefaultWebhookSpawnPerHour)
}

func (c Config) WebhookUnauthRate() int {
	return resolveWebhookCap(0, c.Ingest.Webhook.UnauthRatePerMinute, DefaultWebhookUnauthRatePerMinute)
}

func resolveWebhookCap(override, global, builtin int) int {
	if override > 0 {
		return override
	}
	if global > 0 {
		return global
	}
	return builtin
}

type ServerConfig struct {
	Addr string `toml:"addr"`

	// TLSCert/TLSKey exist ONLY so that a config which sets them can be REJECTED.
	// The relay does not terminate TLS: server.Run serves plain HTTP, and the
	// documented route to wss:// is a reverse proxy in front of it
	// (docs/self-hosting.md). These fields were once accepted and read by nothing,
	// so an operator who set them got plaintext ws:// with no error and no warning
	// while believing TLS was on — a security control the config offered and did
	// not honor. validate() now makes either one fatal. Deleting the fields would
	// be worse, not better: go-toml ignores unknown keys, so the setting would go
	// back to being silently swallowed. Do not wire them to a listener — adding
	// TLS termination is a feature, not a fix for the silent downgrade.
	TLSCert string `toml:"tls_cert"`
	TLSKey  string `toml:"tls_key"`

	// WebURL is the base URL of the browser join client. Auto-war-room (§1.3)
	// uses it to build the one-time /join links it hands back to invitees. When
	// empty the server falls back to the inbound request's own host.
	WebURL string `toml:"web_url"`
}

// RouteConfig is one alert-routing rule (§1.3). When an inbound webhook payload
// matches Match (all fields AND-ed), the server spawns an ephemeral break-glass
// war room, mints one-time invite links for each name in Invite, and returns
// them. Routes are evaluated in order; the first match wins.
//
// Match values are matched against the (possibly nested, dot-addressed) JSON
// payload: a value containing regex metacharacters is an anchored regex
// (^value$), otherwise it is exact string equality. See server/internal/route.
type RouteConfig struct {
	Match      map[string]string `toml:"match"`
	Action     string            `toml:"action"`      // currently only "break-glass"
	Invite     []string          `toml:"invite"`      // display names or @handles to invite
	TTL        Duration          `toml:"ttl"`         // hard lifetime of the spawned room
	RoomPrefix string            `toml:"room_prefix"` // room name is <prefix>-<8 hex>; default "inc"
	ReplyURL   string            `toml:"reply_url"`   // optional: POST the links to the operator's own system
}

// LimitsConfig is the per-connection inbound rate limit plus the bounds on the
// ephemeral artifact relay (§2.3).
type LimitsConfig struct {
	MessagesPerSecond float64 `toml:"messages_per_second"`
	Burst             int     `toml:"burst"`

	// MaxFileBytes caps a single artifact transfer. It is a CLIENT-evaluated policy
	// (like [[trust]]): a blind relay cannot see a transfer's size — it is sealed —
	// so the sender refuses larger artifacts at offer time and the receiver aborts
	// if its in-memory buffer would exceed it. The relay never stores a byte.
	MaxFileBytes int64 `toml:"max_file_bytes"`

	// MaxConcurrentTransfers bounds in-flight transfers per room. Unlike the size
	// cap this IS relay-enforced, because the relay sees the content-free transfer
	// ids — it just never sees what is being transferred.
	MaxConcurrentTransfers int `toml:"max_concurrent_transfers"`
}

// PersistenceConfig controls optional local-only message persistence. Off by
// default (the server is purely in-memory). When enabled, only ciphertext is
// stored — the server still cannot read it.
type PersistenceConfig struct {
	Enabled bool   `toml:"enabled"`
	Path    string `toml:"path"`
	History int    `toml:"history"` // messages to replay to a client on join

	// Key is the at-rest encryption secret for the SQLite store (§7). It is
	// optional here: prefer the NETHERCHAT_PERSIST_KEY environment variable
	// (supplied out of band, so it is not committed alongside config), and if
	// neither is set the server auto-generates a sidecar key file next to the DB.
	// See docs/encryption.md and server.persistSecret.
	Key string `toml:"key"`
}

// RoomConfig is per-room policy. Rooms absent from the config are created on
// demand with the zero value (open, no webhook, no TTL).
//
// Note: there is deliberately NO server-side exec policy. Command execution is an
// edge concern handled by `netherchat agent` against its own local allowlist; a
// blind relay must never run commands.
type RoomConfig struct {
	InviteOnly   bool   `toml:"invite_only"`
	Webhook      bool   `toml:"webhook"`
	WebhookToken string `toml:"webhook_token"`

	// Per-token webhook guard overrides (POST /webhook/{room}); 0/unset → the global
	// [ingest.webhook] default. They cap an authenticated token's request rate and
	// war-room spawns. The global pre-auth ceiling is not overridable per room.
	WebhookRatePerMinute int `toml:"webhook_rate_per_minute"`
	WebhookSpawnPerHour  int `toml:"webhook_spawn_per_hour"`

	TTL     Duration      `toml:"ttl"`
	Scuttle ScuttlePolicy `toml:"scuttle"`

	// Durable opts this room into the "case room" profile: its (still E2E-encrypted)
	// message history is persisted via the existing encrypted-SQLite store so it
	// survives the room going empty and the server restarting, for the life of a
	// review cycle — instead of the default, which keeps nothing. This is OPT-IN per
	// room; ephemeral-with-zero-persistence remains the default and the documented
	// norm. Persisted rows are ciphertext encrypted at rest exactly as the global
	// SQLite option (the relay still holds no room key and cannot read them); set
	// [persistence].path so the at-rest store is the encrypted SQLite database.
	Durable bool `toml:"durable"`

	// Status Beacon (§1.2): out-of-band, read-only incident status. BeaconToken
	// gates PUT/DELETE /beacon/<room> (opt-in: a room with no beacon_token — and no
	// webhook_token to fall back on — cannot have a beacon set). BeaconTTL caps how
	// long a beacon persists before it auto-purges (default 24h, hard max 24h). The
	// relay stores only ciphertext; the beacon key is never sent to it.
	BeaconToken string   `toml:"beacon_token"`
	BeaconTTL   Duration `toml:"beacon_ttl"`
}

// BeaconAuth returns the token that authorizes beacon writes for a room and
// whether the beacon is enabled at all (§1.2). A dedicated beacon_token wins;
// otherwise the room's webhook_token is reused. A room with neither cannot have a
// beacon set — beacons are strictly opt-in, never default-on.
func (c RoomConfig) BeaconAuth() (token string, enabled bool) {
	if c.BeaconToken != "" {
		return c.BeaconToken, true
	}
	if c.WebhookToken != "" {
		return c.WebhookToken, true
	}
	return "", false
}

// BeaconMaxTTL is the hard ceiling on a beacon's lifetime regardless of config.
const BeaconMaxTTL = 24 * time.Hour

// BeaconLifetime clamps a requested beacon TTL (seconds) to [1m, configured max],
// where the configured max is beacon_ttl (default 24h), itself capped at
// BeaconMaxTTL. A non-positive request falls back to 1h.
func (c RoomConfig) BeaconLifetime(requestedSeconds int) time.Duration {
	max := c.BeaconTTL.Std()
	if max <= 0 || max > BeaconMaxTTL {
		max = BeaconMaxTTL
	}
	d := time.Duration(requestedSeconds) * time.Second
	if d <= 0 {
		d = time.Hour
	}
	if d > max {
		d = max
	}
	if d < time.Minute {
		d = time.Minute
	}
	return d
}

// ScuttlePolicy is the per-room dead-man's switch (§1.6): the room burns its keys
// and closes itself when everyone walks away, so the default failure mode is the
// evidence destroying itself rather than a channel someone forgot to delete.
//
//	[rooms.ops.scuttle]
//	idle_after      = "30m"   # no activity for this long → scuttle (run /vanish + close)
//	owner_loss_burn = true    # the first joiner disconnecting (room non-empty) → scuttle
//	heartbeat       = "60s"   # how often the idle janitor checks
//
// A zero policy (no idle_after, owner_loss_burn=false) means the room never
// auto-scuttles; manual /scuttle still works. Unlike the room TTL (which expires
// a room outright), a scuttle first tells every client to ratchet its room key
// forward (forward secrecy) and renders an attestation, then closes the room.
type ScuttlePolicy struct {
	IdleAfter     Duration `toml:"idle_after"`
	OwnerLossBurn bool     `toml:"owner_loss_burn"`
	Heartbeat     Duration `toml:"heartbeat"`
}

// Active reports whether the policy does anything automatic (idle or owner-loss).
func (p ScuttlePolicy) Active() bool {
	return p.IdleAfter.Std() > 0 || p.OwnerLossBurn
}

// HeartbeatOrDefault is the idle-check interval: the configured heartbeat, or a
// 60s default. It is capped at IdleAfter so a long heartbeat can never make the
// room overstay its idle window by more than one tick.
func (p ScuttlePolicy) HeartbeatOrDefault() time.Duration {
	hb := p.Heartbeat.Std()
	if hb <= 0 {
		hb = defaultScuttleHeartbeat
	}
	if idle := p.IdleAfter.Std(); idle > 0 && hb > idle {
		hb = idle
	}
	return hb
}

const defaultScuttleHeartbeat = 60 * time.Second

// Duration is a time.Duration that unmarshals from a TOML string like "24h".
type Duration time.Duration

func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// Std returns the standard library duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// Default returns the configuration used when no file is provided.
func Default() Config {
	return Config{
		Server: ServerConfig{Addr: ":3000"},
		Limits: LimitsConfig{
			MessagesPerSecond:      20,
			Burst:                  40,
			MaxFileBytes:           protocol.DefaultMaxFileBytes,
			MaxConcurrentTransfers: protocol.DefaultMaxConcurrentTransfers,
		},
		Ingest: IngestConfig{
			Freshness: FreshnessConfig{
				Window:     Duration(DefaultFreshnessWindow),
				FutureSkew: Duration(DefaultFreshnessFutureSkew),
			},
			Webhook: WebhookConfig{
				RatePerMinute:       DefaultWebhookRatePerMinute,
				SpawnPerHour:        DefaultWebhookSpawnPerHour,
				UnauthRatePerMinute: DefaultWebhookUnauthRatePerMinute,
			},
		},
		Persistence: PersistenceConfig{Enabled: false, History: 100},
		Rooms:       map[string]RoomConfig{},
	}
}

// Load reads and parses a config file, filling unspecified fields with defaults.
func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Default(), err
	}
	cfg, err := Parse(b)
	if err != nil {
		return cfg, fmt.Errorf("parse %s: %w", path, err)
	}
	return cfg, nil
}

// Parse decodes a config from TOML bytes, filling unspecified fields with defaults
// and normalizing nonsensical values. It is the in-memory counterpart to Load: the
// server uses it to validate a proposed config without reading it from disk or
// applying it (the Terraform provider's POST /api/v1/config/validate, B1).
func Parse(b []byte) (Config, error) {
	cfg := Default()
	if err := toml.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	cfg.normalize()
	if err := cfg.validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// normalize repairs nonsensical values so the server always has a sane config.
func (c *Config) normalize() {
	if c.Server.Addr == "" {
		c.Server.Addr = ":3000"
	}
	if c.Limits.MessagesPerSecond <= 0 {
		c.Limits.MessagesPerSecond = 20
	}
	if c.Limits.Burst <= 0 {
		c.Limits.Burst = 40
	}
	if c.Limits.MaxFileBytes <= 0 {
		c.Limits.MaxFileBytes = protocol.DefaultMaxFileBytes
	}
	if c.Limits.MaxConcurrentTransfers <= 0 {
		c.Limits.MaxConcurrentTransfers = protocol.DefaultMaxConcurrentTransfers
	}
	if (c.Persistence.Enabled || c.AnyDurableRoom()) && c.Persistence.History <= 0 {
		c.Persistence.History = 100
	}
	// Repair the global freshness window the same way the limits above are repaired:
	// a non-positive value (unset, or nonsensical) reverts to the built-in default.
	if c.Ingest.Freshness.Window.Std() <= 0 {
		c.Ingest.Freshness.Window = Duration(DefaultFreshnessWindow)
	}
	if c.Ingest.Freshness.FutureSkew.Std() <= 0 {
		c.Ingest.Freshness.FutureSkew = Duration(DefaultFreshnessFutureSkew)
	}
	// Repair the webhook guard caps the same way: a non-positive global reverts to
	// the built-in default. Per-room overrides are resolved at use-site (0 = global).
	if c.Ingest.Webhook.RatePerMinute <= 0 {
		c.Ingest.Webhook.RatePerMinute = DefaultWebhookRatePerMinute
	}
	if c.Ingest.Webhook.SpawnPerHour <= 0 {
		c.Ingest.Webhook.SpawnPerHour = DefaultWebhookSpawnPerHour
	}
	if c.Ingest.Webhook.UnauthRatePerMinute <= 0 {
		c.Ingest.Webhook.UnauthRatePerMinute = DefaultWebhookUnauthRatePerMinute
	}
	if c.Rooms == nil {
		c.Rooms = map[string]RoomConfig{}
	}
}

// validate enforces fail-closed invariants that normalize() cannot repair by
// defaulting — configuration mistakes that must fail the operator's plan
// (Load, and POST /api/v1/config/validate) rather than run as security theater.
func (c *Config) validate() error {
	// A TLS mandate the relay cannot honor is the same class of mistake: the relay
	// terminates no TLS at all, so tls_cert/tls_key bought an operator plaintext
	// ws:// plus a false belief they were on wss://. Fail the config rather than
	// accept a security setting that does nothing.
	var tlsKeys []string
	if c.Server.TLSCert != "" {
		tlsKeys = append(tlsKeys, "tls_cert")
	}
	if c.Server.TLSKey != "" {
		tlsKeys = append(tlsKeys, "tls_key")
	}
	if len(tlsKeys) > 0 {
		return fmt.Errorf("[server]: tls_cert/tls_key are not honored — the relay does not terminate TLS, "+
			"it speaks plain WebSocket, and setting %s would have served plaintext ws:// with no warning. "+
			"Terminate TLS at a reverse proxy (Caddy, nginx, Traefik) in front of the relay instead; "+
			"see docs/self-hosting.md, \"TLS / wss://\"", strings.Join(tlsKeys, " and "))
	}
	for _, s := range c.Sources {
		// A freshness mandate over an UNSIGNED timestamp is meaningless: a token-only
		// source's `ts` is attacker-controllable, so require_fresh needs an
		// hmac_secret to bind the timestamp into a signature.
		if s.RequireFresh && s.HMACSecret == "" {
			return fmt.Errorf("source %q: require_fresh needs hmac_secret (its timestamp is otherwise unsigned)", s.Name)
		}
	}
	return nil
}

// Room returns the policy for a room (the zero value — fully open — if the room
// is not configured).
func (c Config) Room(name string) RoomConfig { return c.Rooms[name] }

// PersistRoom reports whether the relay should persist (and replay) a room's
// ciphertext history: when global persistence is enabled (legacy all-rooms
// behavior) OR the room is explicitly marked durable (the opt-in case-room
// profile). A default room with neither keeps nothing — zero persistence.
func (c Config) PersistRoom(room string) bool {
	return c.Persistence.Enabled || c.Room(room).Durable
}

// AnyDurableRoom reports whether at least one configured room opts into the
// durable case-room profile. The server uses it to open the message store even
// when global persistence is disabled.
func (c Config) AnyDurableRoom() bool {
	for _, rc := range c.Rooms {
		if rc.Durable {
			return true
		}
	}
	return false
}
