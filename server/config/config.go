// Package config loads the Netherchat server configuration from netherchat.toml
// (config-as-code, R4). Everything policy-related — room access, webhooks,
// /exec, TTL, rate limits, persistence — is driven from here so the server's
// behavior is auditable in one file checked into the operator's repo.
package config

import (
	"fmt"
	"os"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// Config is the full server configuration. The [[trust]] table is the one
// exception to "server config": it is read only by CLIENTS for identity pinning
// (/whois). The relay never reads, forwards, or participates in trust decisions —
// trust is evaluated entirely client-side (FEATURE_ROADMAP_FREE.md §1.1).
type Config struct {
	Server      ServerConfig          `toml:"server"`
	Limits      LimitsConfig          `toml:"limits"`
	Persistence PersistenceConfig     `toml:"persistence"`
	Rooms       map[string]RoomConfig `toml:"rooms"`
	Routes      []RouteConfig         `toml:"route"`
	Trust       []TrustEntry          `toml:"trust"`
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

type ServerConfig struct {
	Addr    string `toml:"addr"`
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

// LimitsConfig is the per-connection inbound rate limit.
type LimitsConfig struct {
	MessagesPerSecond float64 `toml:"messages_per_second"`
	Burst             int     `toml:"burst"`
}

// PersistenceConfig controls optional local-only message persistence. Off by
// default (the server is purely in-memory). When enabled, only ciphertext is
// stored — the server still cannot read it.
type PersistenceConfig struct {
	Enabled bool   `toml:"enabled"`
	Path    string `toml:"path"`
	History int    `toml:"history"` // messages to replay to a client on join
}

// RoomConfig is per-room policy. Rooms absent from the config are created on
// demand with the zero value (open, no webhook, no TTL).
//
// Note: there is deliberately NO server-side exec policy. Command execution is an
// edge concern handled by `netherchat agent` against its own local allowlist; a
// blind relay must never run commands (FEATURE_ROADMAP_FREE.md §0.1).
type RoomConfig struct {
	InviteOnly   bool          `toml:"invite_only"`
	Webhook      bool          `toml:"webhook"`
	WebhookToken string        `toml:"webhook_token"`
	TTL          Duration      `toml:"ttl"`
	Scuttle      ScuttlePolicy `toml:"scuttle"`
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
		Server:      ServerConfig{Addr: ":3000"},
		Limits:      LimitsConfig{MessagesPerSecond: 20, Burst: 40},
		Persistence: PersistenceConfig{Enabled: false, History: 100},
		Rooms:       map[string]RoomConfig{},
	}
}

// Load reads and parses a config file, filling unspecified fields with defaults.
func Load(path string) (Config, error) {
	cfg := Default()
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := toml.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("parse %s: %w", path, err)
	}
	cfg.normalize()
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
	if c.Persistence.Enabled && c.Persistence.History <= 0 {
		c.Persistence.History = 100
	}
	if c.Rooms == nil {
		c.Rooms = map[string]RoomConfig{}
	}
}

// Room returns the policy for a room (the zero value — fully open — if the room
// is not configured).
func (c Config) Room(name string) RoomConfig { return c.Rooms[name] }
