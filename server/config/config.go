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
	InviteOnly   bool     `toml:"invite_only"`
	Webhook      bool     `toml:"webhook"`
	WebhookToken string   `toml:"webhook_token"`
	TTL          Duration `toml:"ttl"`
}

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
