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

// Config is the full server configuration.
type Config struct {
	Server      ServerConfig          `toml:"server"`
	Limits      LimitsConfig          `toml:"limits"`
	Persistence PersistenceConfig     `toml:"persistence"`
	Exec        ExecConfig            `toml:"exec"`
	Rooms       map[string]RoomConfig `toml:"rooms"`
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

// ExecConfig gates the remote /exec feature. Disabled by default; even when
// enabled, only the exact commands in Allow may run (never arbitrary shell),
// and only in rooms whose RoomConfig.ExecEnabled is true.
type ExecConfig struct {
	Enabled bool     `toml:"enabled"`
	Allow   []string `toml:"allow"`
}

// RoomConfig is per-room policy. Rooms absent from the config are created on
// demand with the zero value (open, no webhook, no TTL).
type RoomConfig struct {
	InviteOnly   bool     `toml:"invite_only"`
	ExecEnabled  bool     `toml:"exec_enabled"`
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
		Exec:        ExecConfig{Enabled: false},
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

// ExecAllowed reports whether the given command may run in the given room.
func (c Config) ExecAllowed(room, command string) bool {
	if !c.Exec.Enabled || !c.Room(room).ExecEnabled {
		return false
	}
	for _, allowed := range c.Exec.Allow {
		if allowed == command {
			return true
		}
	}
	return false
}
