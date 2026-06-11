// Package tfconfig edits a netherchat.toml as config-as-code for the Terraform
// provider (B1). It holds the file as a generic tree so every section the provider
// does NOT manage (server, limits, persistence, …) survives a round-trip untouched
// — Terraform manages rooms, routes, trust pins, and action quorums, and leaves the
// rest exactly as it found it.
//
// It depends only on go-toml/v2 (not the Terraform SDK), so it is fast to test in
// isolation: `go test ./internal/tfconfig/` never compiles the SDK.
package tfconfig

import (
	"bytes"
	"fmt"
	"os"

	"github.com/pelletier/go-toml/v2"
)

// Config is a parsed netherchat.toml the provider mutates in place.
type Config struct{ root map[string]any }

// Empty returns a config with no sections.
func Empty() *Config { return &Config{root: map[string]any{}} }

// Parse decodes TOML bytes (an empty input yields an empty config).
func Parse(b []byte) (*Config, error) {
	root := map[string]any{}
	if len(bytes.TrimSpace(b)) > 0 {
		if err := toml.Unmarshal(b, &root); err != nil {
			return nil, fmt.Errorf("parse netherchat.toml: %w", err)
		}
	}
	return &Config{root: root}, nil
}

// Load reads and parses path; a missing file is an empty config, not an error.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Empty(), nil
	}
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Bytes renders the config back to TOML (map keys sorted, so output is stable).
func (c *Config) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	enc := toml.NewEncoder(&buf)
	enc.SetIndentTables(true)
	if err := enc.Encode(c.root); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Write renders and writes the config to path.
func (c *Config) Write(path string) error {
	b, err := c.Bytes()
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// --- rooms (rooms.<name> tables) --------------------------------------------

// Room is the managed shape of a [rooms.<name>] section.
type Room struct {
	InviteOnly   bool
	Webhook      bool
	WebhookToken string
	ExecEnabled  bool
	BeaconToken  string
	BeaconTTL    string
	TTL          string
}

// SetRoom upserts rooms.<name>, writing only the non-zero fields.
func (c *Config) SetRoom(name string, r Room) {
	m := map[string]any{}
	if r.InviteOnly {
		m["invite_only"] = true
	}
	if r.Webhook {
		m["webhook"] = true
	}
	if r.WebhookToken != "" {
		m["webhook_token"] = r.WebhookToken
	}
	if r.ExecEnabled {
		m["exec_enabled"] = true
	}
	if r.BeaconToken != "" {
		m["beacon_token"] = r.BeaconToken
	}
	if r.BeaconTTL != "" {
		m["beacon_ttl"] = r.BeaconTTL
	}
	if r.TTL != "" {
		m["ttl"] = r.TTL
	}
	c.table("rooms")[name] = m
}

// GetRoom returns rooms.<name> if present.
func (c *Config) GetRoom(name string) (Room, bool) {
	m, ok := c.table("rooms")[name].(map[string]any)
	if !ok {
		return Room{}, false
	}
	return Room{
		InviteOnly:   boolOf(m["invite_only"]),
		Webhook:      boolOf(m["webhook"]),
		WebhookToken: strOf(m["webhook_token"]),
		ExecEnabled:  boolOf(m["exec_enabled"]),
		BeaconToken:  strOf(m["beacon_token"]),
		BeaconTTL:    strOf(m["beacon_ttl"]),
		TTL:          strOf(m["ttl"]),
	}, true
}

// DeleteRoom removes rooms.<name>.
func (c *Config) DeleteRoom(name string) {
	delete(c.table("rooms"), name)
	c.pruneEmpty("rooms")
}

// --- trust ([[trust]] array, keyed by handle) -------------------------------

// Trust is the managed shape of a [[trust]] entry.
type Trust struct {
	Handle  string
	Fpr     string
	KeysURL string
}

// SetTrust upserts the [[trust]] entry with this handle.
func (c *Config) SetTrust(t Trust) {
	m := map[string]any{"handle": t.Handle}
	if t.Fpr != "" {
		m["fpr"] = t.Fpr
	}
	if t.KeysURL != "" {
		m["keys_url"] = t.KeysURL
	}
	c.setListItem("trust", "handle", t.Handle, m)
}

// GetTrust returns the [[trust]] entry with this handle.
func (c *Config) GetTrust(handle string) (Trust, bool) {
	if m := c.findListItem("trust", "handle", handle); m != nil {
		return Trust{Handle: handle, Fpr: strOf(m["fpr"]), KeysURL: strOf(m["keys_url"])}, true
	}
	return Trust{}, false
}

// DeleteTrust removes the [[trust]] entry with this handle.
func (c *Config) DeleteTrust(handle string) { c.deleteListItem("trust", "handle", handle) }

// --- routes ([[route]] array, keyed by room_prefix) -------------------------

// Route is the managed shape of a [[route]] entry. Terraform-managed routes are
// keyed by RoomPrefix (their resource id), so each must use a unique prefix.
type Route struct {
	Match      map[string]string
	Action     string
	Invite     []string
	TTL        string
	RoomPrefix string
	ReplyURL   string
}

// SetRoute upserts the [[route]] entry with this room_prefix.
func (c *Config) SetRoute(r Route) {
	m := map[string]any{"room_prefix": r.RoomPrefix}
	if len(r.Match) > 0 {
		mm := map[string]any{}
		for k, v := range r.Match {
			mm[k] = v
		}
		m["match"] = mm
	}
	if r.Action != "" {
		m["action"] = r.Action
	}
	if len(r.Invite) > 0 {
		inv := make([]any, len(r.Invite))
		for i, v := range r.Invite {
			inv[i] = v
		}
		m["invite"] = inv
	}
	if r.TTL != "" {
		m["ttl"] = r.TTL
	}
	if r.ReplyURL != "" {
		m["reply_url"] = r.ReplyURL
	}
	c.setListItem("route", "room_prefix", r.RoomPrefix, m)
}

// GetRoute returns the [[route]] entry with this room_prefix.
func (c *Config) GetRoute(roomPrefix string) (Route, bool) {
	m := c.findListItem("route", "room_prefix", roomPrefix)
	if m == nil {
		return Route{}, false
	}
	r := Route{RoomPrefix: roomPrefix, Action: strOf(m["action"]), TTL: strOf(m["ttl"]), ReplyURL: strOf(m["reply_url"])}
	if mm, ok := m["match"].(map[string]any); ok {
		r.Match = map[string]string{}
		for k, v := range mm {
			r.Match[k] = strOf(v)
		}
	}
	if inv, ok := m["invite"].([]any); ok {
		for _, v := range inv {
			r.Invite = append(r.Invite, strOf(v))
		}
	}
	return r, true
}

// DeleteRoute removes the [[route]] entry with this room_prefix.
func (c *Config) DeleteRoute(roomPrefix string) { c.deleteListItem("route", "room_prefix", roomPrefix) }

// --- action quorums (action.<name> tables) ----------------------------------

// SetActionQuorum upserts action.<action> quorum.
func (c *Config) SetActionQuorum(action string, quorum int) {
	c.table("action")[action] = map[string]any{"quorum": int64(quorum)}
}

// GetActionQuorum returns action.<action> quorum.
func (c *Config) GetActionQuorum(action string) (int, bool) {
	m, ok := c.table("action")[action].(map[string]any)
	if !ok {
		return 0, false
	}
	return intOf(m["quorum"]), true
}

// DeleteAction removes action.<action>.
func (c *Config) DeleteAction(action string) {
	delete(c.table("action"), action)
	c.pruneEmpty("action")
}

// --- internal map helpers ---------------------------------------------------

func (c *Config) table(name string) map[string]any {
	if m, ok := c.root[name].(map[string]any); ok {
		return m
	}
	m := map[string]any{}
	c.root[name] = m
	return m
}

func (c *Config) pruneEmpty(name string) {
	if m, ok := c.root[name].(map[string]any); ok && len(m) == 0 {
		delete(c.root, name)
	}
}

func (c *Config) listOf(name string) []map[string]any {
	switch v := c.root[name].(type) {
	case []map[string]any:
		return v
	case []any:
		out := make([]map[string]any, 0, len(v))
		for _, e := range v {
			if m, ok := e.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	default:
		return nil
	}
}

func (c *Config) findListItem(name, keyField, keyVal string) map[string]any {
	for _, e := range c.listOf(name) {
		if strOf(e[keyField]) == keyVal {
			return e
		}
	}
	return nil
}

func (c *Config) setListItem(name, keyField, keyVal string, item map[string]any) {
	list := c.listOf(name)
	for i, e := range list {
		if strOf(e[keyField]) == keyVal {
			list[i] = item
			c.root[name] = list
			return
		}
	}
	c.root[name] = append(list, item)
}

func (c *Config) deleteListItem(name, keyField, keyVal string) {
	list := c.listOf(name)
	out := make([]map[string]any, 0, len(list))
	for _, e := range list {
		if strOf(e[keyField]) == keyVal {
			continue
		}
		out = append(out, e)
	}
	if len(out) == 0 {
		delete(c.root, name)
		return
	}
	c.root[name] = out
}

func boolOf(v any) bool { b, _ := v.(bool); return b }
func strOf(v any) string {
	s, _ := v.(string)
	return s
}
func intOf(v any) int {
	switch n := v.(type) {
	case int64:
		return int(n)
	case int:
		return n
	case float64:
		return int(n)
	default:
		return 0
	}
}
