package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefault(t *testing.T) {
	c := Default()
	if c.Server.Addr != ":3000" {
		t.Errorf("default addr = %q", c.Server.Addr)
	}
	if c.Limits.MessagesPerSecond != 20 || c.Limits.Burst != 40 {
		t.Errorf("default limits = %+v", c.Limits)
	}
	if c.Persistence.Enabled {
		t.Error("persistence should default off")
	}
	if c.Exec.Enabled {
		t.Error("exec should default off")
	}
}

func TestLoad(t *testing.T) {
	toml := `
[server]
addr = ":9000"

[limits]
messages_per_second = 5

[exec]
enabled = true
allow = ["uptime", "df -h"]

[rooms.ops]
invite_only = true
exec_enabled = true

[rooms.alerts]
webhook = true
webhook_token = "secret"
ttl = "24h"
`
	path := filepath.Join(t.TempDir(), "netherchat.toml")
	if err := os.WriteFile(path, []byte(toml), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if c.Server.Addr != ":9000" {
		t.Errorf("addr = %q", c.Server.Addr)
	}
	if c.Limits.MessagesPerSecond != 5 {
		t.Errorf("mps = %v", c.Limits.MessagesPerSecond)
	}
	if c.Limits.Burst != 40 {
		t.Errorf("burst should keep default 40, got %d", c.Limits.Burst)
	}
	if !c.Room("ops").InviteOnly {
		t.Error("ops should be invite_only")
	}
	if c.Room("alerts").TTL.Std() != 24*time.Hour {
		t.Errorf("alerts ttl = %v", c.Room("alerts").TTL.Std())
	}
	if c.Room("alerts").WebhookToken != "secret" {
		t.Errorf("alerts token = %q", c.Room("alerts").WebhookToken)
	}
	if !c.Room("nonexistent").InviteOnly == false {
		// zero value: open room
	}
}

func TestExecAllowed(t *testing.T) {
	c := Default()
	c.Exec.Enabled = true
	c.Exec.Allow = []string{"uptime"}
	c.Rooms = map[string]RoomConfig{"ops": {ExecEnabled: true}}

	if !c.ExecAllowed("ops", "uptime") {
		t.Error("uptime should be allowed in ops")
	}
	if c.ExecAllowed("ops", "rm -rf /") {
		t.Error("non-allowlisted command must be rejected")
	}
	if c.ExecAllowed("general", "uptime") {
		t.Error("exec must be rejected in a room without exec_enabled")
	}

	c.Exec.Enabled = false
	if c.ExecAllowed("ops", "uptime") {
		t.Error("exec must be rejected when globally disabled")
	}
}
