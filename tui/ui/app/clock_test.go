package app

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/tui/client"
)

// TestHeaderShowsClock proves the incident clock appears in the TUI header (A1).
func TestHeaderShowsClock(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), discardLogger()))
	defer ts.Close()
	c := connectCore(t, ts.URL, "ops", "alice")
	waitKeyReady(t, c)

	m := newModel(ts.URL, "alice", "", "ops", "")
	m.resize(120, 40)
	r := m.session["ops"]
	r.client, r.connected, r.keyReady = c, true, true

	if strings.Contains(m.headerView(), "⏱") {
		t.Fatal("no clock should show before /clock start")
	}
	c.ClockStart()
	if !strings.Contains(m.headerView(), "⏱") {
		t.Fatalf("header should show the incident clock after start:\n%s", m.headerView())
	}
}

// TestBreakGlassAutoClock proves the clock auto-starts when a break-glass room's
// key is ready (A1).
func TestBreakGlassAutoClock(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), discardLogger()))
	defer ts.Close()
	c := connectCore(t, ts.URL, "ops", "alice")
	waitKeyReady(t, c)

	m := newModel(ts.URL, "alice", "", "ops", "")
	r := m.session["ops"]
	r.client, r.connected, r.autoClock = c, true, true

	m.handleRoomEvent("ops", client.EvKeyReady{Epoch: 0})

	if _, _, ok := c.ClockElapsed(); !ok {
		t.Fatal("a break-glass room must auto-start the incident clock on key ready")
	}
	if r.autoClock {
		t.Fatal("autoClock should be cleared after firing")
	}
}
