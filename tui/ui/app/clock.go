package app

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// Incident clock (A1) — TUI side. The clock state lives in the client; here we
// drive the commands, the header display, and a 1s refresh tick that runs only
// while a clock is active.

// clockTickMsg refreshes the header clock once a second.
type clockTickMsg time.Time

func clockTick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return clockTickMsg(t) })
}

// anyClockRunning reports whether any joined room has a running incident clock.
func (m *Model) anyClockRunning() bool {
	for _, r := range m.session {
		if r.client == nil {
			continue
		}
		if _, running, ok := r.client.ClockElapsed(); ok && running {
			return true
		}
	}
	return false
}

// runClock implements /clock [start|stop|status] (A1).
func (m *Model) runClock(r *room, arg string) {
	if !m.connected(r) {
		return
	}
	switch strings.ToLower(strings.TrimSpace(arg)) {
	case "start":
		r.client.ClockStart()
	case "stop":
		r.client.ClockStop()
	case "", "status":
		d, running, ok := r.client.ClockElapsed()
		if !ok {
			m.addSystem("⏱ no incident clock running — /clock start to begin")
			return
		}
		state := "stopped (resolved)"
		if running {
			state = "running"
		}
		m.addSystem(fmt.Sprintf("⏱ incident clock: %s (%s)", formatClock(d), state))
	default:
		m.addError("usage: /clock [start|stop]")
	}
}

// clockSegment returns the " · ⏱ HH:MM:SS" header segment for the active room, or
// "" when no clock is running.
func (m *Model) clockSegment(r *room) string {
	if r == nil || r.client == nil {
		return ""
	}
	d, _, ok := r.client.ClockElapsed()
	if !ok {
		return ""
	}
	return " · ⏱ " + formatClock(d)
}

// formatClock renders a duration as HH:MM:SS (hours uncapped).
func formatClock(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	t := int(d.Seconds())
	return fmt.Sprintf("%02d:%02d:%02d", t/3600, (t%3600)/60, t%60)
}
