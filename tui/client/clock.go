package client

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/record"
)

// Incident clock (A1). The clock is purely CLIENT-SIDE state: it needs no new
// opcode. /clock start broadcasts an ordinary E2E message that every member
// recognizes and uses to sync its own clock; the same for stop. When a seal is
// initiated, the elapsed timing is captured into the sealed record as two signed
// note entries (so MTTR is record metadata, never content that leaks).

const (
	clockStartMsg     = "⏱ incident clock started"
	clockStopPrefix   = "⏱ incident clock stopped — elapsed: "
	clockNoteStarted  = "Incident started: "
	clockNoteDuration = "Incident duration: "
)

// ClockStart starts the incident clock for this room (if not already running),
// broadcasts the marker message so other members sync, and emits a local echo. It
// is idempotent — starting an already-running clock is a no-op.
func (c *Client) ClockStart() {
	c.mu.Lock()
	if !c.clockStart.IsZero() {
		c.mu.Unlock()
		return
	}
	now := time.Now()
	c.clockStart = now
	c.clockStop = time.Time{}
	c.clockNotesAdded = false
	c.mu.Unlock()

	_ = c.sealAndSend(protocol.OpMessage, []byte(clockStartMsg))
	c.emit(EvClockStart{Actor: c.name, Fpr: c.Fingerprint(), Self: true, At: now})
}

// ClockStop stops the clock (marking the resolution time), broadcasts the elapsed
// marker, and emits a local echo. No-op if the clock was never started or is
// already stopped.
func (c *Client) ClockStop() {
	c.mu.Lock()
	if c.clockStart.IsZero() || !c.clockStop.IsZero() {
		c.mu.Unlock()
		return
	}
	now := time.Now()
	c.clockStop = now
	elapsed := now.Sub(c.clockStart)
	c.mu.Unlock()

	_ = c.sealAndSend(protocol.OpMessage, []byte(clockStopPrefix+formatHMS(elapsed)))
	c.emit(EvClockStop{Actor: c.name, Fpr: c.Fingerprint(), ElapsedSeconds: int(elapsed.Seconds()), Self: true, At: now})
}

// ClockElapsed reports the incident clock's elapsed time. ok is false when no clock
// has started; running is false once it has been stopped (the value is then frozen
// at the resolution time).
func (c *Client) ClockElapsed() (elapsed time.Duration, running, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.clockStart.IsZero() {
		return 0, false, false
	}
	if c.clockStop.IsZero() {
		return time.Since(c.clockStart), true, true
	}
	return c.clockStop.Sub(c.clockStart), false, true
}

// recognizeClock inspects a decrypted message; if it is a clock marker it syncs
// this client's clock to it, emits the typed event, and returns true (so the caller
// does NOT also surface it as an ordinary chat message). at is the message time.
func (c *Client) recognizeClock(senderName, fpr, text string, at time.Time) bool {
	switch {
	case text == clockStartMsg:
		c.mu.Lock()
		if c.clockStart.IsZero() {
			c.clockStart = at
			c.clockStop = time.Time{}
			c.clockNotesAdded = false
		}
		c.mu.Unlock()
		c.emit(EvClockStart{Actor: senderName, Fpr: fpr, At: at})
		return true
	case strings.HasPrefix(text, clockStopPrefix):
		elapsed := parseHMS(strings.TrimPrefix(text, clockStopPrefix))
		c.mu.Lock()
		if c.clockStop.IsZero() {
			c.clockStop = at
		}
		c.mu.Unlock()
		c.emit(EvClockStop{Actor: senderName, Fpr: fpr, ElapsedSeconds: int(elapsed.Seconds()), At: at})
		return true
	}
	return false
}

// appendClockNotes appends the two incident-timing note entries to the record chain
// when a seal is initiated, so the duration falls out of the timeline automatically
// (A1). Called once per clock session; subsequent seals do not re-add them.
func (c *Client) appendClockNotes() {
	c.mu.Lock()
	if c.clockStart.IsZero() || c.clockNotesAdded {
		c.mu.Unlock()
		return
	}
	start := c.clockStart
	stop := c.clockStop
	c.clockNotesAdded = true
	c.mu.Unlock()

	var elapsed time.Duration
	state := "ongoing"
	if stop.IsZero() {
		elapsed = time.Since(start)
	} else {
		elapsed = stop.Sub(start)
		state = "resolved"
	}
	_ = c.appendRecord(record.KindNote, "", clockNoteStarted+start.UTC().Format(time.RFC3339))
	_ = c.appendRecord(record.KindNote, "", fmt.Sprintf("%s%s (%s)", clockNoteDuration, formatHMS(elapsed), state))
}

// clearClockLocked resets the clock; caller holds c.mu. Called on /vanish.
func (c *Client) clearClockLocked() {
	c.clockStart = time.Time{}
	c.clockStop = time.Time{}
	c.clockNotesAdded = false
}

// formatHMS renders a duration as HH:MM:SS (hours not capped).
func formatHMS(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	total := int(d.Seconds())
	return fmt.Sprintf("%02d:%02d:%02d", total/3600, (total%3600)/60, total%60)
}

// parseHMS parses an HH:MM:SS string back to a duration (best effort; 0 on garbage).
func parseHMS(s string) time.Duration {
	parts := strings.Split(strings.TrimSpace(s), ":")
	if len(parts) != 3 {
		return 0
	}
	h, e1 := strconv.Atoi(parts[0])
	m, e2 := strconv.Atoi(parts[1])
	sec, e3 := strconv.Atoi(parts[2])
	if e1 != nil || e2 != nil || e3 != nil {
		return 0
	}
	return time.Duration(h*3600+m*60+sec) * time.Second
}
