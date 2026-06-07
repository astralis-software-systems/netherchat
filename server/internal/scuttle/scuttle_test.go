package scuttle

import (
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
)

// fakeHub is a minimal scuttle.Hub for unit-testing the manager's policy logic
// without a real room registry.
type fakeHub struct {
	mu       sync.Mutex
	last     time.Time
	gone     bool
	reasons  []string
	scuttled chan string
}

func newFakeHub() *fakeHub {
	return &fakeHub{last: time.Now(), scuttled: make(chan string, 8)}
}

func (f *fakeHub) LastActivity(string) (time.Time, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.gone {
		return time.Time{}, false
	}
	return f.last, true
}

func (f *fakeHub) Scuttle(_, reason string) {
	f.mu.Lock()
	f.reasons = append(f.reasons, reason)
	f.mu.Unlock()
	f.scuttled <- reason
}

func (f *fakeHub) setGone() {
	f.mu.Lock()
	f.gone = true
	f.mu.Unlock()
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func mgr(h Hub, pol Policy) *Manager {
	return New(h, func(string) Policy { return pol }, quiet())
}

// awaitScuttle waits for a scuttle reason or fails on timeout.
func awaitScuttle(t *testing.T, h *fakeHub, timeout time.Duration) string {
	t.Helper()
	select {
	case r := <-h.scuttled:
		return r
	case <-time.After(timeout):
		t.Fatal("timed out waiting for scuttle")
		return ""
	}
}

// assertNoScuttle fails if a scuttle fires within the window.
func assertNoScuttle(t *testing.T, h *fakeHub, window time.Duration) {
	t.Helper()
	select {
	case r := <-h.scuttled:
		t.Fatalf("unexpected scuttle: %s", r)
	case <-time.After(window):
	}
}

// TestIdleScuttle proves the idle janitor burns a quiet room after idle_after.
func TestIdleScuttle(t *testing.T) {
	h := newFakeHub()
	m := mgr(h, Policy{IdleAfter: 60 * time.Millisecond, Heartbeat: 15 * time.Millisecond})
	m.Start("ops")
	if r := awaitScuttle(t, h, 2*time.Second); r != protocol.ScuttleIdle {
		t.Fatalf("idle scuttle reason = %q, want %q", r, protocol.ScuttleIdle)
	}
}

// TestActivityDefersIdle proves activity (a fresh lastActivity) keeps the room
// alive, and that Stop ends the janitor.
func TestActivityDefersIdle(t *testing.T) {
	h := newFakeHub()
	m := mgr(h, Policy{IdleAfter: 80 * time.Millisecond, Heartbeat: 15 * time.Millisecond})
	m.Start("ops")
	// Keep touching activity for a while; the room must not scuttle.
	done := time.After(200 * time.Millisecond)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
loop:
	for {
		select {
		case <-done:
			break loop
		case <-tick.C:
			h.mu.Lock()
			h.last = time.Now()
			h.mu.Unlock()
		case r := <-h.scuttled:
			t.Fatalf("scuttled while active: %s", r)
		}
	}
	m.Stop("ops")
	assertNoScuttle(t, h, 150*time.Millisecond)
}

// TestRoomGoneStopsJanitor proves the janitor exits (no scuttle) when the room
// disappears on its own (everyone left).
func TestRoomGoneStopsJanitor(t *testing.T) {
	h := newFakeHub()
	m := mgr(h, Policy{IdleAfter: time.Hour, Heartbeat: 15 * time.Millisecond})
	m.Start("ops")
	h.setGone()
	assertNoScuttle(t, h, 150*time.Millisecond)
}

// TestOwnerLossBurn proves OwnerLeft scuttles iff the policy opts in.
func TestOwnerLossBurn(t *testing.T) {
	h := newFakeHub()
	mgr(h, Policy{OwnerLossBurn: true}).OwnerLeft("ops")
	if r := awaitScuttle(t, h, time.Second); r != protocol.ScuttleOwnerLoss {
		t.Fatalf("owner-loss reason = %q, want %q", r, protocol.ScuttleOwnerLoss)
	}

	h2 := newFakeHub()
	mgr(h2, Policy{OwnerLossBurn: false}).OwnerLeft("ops")
	assertNoScuttle(t, h2, 100*time.Millisecond)
}

// TestArmFires proves /scuttle arm burns after the countdown, and Stop cancels it.
func TestArmFires(t *testing.T) {
	h := newFakeHub()
	m := mgr(h, Policy{})
	m.Arm("ops", 50*time.Millisecond)
	if r := awaitScuttle(t, h, time.Second); r != protocol.ScuttleArmed {
		t.Fatalf("armed reason = %q, want %q", r, protocol.ScuttleArmed)
	}

	h2 := newFakeHub()
	m2 := mgr(h2, Policy{})
	m2.Arm("ops", 80*time.Millisecond)
	m2.Stop("ops") // cancel before it fires
	assertNoScuttle(t, h2, 200*time.Millisecond)
}
