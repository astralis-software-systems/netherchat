// Package scuttle implements Netherchat's dead-man's switch (§1.6): the per-room
// policy that burns a room's keys and closes it when everyone walks away, so the
// default failure mode is the evidence destroying itself rather than a channel
// someone forgot to delete.
//
// The Manager owns one lightweight goroutine per room that has an idle policy
// (started when the first member joins, stopped when the room empties), plus the
// one-shot timers behind /scuttle arm. It is deliberately decoupled from the hub:
// it reads room idle state and triggers the burn through the small Hub interface,
// so it can be unit-tested with a fake hub and the hub need not know scuttle
// policy exists.
package scuttle

import (
	"log/slog"
	"sync"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
)

// Hub is the slice of the server's room registry the Manager needs. The real
// *hub.Hub satisfies it.
type Hub interface {
	// LastActivity returns the room's last-activity time; ok is false once the
	// room no longer exists (the janitor's signal to stop).
	LastActivity(room string) (t time.Time, ok bool)
	// Scuttle broadcasts the burn to the room and closes it. reason is a
	// protocol.Scuttle* value.
	Scuttle(room, reason string)
}

// Policy is a room's effective scuttle configuration, in stdlib durations. It is
// the transport-agnostic mirror of config.ScuttlePolicy.
type Policy struct {
	IdleAfter     time.Duration
	OwnerLossBurn bool
	Heartbeat     time.Duration // idle-check interval; assumed already defaulted/capped
}

// Manager coordinates the per-room idle janitors and armed countdowns.
type Manager struct {
	hub      Hub
	policyOf func(room string) Policy
	log      *slog.Logger

	mu    sync.Mutex
	idle  map[string]chan struct{} // room -> stop signal for its idle janitor
	armed map[string]*time.Timer   // room -> pending /scuttle arm timer
}

// New returns a Manager. policyOf resolves a room's effective policy (already
// defaulted, e.g. via config.ScuttlePolicy.HeartbeatOrDefault).
func New(h Hub, policyOf func(room string) Policy, log *slog.Logger) *Manager {
	if log == nil {
		log = slog.Default()
	}
	return &Manager{
		hub:      h,
		policyOf: policyOf,
		log:      log,
		idle:     make(map[string]chan struct{}),
		armed:    make(map[string]*time.Timer),
	}
}

// Start begins watching a room for idle scuttle. It is called when the first
// member joins and is idempotent: a second call while a janitor already runs is a
// no-op. Rooms with no idle_after get no goroutine (owner-loss and arm need no
// polling).
func (m *Manager) Start(room string) {
	pol := m.policyOf(room)
	if pol.IdleAfter <= 0 {
		return
	}
	m.mu.Lock()
	if _, running := m.idle[room]; running {
		m.mu.Unlock()
		return
	}
	stop := make(chan struct{})
	m.idle[room] = stop
	m.mu.Unlock()

	go m.idleLoop(room, pol, stop)
}

// Stop cancels a room's idle janitor and any armed countdown. Called when the
// room empties (or is being torn down). Safe to call for an unwatched room.
func (m *Manager) Stop(room string) {
	m.mu.Lock()
	if stop, ok := m.idle[room]; ok {
		close(stop)
		delete(m.idle, room)
	}
	if t, ok := m.armed[room]; ok {
		t.Stop()
		delete(m.armed, room)
	}
	m.mu.Unlock()
}

// OwnerLeft is called when the room's founding connection (the first joiner)
// disconnects while the room is still non-empty. If owner_loss_burn is set, the
// room scuttles.
func (m *Manager) OwnerLeft(room string) {
	if m.policyOf(room).OwnerLossBurn {
		m.log.Info("owner-loss scuttle", "room", room)
		m.hub.Scuttle(room, protocol.ScuttleOwnerLoss)
	}
}

// Arm schedules a one-shot scuttle after d (the /scuttle arm path). A fresh arm
// replaces any pending one. The countdown notice to participants is broadcast by
// the caller (the relay) so it is visible immediately; this only owns the timer.
func (m *Manager) Arm(room string, d time.Duration) {
	if d <= 0 {
		return
	}
	m.mu.Lock()
	if prev, ok := m.armed[room]; ok {
		prev.Stop()
	}
	m.armed[room] = time.AfterFunc(d, func() {
		m.mu.Lock()
		delete(m.armed, room)
		m.mu.Unlock()
		m.hub.Scuttle(room, protocol.ScuttleArmed)
	})
	m.mu.Unlock()
}

// idleLoop polls a room's idle time at the heartbeat interval and scuttles it
// once it has been quiet longer than idle_after. It exits when Stop closes its
// channel or the room disappears (LastActivity ok=false) — whichever comes first.
func (m *Manager) idleLoop(room string, pol Policy, stop <-chan struct{}) {
	ticker := time.NewTicker(pol.Heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			last, ok := m.hub.LastActivity(room)
			if !ok {
				m.forget(room)
				return
			}
			if time.Since(last) >= pol.IdleAfter {
				m.forget(room)
				m.log.Info("idle scuttle", "room", room, "idle_after", pol.IdleAfter)
				m.hub.Scuttle(room, protocol.ScuttleIdle)
				return
			}
		}
	}
}

// forget drops the room's idle-janitor registration (the goroutine is exiting on
// its own, so we do not close the channel here).
func (m *Manager) forget(room string) {
	m.mu.Lock()
	delete(m.idle, room)
	m.mu.Unlock()
}
