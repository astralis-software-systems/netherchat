// Package beacon holds the Status Beacon store (§1.2): at most one ciphertext blob
// per room — the single, bounded, TTL'd exception to the relay's zero-persistence
// posture. The relay stores ONLY ciphertext; the beacon key (HKDF of the room
// secret) is never sent to the server, so the relay cannot read a beacon's status.
// A beacon is overwritten on each set, deleted on /beacon clear, purged when its
// room scuttles, and auto-expires at its TTL.
package beacon

import (
	"sync"
	"time"
)

// Entry is one room's current beacon: the opaque ciphertext, when it was last set,
// and when it expires.
type Entry struct {
	Ciphertext []byte
	UpdatedAt  time.Time
	Expires    time.Time
}

// Store is a thread-safe, in-memory room→beacon map. It holds no key material and
// never inspects the ciphertext.
type Store struct {
	mu      sync.Mutex
	beacons map[string]Entry
}

// New returns an empty store.
func New() *Store { return &Store{beacons: make(map[string]Entry)} }

// Set stores (overwriting any previous) a room's beacon with a lifetime of ttl.
func (s *Store) Set(room string, ciphertext []byte, ttl time.Duration) {
	now := time.Now()
	s.mu.Lock()
	s.beacons[room] = Entry{
		Ciphertext: append([]byte(nil), ciphertext...),
		UpdatedAt:  now,
		Expires:    now.Add(ttl),
	}
	s.mu.Unlock()
}

// Get returns a room's beacon, or ok=false if absent or expired. Expired entries
// are purged lazily on read, so the TTL is enforced even without the janitor.
func (s *Store) Get(room string) (Entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.beacons[room]
	if !ok {
		return Entry{}, false
	}
	if time.Now().After(e.Expires) {
		delete(s.beacons, room)
		return Entry{}, false
	}
	return e, true
}

// Delete removes a room's beacon — the explicit /beacon clear, and the purge fired
// when a room scuttles or otherwise closes.
func (s *Store) Delete(room string) {
	s.mu.Lock()
	delete(s.beacons, room)
	s.mu.Unlock()
}

// Purge drops every expired entry (periodic memory hygiene; correctness is already
// guaranteed by Get's lazy expiry).
func (s *Store) Purge() {
	now := time.Now()
	s.mu.Lock()
	for room, e := range s.beacons {
		if now.After(e.Expires) {
			delete(s.beacons, room)
		}
	}
	s.mu.Unlock()
}
