// Package invite manages one-time invite tokens that gate joining invite-only
// rooms. Tokens are random, single-use, optionally time-limited, and held only
// in memory (nothing is persisted).
package invite

import (
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"sync"
	"time"
)

// sweepInterval is how often the janitor reclaims expired tokens. Invites carry
// no tight timing promise — an expired token is already rejected by Redeem — so a
// coarse tick mirroring the hub's idle janitor is plenty; a tighter one would only
// add lock contention for no reclamation benefit.
const sweepInterval = 30 * time.Second

type entry struct {
	room    string
	expires time.Time // zero = no expiry
}

// Store is a concurrency-safe set of live invite tokens.
type Store struct {
	mu     sync.Mutex
	tokens map[string]entry
}

// New returns an empty store. It does not start the janitor; call Start to begin
// reclaiming expired tokens (so a Store built without a running relay spins no
// goroutine).
func New() *Store { return &Store{tokens: make(map[string]entry)} }

// Generate mints a one-time token for room, valid for ttl (0 = no expiry).
func (s *Store) Generate(room string, ttl time.Duration) (token string, expires time.Time) {
	var b [18]byte
	_, _ = rand.Read(b[:])
	token = base64.RawURLEncoding.EncodeToString(b[:])

	var exp time.Time
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}
	s.mu.Lock()
	s.tokens[token] = entry{room: room, expires: exp}
	s.mu.Unlock()
	return token, exp
}

// Redeem consumes a token for the given room. It returns true exactly once per
// valid token; expired or mismatched tokens are rejected (and expired ones
// removed).
func (s *Store) Redeem(token, room string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.tokens[token]
	if !ok {
		return false
	}
	if !e.expires.IsZero() && time.Now().After(e.expires) {
		delete(s.tokens, token)
		return false
	}
	if e.room != room {
		return false
	}
	delete(s.tokens, token)
	return true
}

// Start begins the background janitor that reclaims expired tokens. It is
// non-blocking and runs for the process lifetime (no stop channel), mirroring the
// hub idle-janitor and the ephemeral-room janitor.
func (s *Store) Start() { go s.janitor() }

// janitor periodically reclaims expired tokens. A reclaim is debug-logged only
// when it actually removed something, so the janitor stays quiet in the common
// case but a real reclaim is visible.
func (s *Store) janitor() {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()
	for range ticker.C {
		if n := s.sweep(time.Now()); n > 0 {
			slog.Debug("reclaimed expired invite tokens", "count", n)
		}
	}
}

// sweep removes every token whose expiry has passed as of now and returns how
// many it reclaimed. It uses the exact predicate Redeem uses
// (!expires.IsZero() && now.After(expires)) under the same mutex, so it can only
// ever delete a token Redeem would already reject — never a live, unexpired one.
// Zero-expiry tokens are never reclaimed. Reclaiming notifies nobody, so it can
// iterate-and-delete entirely under the lock.
func (s *Store) sweep(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	for token, e := range s.tokens {
		if !e.expires.IsZero() && now.After(e.expires) {
			delete(s.tokens, token)
			n++
		}
	}
	return n
}
