// Package invite manages one-time invite tokens that gate joining invite-only
// rooms. Tokens are random, single-use, optionally time-limited, and held only
// in memory (nothing is persisted).
package invite

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

type entry struct {
	room    string
	expires time.Time // zero = no expiry
}

// Store is a concurrency-safe set of live invite tokens.
type Store struct {
	mu     sync.Mutex
	tokens map[string]entry
}

// New returns an empty store.
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
