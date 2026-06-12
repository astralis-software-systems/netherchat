// Package ephemeral tracks dynamically-created, invite-only rooms that vanish at
// a hard deadline — the backing store for the /break-glass war room. Unlike the
// rooms in netherchat.toml (static config, idle-based TTL), these are created at
// runtime by a connected member, are always invite-only, and are closed at an
// absolute time whether or not they are still in use.
//
// The registry holds only routing/lifecycle metadata: a room name, its deadline,
// and who created it. It never holds keys or message content — like the rest of
// the server, it is part of the blind relay.
package ephemeral

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"sync"
	"time"
)

// Bounds on a war room's lifetime. The client validates too, but the server is
// authoritative: a hostile or buggy client cannot create an immortal room.
const (
	MinTTL      = time.Minute
	MaxTTL      = 7 * 24 * time.Hour
	MaxInvitees = 64

	sweepInterval = time.Second // how often the janitor checks deadlines
)

// Room is a live ephemeral room's metadata.
type Room struct {
	Name      string
	CreatedBy string
	Created   time.Time
	Deadline  time.Time

	// Notice is an optional marked-plaintext, metadata-only line delivered to each
	// member as they join (NC-1 alert ingress: "why this war room opened"). It lives
	// only in memory and dies with the room. It is never message content.
	Notice string
}

// Registry is a concurrency-safe set of live ephemeral rooms. The zero value is
// not usable; call New.
type Registry struct {
	mu       sync.Mutex
	rooms    map[string]Room
	onExpire func(room, reason string)
	log      *slog.Logger
}

// New returns an empty registry. Call Start to begin expiring rooms at their
// deadlines.
func New(log *slog.Logger) *Registry {
	if log == nil {
		log = slog.Default()
	}
	return &Registry{rooms: make(map[string]Room), log: log}
}

// Start begins the deadline janitor. onExpire is invoked once per room when its
// deadline passes (wired to hub.ExpireRoom, which closes the room's members);
// the registry then forgets the room. Start is non-blocking.
func (r *Registry) Start(onExpire func(room, reason string)) {
	r.mu.Lock()
	r.onExpire = onExpire
	r.mu.Unlock()
	go r.janitor()
}

// ClampTTL coerces a requested duration into [MinTTL, MaxTTL].
func ClampTTL(d time.Duration) time.Duration {
	switch {
	case d < MinTTL:
		return MinTTL
	case d > MaxTTL:
		return MaxTTL
	default:
		return d
	}
}

// Create registers a new ephemeral room named "war-<8 hex>". It is the
// break-glass default; see CreateNamed for the prefix-controlled variant.
func (r *Registry) Create(ttl time.Duration, by string) Room {
	return r.CreateNamed(ttl, by, "war")
}

// CreateNamed registers a new ephemeral room with a fresh, unguessable name of
// the form "<prefix>-<8 hex>" and a hard deadline of now+ttl. ttl is clamped
// into [MinTTL, MaxTTL]. Auto-war-room (§1.3) uses the per-route prefix (default
// "inc"); break-glass uses "war".
func (r *Registry) CreateNamed(ttl time.Duration, by, prefix string) Room {
	if prefix == "" {
		prefix = "war"
	}
	ttl = ClampTTL(ttl)
	now := time.Now()
	room := Room{CreatedBy: by, Created: now, Deadline: now.Add(ttl)}

	r.mu.Lock()
	defer r.mu.Unlock()
	for {
		room.Name = newRoomName(prefix)
		if _, taken := r.rooms[room.Name]; !taken {
			break
		}
	}
	r.rooms[room.Name] = room
	return room
}

// CreateNamedNotice is CreateNamed plus a marked-plaintext, metadata-only notice
// delivered to each member as they join (NC-1). An empty notice behaves exactly
// like CreateNamed.
func (r *Registry) CreateNamedNotice(ttl time.Duration, by, prefix, notice string) Room {
	room := r.CreateNamed(ttl, by, prefix)
	if notice != "" {
		r.mu.Lock()
		if cur, ok := r.rooms[room.Name]; ok {
			cur.Notice = notice
			r.rooms[room.Name] = cur
			room = cur
		}
		r.mu.Unlock()
	}
	return room
}

// Get returns the room's metadata if it is a live ephemeral room.
func (r *Registry) Get(name string) (Room, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	room, ok := r.rooms[name]
	return room, ok
}

// janitor closes rooms whose deadline has passed. A 1s tick keeps a war room's
// "vanishes at 16:00" promise tight (a 4h room is not allowed to overstay by the
// 30s of the hub's idle janitor).
func (r *Registry) janitor() {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()
	for range ticker.C {
		r.sweep(time.Now())
	}
}

func (r *Registry) sweep(now time.Time) {
	r.mu.Lock()
	var expired []string
	for name, room := range r.rooms {
		if now.After(room.Deadline) {
			expired = append(expired, name)
			delete(r.rooms, name)
		}
	}
	onExpire := r.onExpire
	r.mu.Unlock()

	for _, name := range expired {
		r.log.Info("war room expired (break-glass ttl)", "room", name)
		if onExpire != nil {
			onExpire(name, "this break-glass war room has reached its TTL and is closing")
		}
	}
}

// newRoomName returns an unguessable ephemeral room name like "war-3f9a2b71" or
// "inc-3f9a2b71" — the prefix plus 8 hex characters (4 random bytes).
func newRoomName(prefix string) string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return prefix + "-" + hex.EncodeToString(b[:])
}
