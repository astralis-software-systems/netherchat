// Package hub holds the in-memory room and membership state for the Netherchat
// server. It is the heart of the blind relay: it tracks who is connected and
// routes opaque envelopes between them. It never inspects message contents and
// never holds any key material — by default nothing here is written to disk
// (R4: zero persistence). When a room empties, it is deleted and any per-room
// state simply evaporates.
package hub

import (
	"log/slog"
	"sync"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/server/config"
)

// Member is a connected participant from the hub's perspective. Send delivers an
// envelope to the member's connection; it must be non-blocking and safe to call
// from any goroutine. Close terminates the connection (used by the TTL janitor).
type Member struct {
	Info  protocol.Member
	Send  func(protocol.Envelope)
	Close func()
}

type room struct {
	members      map[string]*Member
	order        []string // join order; index 0 is the oldest still-present member
	lastActivity time.Time
}

// Hub is a thread-safe registry of rooms and their members.
type Hub struct {
	mu    sync.Mutex
	rooms map[string]*room
	cfg   config.Config
	log   *slog.Logger
}

// New returns a hub and starts the TTL janitor that expires idle rooms whose
// config sets a ttl.
func New(cfg config.Config, log *slog.Logger) *Hub {
	if log == nil {
		log = slog.Default()
	}
	h := &Hub{rooms: make(map[string]*room), cfg: cfg, log: log}
	go h.janitor()
	return h
}

// JoinResult tells the transport what follow-up actions to take after a member
// joins.
type JoinResult struct {
	Existing    []protocol.Member
	YouAreFirst bool
	Distributor *Member
}

// Join adds a member to a room (creating the room if needed).
func (h *Hub) Join(roomName string, m *Member) JoinResult {
	h.mu.Lock()
	defer h.mu.Unlock()

	r := h.rooms[roomName]
	if r == nil {
		r = &room{members: make(map[string]*Member)}
		h.rooms[roomName] = r
	}
	r.lastActivity = time.Now()

	res := JoinResult{YouAreFirst: len(r.members) == 0}
	for _, id := range r.order {
		if em := r.members[id]; em != nil {
			res.Existing = append(res.Existing, em.Info)
			if res.Distributor == nil {
				res.Distributor = em
			}
		}
	}

	r.members[m.Info.ID] = m
	r.order = append(r.order, m.Info.ID)
	return res
}

// Leave removes a member and reports whether the room is now empty (deleted).
func (h *Hub) Leave(roomName, memberID string) (roomEmpty bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.removeLocked(roomName, memberID)
}

func (h *Hub) removeLocked(roomName, memberID string) bool {
	r := h.rooms[roomName]
	if r == nil {
		return true
	}
	delete(r.members, memberID)
	for i, id := range r.order {
		if id == memberID {
			r.order = append(r.order[:i], r.order[i+1:]...)
			break
		}
	}
	if len(r.members) == 0 {
		delete(h.rooms, roomName)
		return true
	}
	return false
}

// ExpireRoom closes a room out of band: it removes the room, notifies every
// member with a plaintext system message, and terminates their connections. It
// is used by the ephemeral-room (break-glass) janitor when a war room hits its
// hard deadline, and is safe to call for a room that is already gone (no-op).
func (h *Hub) ExpireRoom(roomName, reason string) {
	h.mu.Lock()
	r := h.rooms[roomName]
	if r == nil {
		h.mu.Unlock()
		return
	}
	members := make([]*Member, 0, len(r.members))
	for _, m := range r.members {
		members = append(members, m)
	}
	delete(h.rooms, roomName)
	h.mu.Unlock()

	h.log.Info("room expired", "room", roomName, "members", len(members))
	closeMembers(members, reason)
}

// closeMembers sends a closing system notice to each member and then terminates
// the connection. Called outside the hub lock.
func closeMembers(members []*Member, reason string) {
	notice, _ := protocol.Encode(protocol.OpServerMessage, protocol.ServerMessage{
		Kind: "system",
		From: "server",
		Text: reason,
		At:   time.Now().Unix(),
	})
	for _, m := range members {
		if m.Send != nil {
			m.Send(notice)
		}
		if m.Close != nil {
			m.Close()
		}
	}
}

// IsEmpty reports whether a room has no members (or does not exist).
func (h *Hub) IsEmpty(roomName string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	r := h.rooms[roomName]
	return r == nil || len(r.members) == 0
}

// Touch records activity in a room, resetting its idle timer.
func (h *Hub) Touch(roomName string) {
	h.mu.Lock()
	if r := h.rooms[roomName]; r != nil {
		r.lastActivity = time.Now()
	}
	h.mu.Unlock()
}

// Broadcast delivers env to every member of the room except exceptID.
func (h *Hub) Broadcast(roomName, exceptID string, env protocol.Envelope) {
	for _, send := range h.recipients(roomName, exceptID) {
		send(env)
	}
}

// SendTo delivers env to a single member by ID.
func (h *Hub) SendTo(roomName, toID string, env protocol.Envelope) bool {
	h.mu.Lock()
	var send func(protocol.Envelope)
	if r := h.rooms[roomName]; r != nil {
		if m := r.members[toID]; m != nil {
			send = m.Send
		}
	}
	h.mu.Unlock()

	if send == nil {
		return false
	}
	send(env)
	return true
}

func (h *Hub) recipients(roomName, exceptID string) []func(protocol.Envelope) {
	h.mu.Lock()
	defer h.mu.Unlock()

	r := h.rooms[roomName]
	if r == nil {
		return nil
	}
	out := make([]func(protocol.Envelope), 0, len(r.members))
	for id, m := range r.members {
		if id == exceptID {
			continue
		}
		out = append(out, m.Send)
	}
	return out
}

// RoomStat is non-sensitive room metadata for the REST /rooms endpoint.
type RoomStat struct {
	Name    string `json:"name"`
	Members int    `json:"members"`
}

// Stats returns a snapshot of current rooms and their member counts.
func (h *Hub) Stats() []RoomStat {
	h.mu.Lock()
	defer h.mu.Unlock()

	stats := make([]RoomStat, 0, len(h.rooms))
	for name, r := range h.rooms {
		stats = append(stats, RoomStat{Name: name, Members: len(r.members)})
	}
	return stats
}

// janitor periodically expires idle rooms that have a configured TTL.
func (h *Hub) janitor() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		h.expireIdleRooms()
	}
}

func (h *Hub) expireIdleRooms() {
	now := time.Now()

	// Collect expired rooms and their members under lock; act outside it.
	type victim struct {
		name    string
		members []*Member
	}
	var victims []victim

	h.mu.Lock()
	for name, r := range h.rooms {
		ttl := h.cfg.Room(name).TTL.Std()
		if ttl <= 0 {
			continue
		}
		if now.Sub(r.lastActivity) <= ttl {
			continue
		}
		v := victim{name: name}
		for _, m := range r.members {
			v.members = append(v.members, m)
		}
		victims = append(victims, v)
		delete(h.rooms, name)
	}
	h.mu.Unlock()

	for _, v := range victims {
		h.log.Info("room expired (idle ttl)", "room", v.name, "members", len(v.members))
		closeMembers(v.members, "this room has expired (ttl) and is closing")
	}
}
