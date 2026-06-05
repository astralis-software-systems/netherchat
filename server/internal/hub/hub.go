// Package hub holds the in-memory room and membership state for the Netherchat
// server. It is the heart of the blind relay: it tracks who is connected and
// routes opaque envelopes between them. It never inspects message contents and
// never holds any key material — by default nothing here is written to disk
// (R4: zero persistence). When a room empties, it is deleted and any per-room
// state simply evaporates.
package hub

import (
	"sync"

	"github.com/salehkreiner/netherchat/protocol"
)

// Member is a connected participant from the hub's perspective. Send delivers an
// envelope to the member's connection; it must be non-blocking and safe to call
// from any goroutine (the transport layer guarantees this).
type Member struct {
	Info protocol.Member
	Send func(protocol.Envelope)
}

type room struct {
	members map[string]*Member
	order   []string // join order; index 0 is the oldest still-present member
}

// Hub is a thread-safe registry of rooms and their members.
type Hub struct {
	mu    sync.Mutex
	rooms map[string]*room
}

// New returns an empty hub.
func New() *Hub { return &Hub{rooms: make(map[string]*room)} }

// JoinResult tells the transport what follow-up actions to take after a member
// joins: whom to show in the Welcome, whether this member must mint the room key
// (YouAreFirst), and which existing member should distribute the current room
// key to the newcomer (Distributor, nil when YouAreFirst).
type JoinResult struct {
	Existing    []protocol.Member
	YouAreFirst bool
	Distributor *Member
}

// Join adds a member to a room (creating the room if needed) and returns the
// information the transport needs to complete the handshake.
func (h *Hub) Join(roomName string, m *Member) JoinResult {
	h.mu.Lock()
	defer h.mu.Unlock()

	r := h.rooms[roomName]
	if r == nil {
		r = &room{members: make(map[string]*Member)}
		h.rooms[roomName] = r
	}

	res := JoinResult{YouAreFirst: len(r.members) == 0}
	// Snapshot existing members in join order, and pick the oldest as the
	// key distributor. Doing this deterministically avoids a thundering herd of
	// every existing member trying to wrap the key for the newcomer.
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

// Leave removes a member from a room and reports whether the room is now empty
// (in which case it has been deleted and its state forgotten).
func (h *Hub) Leave(roomName, memberID string) (roomEmpty bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

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

// Broadcast delivers env to every member of the room except exceptID.
func (h *Hub) Broadcast(roomName, exceptID string, env protocol.Envelope) {
	for _, send := range h.recipients(roomName, exceptID) {
		send(env)
	}
}

// SendTo delivers env to a single member by ID. Reports whether the member was
// found in the room.
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

// recipients snapshots the send callbacks of a room's members (minus exceptID)
// under lock, so the actual sends happen without holding the mutex.
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

// RoomStat is non-sensitive room metadata for the REST /rooms endpoint. It
// deliberately exposes only a name and a member count — never message content.
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
