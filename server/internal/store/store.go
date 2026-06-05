// Package store provides optional, opt-in persistence of per-room message
// envelopes so the server can replay recent history to a member when it joins.
//
// CRITICAL honesty note: the server is a blind relay and never holds a room key,
// so everything stored here is CIPHERTEXT. It is decryptable only by a client
// that currently holds the room's key. Therefore persisted history is replayable
// to someone joining a still-active room, but is NOT recoverable once the room
// fully empties, the key rotates (/vanish), or the server restarts — the key is
// gone by design. See docs/encryption.md.
//
// The Store interface is the swappable seam the deployment notes call for
// (in-memory today, SQLite for local durability, Postgres later).
package store

import "github.com/salehkreiner/netherchat/protocol"

// Store persists and replays per-room message envelopes.
type Store interface {
	// Append records a message envelope for a room.
	Append(room string, env protocol.Envelope) error
	// History returns up to limit most-recent envelopes for a room, oldest first.
	History(room string, limit int) ([]protocol.Envelope, error)
	// Close releases any resources.
	Close() error
}
