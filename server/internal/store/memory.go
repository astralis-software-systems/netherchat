package store

import (
	"sync"

	"github.com/salehkreiner/netherchat/protocol"
)

// Memory is an in-process ring buffer of recent envelopes per room. It provides
// history replay within a running server but nothing survives a restart.
type Memory struct {
	mu    sync.Mutex
	max   int
	rooms map[string][]protocol.Envelope
}

// NewMemory returns a Memory store keeping up to max envelopes per room.
func NewMemory(max int) *Memory {
	if max <= 0 {
		max = 100
	}
	return &Memory{max: max, rooms: make(map[string][]protocol.Envelope)}
}

func (m *Memory) Append(room string, env protocol.Envelope) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	buf := append(m.rooms[room], env)
	if len(buf) > m.max {
		buf = buf[len(buf)-m.max:]
	}
	m.rooms[room] = buf
	return nil
}

func (m *Memory) History(room string, limit int) ([]protocol.Envelope, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	buf := m.rooms[room]
	if limit > 0 && len(buf) > limit {
		buf = buf[len(buf)-limit:]
	}
	out := make([]protocol.Envelope, len(buf))
	copy(out, buf)
	return out, nil
}

func (m *Memory) Close() error { return nil }
