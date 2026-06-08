package ws

import (
	"sync"
	"time"
)

// transferTTL is the safety net for the concurrency tracker: a transfer that
// never reaches its final chunk or an abort (a sender that wedges) is swept after
// this long so its slot does not leak. Real transfers free their slot in seconds.
const transferTTL = 5 * time.Minute

// transferTracker bounds concurrent in-flight artifact transfers per room (§2.3).
// It is the ONE thing the blind relay tracks about a transfer: a content-free
// transfer id and which member opened it — never the filename, size, or contents.
// A slot is freed when the relay forwards the final chunk, on an abort, when the
// opening member disconnects, or by TTL.
type transferTracker struct {
	mu    sync.Mutex
	max   int
	rooms map[string]map[string]xfer // room -> transfer id -> info
}

type xfer struct {
	owner   string // member id that opened the transfer (the sender)
	started time.Time
}

func newTransferTracker(max int) *transferTracker {
	if max <= 0 {
		max = 1
	}
	return &transferTracker{max: max, rooms: make(map[string]map[string]xfer)}
}

// tryStart reserves a slot for tid in room, owned by owner. It returns false when
// the room already holds max distinct transfers (the offer is rejected). Re-offering
// an id already tracked is idempotent and always succeeds.
func (t *transferTracker) tryStart(room, tid, owner string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	m := t.rooms[room]
	if m == nil {
		m = make(map[string]xfer)
		t.rooms[room] = m
	}
	t.sweepLocked(m)
	if _, ok := m[tid]; ok {
		return true // already counted
	}
	if len(m) >= t.max {
		return false
	}
	m[tid] = xfer{owner: owner, started: time.Now()}
	return true
}

// finish frees a transfer's slot (final chunk forwarded, abort, or completion).
func (t *transferTracker) finish(room, tid string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if m := t.rooms[room]; m != nil {
		delete(m, tid)
		if len(m) == 0 {
			delete(t.rooms, room)
		}
	}
}

// abortBy frees every transfer owned by member in room and returns their ids, so
// the caller can broadcast a FileAbort when a sender disconnects mid-transfer.
func (t *transferTracker) abortBy(room, owner string) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	m := t.rooms[room]
	if m == nil {
		return nil
	}
	var ids []string
	for tid, x := range m {
		if x.owner == owner {
			ids = append(ids, tid)
			delete(m, tid)
		}
	}
	if len(m) == 0 {
		delete(t.rooms, room)
	}
	return ids
}

// sweepLocked drops transfers older than the TTL. Caller holds the lock.
func (t *transferTracker) sweepLocked(m map[string]xfer) {
	now := time.Now()
	for tid, x := range m {
		if now.Sub(x.started) > transferTTL {
			delete(m, tid)
		}
	}
}
