package ws

import (
	"testing"
	"time"
)

// TestTransferConcurrencyLimit proves the tracker bounds concurrent transfers per
// room (§2.3): the (max+1)-th distinct transfer is rejected, and re-offering an
// id already counted is idempotent.
func TestTransferConcurrencyLimit(t *testing.T) {
	tr := newTransferTracker(2)
	if !tr.tryStart("ops", "t1", "alice") {
		t.Fatal("first transfer should start")
	}
	if !tr.tryStart("ops", "t2", "alice") {
		t.Fatal("second transfer should start")
	}
	if tr.tryStart("ops", "t3", "bob") {
		t.Fatal("third transfer must be rejected at the limit")
	}
	if !tr.tryStart("ops", "t1", "alice") {
		t.Fatal("re-offering an already-counted transfer must be idempotent")
	}
	// A different room has its own budget.
	if !tr.tryStart("other", "t9", "alice") {
		t.Fatal("a different room should not be affected")
	}
}

// TestTransferFinishFreesSlot proves finishing a transfer frees its slot.
func TestTransferFinishFreesSlot(t *testing.T) {
	tr := newTransferTracker(1)
	if !tr.tryStart("ops", "t1", "alice") {
		t.Fatal("first should start")
	}
	if tr.tryStart("ops", "t2", "alice") {
		t.Fatal("second should be rejected (room full)")
	}
	tr.finish("ops", "t1")
	if !tr.tryStart("ops", "t2", "alice") {
		t.Fatal("after finish, a new transfer should start")
	}
}

// TestTransferAbortBy proves a sender's transfers are returned and freed when it
// disconnects.
func TestTransferAbortBy(t *testing.T) {
	tr := newTransferTracker(5)
	tr.tryStart("ops", "a1", "alice")
	tr.tryStart("ops", "a2", "alice")
	tr.tryStart("ops", "b1", "bob")

	ids := tr.abortBy("ops", "alice")
	if len(ids) != 2 {
		t.Fatalf("abortBy returned %d ids, want 2 (alice's)", len(ids))
	}
	// bob's transfer survives; the slots alice held are free.
	if !tr.tryStart("ops", "a3", "alice") || !tr.tryStart("ops", "a4", "alice") {
		t.Fatal("alice's freed slots should be reusable")
	}
}

// TestTransferTTLSweep proves a wedged transfer is swept after the TTL so its slot
// does not leak.
func TestTransferTTLSweep(t *testing.T) {
	tr := newTransferTracker(1)
	tr.mu.Lock()
	tr.rooms["ops"] = map[string]xfer{"stale": {owner: "alice", started: time.Now().Add(-2 * transferTTL)}}
	tr.mu.Unlock()
	// tryStart sweeps first, so the stale transfer is gone and the room has room.
	if !tr.tryStart("ops", "fresh", "bob") {
		t.Fatal("a stale transfer past the TTL should be swept, freeing its slot")
	}
}
