package client

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
)

// These tests hold the write loop still so the close race is not a race. A real
// transport drains a queued frame in microseconds, which makes "did Close wait for
// it?" a coin flip to observe from outside; a transport whose Send the test controls
// makes the same question deterministic in both directions.
//
// They are the guard for the operator-shaped failure in tui/ui/app: approve an
// artifact, be elected writer, close the window. That test proves the defect exists
// where a person meets it. These prove the fix at the mechanism, including the two
// cases the operator path cannot stage — a socket that never completes a write, and
// one that is already dead.

// gateTransport is a Transport whose Send the test opens, holds, or fails.
type gateTransport struct {
	release chan struct{} // Send waits here before doing anything
	entered chan struct{} // closed when the write loop first reaches Send

	recv     chan []byte
	closeRcv sync.Once
	inOnce   sync.Once

	mu   sync.Mutex
	err  error // what Send returns once released
	sent []protocol.Op
}

func newGate() *gateTransport {
	return &gateTransport{
		release: make(chan struct{}),
		entered: make(chan struct{}),
		recv:    make(chan []byte, 8),
	}
}

// open lets every Send through immediately, from now on.
func (g *gateTransport) open() { g.releaseOnce() }

// failWith releases the held Send and every later one with err.
func (g *gateTransport) failWith(err error) {
	g.mu.Lock()
	g.err = err
	g.mu.Unlock()
	g.releaseOnce()
}

var _ Transport = (*gateTransport)(nil)

func (g *gateTransport) releaseOnce() {
	select {
	case <-g.release:
	default:
		close(g.release)
	}
}

func (g *gateTransport) Send(b []byte) error {
	g.inOnce.Do(func() { close(g.entered) })
	<-g.release
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.err != nil {
		return g.err
	}
	var env protocol.Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return err
	}
	g.sent = append(g.sent, env.Type)
	return nil
}

func (g *gateTransport) Recv() (<-chan []byte, error) { return g.recv, nil }

func (g *gateTransport) Close() error {
	g.closeRcv.Do(func() { close(g.recv) })
	return nil
}

func (g *gateTransport) PeerID() string     { return "SHA256:gate" }
func (g *gateTransport) RemoteAddr() string { return "gate" }

func (g *gateTransport) delivered() []protocol.Op {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]protocol.Op(nil), g.sent...)
}

// gateClient connects a fresh client over g and returns once the write loop is
// parked inside Send with the Hello. From that point the queue state is the
// test's to set: nothing more can leave until the gate opens. The room key is
// never established — these tests only need frames in the queue, and the control
// frames they use do not require one.
func gateClient(t *testing.T, g *gateTransport) *Client {
	t.Helper()
	c, err := NewEphemeral("ws://gate/ws", "ops", "operator")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if err := c.ConnectWith(g); err != nil {
		t.Fatalf("connect: %v", err)
	}
	select {
	case <-g.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the write loop never reached the transport")
	}
	return c
}

// waitQueued blocks until n frames are sitting in the send queue, so a test can
// close at a known point rather than a hoped-for one.
func waitQueued(t *testing.T, c *Client, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(c.sendCh) >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d queued frame(s); have %d", n, len(c.sendCh))
}

// TestCloseFlushesQueuedFrames: a frame enqueued while the write loop is mid-send
// still reaches the wire. This is the defect stripped to its mechanism — the write
// loop is provably busy at close time, so before the flush the frame had no way to
// survive.
func TestCloseFlushesQueuedFrames(t *testing.T) {
	g := newGate()
	c := gateClient(t, g)

	// The Hello is in flight and the transport is holding it, so the control frame
	// cannot already have been written.
	c.Vanish()
	waitQueued(t, c, 1)

	// Release the transport a moment after Close starts waiting, the way a socket
	// that was merely slow comes back.
	go func() { time.Sleep(50 * time.Millisecond); g.open() }()

	if err := c.Close(); err != nil {
		t.Fatalf("Close on a connection that came back must not report a loss: %v", err)
	}
	got := g.delivered()
	if len(got) != 2 || got[0] != protocol.OpHello || got[1] != protocol.OpControl {
		t.Fatalf("wire = %v, want [%s %s]: Close discarded the queued frame",
			got, protocol.OpHello, protocol.OpControl)
	}
	// Teardown is idempotent: t.Cleanup and an explicit close both happen in this
	// codebase, sometimes on the same client.
	if err := c.Close(); errors.As(err, new(*UnflushedError)) {
		t.Fatalf("a second Close must not invent a loss: %v", err)
	}
}

// TestCloseReportsWhatItCouldNotFlush: when the socket never completes the write,
// Close gives up at its budget and names the frames that did not go out. The loss
// still happens — it just stops being silent.
func TestCloseReportsWhatItCouldNotFlush(t *testing.T) {
	g := newGate()
	c := gateClient(t, g)
	defer g.open() // let the parked write loop exit when the test ends

	c.Vanish()
	c.SetTTL(30)
	waitQueued(t, c, 2)

	start := time.Now()
	err := c.CloseWithin(150 * time.Millisecond)
	elapsed := time.Since(start)

	var u *UnflushedError
	if !errors.As(err, &u) {
		t.Fatalf("Close returned %v, want an *UnflushedError naming the undelivered frames", err)
	}
	// The Hello the transport is still holding counts too: unacknowledged is not
	// delivered, and it is the frame most likely to be lost when a socket wedges.
	want := []protocol.Op{protocol.OpHello, protocol.OpControl, protocol.OpControl}
	if !sameOps(u.Ops, want) {
		t.Fatalf("unflushed ops = %v, want %v", u.Ops, want)
	}
	if !errors.Is(u, context.DeadlineExceeded) {
		t.Fatalf("cause = %v, want context.DeadlineExceeded", u.Cause)
	}
	if elapsed > time.Second {
		t.Fatalf("CloseWithin(150ms) took %s: the budget must bound the wait", elapsed)
	}
}

// TestCloseOnADeadSocketDoesNotWait: a transport that has already failed costs the
// caller nothing. The write loop is gone, there is nothing to drain into, and Close
// reports the residue immediately rather than spending the budget proving it.
func TestCloseOnADeadSocketDoesNotWait(t *testing.T) {
	g := newGate()
	c := gateClient(t, g)

	c.Vanish()
	waitQueued(t, c, 1)

	// The socket dies with the Hello in flight; the control frame never leaves the
	// queue. This is the peer-is-gone case: no retry is possible, and pretending
	// otherwise would only burn the deadline.
	boom := errors.New("connection reset by peer")
	g.failWith(boom)

	deadline := time.Now().Add(2 * time.Second)
	for c.ctx.Err() == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	start := time.Now()
	err := c.Close()
	elapsed := time.Since(start)

	var u *UnflushedError
	if !errors.As(err, &u) {
		t.Fatalf("Close returned %v, want an *UnflushedError for the frames the dead socket ate", err)
	}
	want := []protocol.Op{protocol.OpHello, protocol.OpControl}
	if !sameOps(u.Ops, want) {
		t.Fatalf("unflushed ops = %v, want the failed Hello and the queued control frame %v", u.Ops, want)
	}
	if !errors.Is(u, boom) {
		t.Fatalf("cause = %v, want the transport error", u.Cause)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("Close on a dead socket took %s: it must not wait out the budget", elapsed)
	}
}

// TestCloseWithinZeroDoesNotWaitButStillReports is the opt-out, for a caller that
// must not block. Skipping the wait does not skip the accounting: the frames are
// still named, so a caller that cannot afford to wait can still say what it lost.
func TestCloseWithinZeroDoesNotWaitButStillReports(t *testing.T) {
	g := newGate()
	c := gateClient(t, g)
	defer g.open()

	c.Vanish()
	waitQueued(t, c, 1)

	start := time.Now()
	err := c.CloseWithin(0)
	elapsed := time.Since(start)

	if elapsed > 200*time.Millisecond {
		t.Fatalf("CloseWithin(0) took %s: it must not wait at all", elapsed)
	}
	var u *UnflushedError
	if !errors.As(err, &u) {
		t.Fatalf("CloseWithin(0) returned %v, want the undelivered frame reported", err)
	}
	want := []protocol.Op{protocol.OpHello, protocol.OpControl}
	if !sameOps(u.Ops, want) {
		t.Fatalf("unflushed ops = %v, want %v", u.Ops, want)
	}
}

// sameOps compares two opcode sequences.
func sameOps(got, want []protocol.Op) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestUnflushedEvidenceClassification pins which lost frames are evidence. The
// distinction is the whole reason a caller would treat this error differently from
// a dropped message: a chat line nobody received is visible to the person who typed
// it, and a record entry nobody received is visible to nobody.
func TestUnflushedEvidenceClassification(t *testing.T) {
	evidence := []protocol.Op{
		protocol.OpRecordEntry, protocol.OpSealRequest, protocol.OpSealAck,
		protocol.OpRosterRequest, protocol.OpRosterAck,
		protocol.OpScuttleReceiptRequest, protocol.OpScuttleReceiptAck,
		protocol.OpArtifactApproval, protocol.OpArtifactRejection,
	}
	for _, op := range evidence {
		if !(&UnflushedError{Ops: []protocol.Op{op}}).Evidence() {
			t.Errorf("%s must count as evidence: nothing re-files it and nobody misses it", op)
		}
	}
	ordinary := []protocol.Op{protocol.OpMessage, protocol.OpHello, protocol.OpControl, protocol.OpFileChunk}
	for _, op := range ordinary {
		if (&UnflushedError{Ops: []protocol.Op{op}}).Evidence() {
			t.Errorf("%s is not evidence: losing it is visible to the sender", op)
		}
	}
	// The message has to say the thing out loud, or a caller that logs it learns
	// only that a number of frames went missing.
	msg := (&UnflushedError{Ops: []protocol.Op{protocol.OpRecordEntry}, Cause: context.DeadlineExceeded}).Error()
	for _, want := range []string{string(protocol.OpRecordEntry), "did not reach the room", "deadline"} {
		if !strings.Contains(msg, want) {
			t.Errorf("Error() = %q, want it to mention %q", msg, want)
		}
	}
}
