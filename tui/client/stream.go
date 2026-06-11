package client

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
)

const (
	// streamFlushInterval is how often a live stream pushes its current ring buffer
	// to the room (§2.2). Updates are coalesced — a busy log produces one update per
	// tick, not one per line.
	streamFlushInterval = 500 * time.Millisecond
	// streamBatchLines forces an early flush when this many new lines have arrived
	// since the last one, so a burst is not held back for the full interval.
	streamBatchLines = 10
	// DefaultStreamLines / MaxStreamLines bound the ring buffer (--lines).
	DefaultStreamLines = 200
	MaxStreamLines     = 1000
)

// Stream is an outbound live-log stream (§2.2): a fixed-size ring buffer fed line
// by line, flushed to the room as OpStreamUpdate frames. It is ephemeral — nothing
// is persisted, and when it ends an OpStreamEnd makes the block static. The same
// type drives both `netherchat stream` (pipe) and the TUI's /stream (file tail).
type Stream struct {
	c    *Client
	id   string
	name string
	max  int

	mu     sync.Mutex
	buf    []string
	seq    uint64
	dirty  bool
	sent   int
	closed bool
}

// NewStream creates a stream with a fresh random id. sourceName labels the block
// header (e.g. "app.log"); maxLines bounds the ring buffer (clamped to
// [1, MaxStreamLines]).
func (c *Client) NewStream(sourceName string, maxLines int) *Stream {
	if maxLines <= 0 {
		maxLines = DefaultStreamLines
	}
	if maxLines > MaxStreamLines {
		maxLines = MaxStreamLines
	}
	return &Stream{c: c, id: newStreamID(), name: sourceName, max: maxLines}
}

// ID returns the stream's unique id.
func (s *Stream) ID() string { return s.id }

// Sent returns how many lines have been fed into the stream so far (for progress).
func (s *Stream) Sent() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sent
}

// AddLine appends a line, dropping the oldest when the ring buffer is full.
func (s *Stream) AddLine(line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.buf = append(s.buf, line)
	if len(s.buf) > s.max {
		s.buf = append([]string(nil), s.buf[len(s.buf)-s.max:]...)
	}
	s.dirty = true
	s.sent++
}

// flush sends the current ring buffer as a StreamUpdate when there is new content.
func (s *Stream) flush() {
	s.mu.Lock()
	if s.closed || !s.dirty {
		s.mu.Unlock()
		return
	}
	s.seq++
	seq := s.seq
	lines := append([]string(nil), s.buf...)
	s.dirty = false
	s.mu.Unlock()

	body, _ := json.Marshal(protocol.StreamUpdateBody{
		StreamID: s.id, Name: s.name, Lines: lines, Seq: seq, TS: time.Now().Unix(),
	})
	if err := s.c.sealAndSend(protocol.OpStreamUpdate, body); err != nil {
		return
	}
	// Local echo so the streamer's own TUI shows the block updating in place.
	s.c.emit(EvStreamUpdate{
		StreamID: s.id, Name: s.name, From: s.c.name, Fpr: s.c.Fingerprint(),
		Lines: lines, Seq: seq, Self: true, At: time.Now(),
	})
}

// End closes the stream: it flushes anything pending, sends a StreamEnd so every
// block goes static, and emits the local echo. Safe to call more than once.
func (s *Stream) End(reason string) {
	s.flush()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()

	body, _ := json.Marshal(protocol.StreamEndBody{StreamID: s.id, Reason: reason})
	_ = s.c.sealAndSend(protocol.OpStreamEnd, body)
	s.c.emit(EvStreamEnd{StreamID: s.id, Reason: reason, From: s.c.name, Self: true})
}

// Run drives the stream from a channel of lines until the channel closes or ctx is
// cancelled, coalescing updates on streamFlushInterval / streamBatchLines. On
// channel close it ends with endReason (e.g. sender_disconnected for a closed
// pipe); on ctx cancellation it ends with manual_stop.
func (s *Stream) Run(ctx context.Context, lines <-chan string, endReason string) {
	ticker := time.NewTicker(streamFlushInterval)
	defer ticker.Stop()
	pending := 0
	for {
		select {
		case <-ctx.Done():
			s.End(protocol.StreamEndManual)
			return
		case <-ticker.C:
			s.flush()
			pending = 0
		case line, ok := <-lines:
			if !ok {
				s.End(endReason)
				return
			}
			s.AddLine(line)
			if pending++; pending >= streamBatchLines {
				s.flush()
				pending = 0
			}
		}
	}
}

// ScanLines reads r line by line into a channel that closes when r reaches EOF or
// ctx is cancelled. It is the line source for pipe mode (os.Stdin) and any reader.
func ScanLines(ctx context.Context, r io.Reader) <-chan string {
	out := make(chan string, 256)
	go func() {
		defer close(out)
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			select {
			case out <- sc.Text():
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

func newStreamID() string { return newRequestID() } // 16 hex chars, same generator as request ids
