package client

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
)

// TestStreamRingBufferCap proves the ring buffer drops the oldest lines once it is
// full (the --lines cap, §2.2).
func TestStreamRingBufferCap(t *testing.T) {
	c := &Client{name: "alice"}
	s := c.NewStream("app.log", 3)
	for _, l := range []string{"1", "2", "3", "4", "5"} {
		s.AddLine(l)
	}
	s.mu.Lock()
	got := append([]string(nil), s.buf...)
	s.mu.Unlock()
	if len(got) != 3 || got[0] != "3" || got[2] != "5" {
		t.Fatalf("ring buffer = %v, want [3 4 5]", got)
	}
	if s.Sent() != 5 {
		t.Fatalf("Sent = %d, want 5 (counts every line, not just the kept ones)", s.Sent())
	}
}

// TestStreamRoundTrip proves a StreamUpdate carries the full ring buffer to other
// members and a StreamEnd follows — the basis of the in-place live block (§2.2).
func TestStreamRoundTrip(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLog()))
	defer ts.Close()

	streamer := dialClient(t, ts.URL, "ops", "alice")
	waitFor[EvKeyReady](t, streamer, 5*time.Second)
	watcher := dialClient(t, ts.URL, "ops", "bob")
	waitFor[EvKeyReady](t, watcher, 5*time.Second)

	st := streamer.NewStream("app.log", 200)
	st.AddLine("2026-06-10 03:14:22 ERROR database connection refused")
	st.AddLine("2026-06-10 03:14:23 WARN  retry attempt 1/3")
	st.flush()

	up := waitFor[EvStreamUpdate](t, watcher, 5*time.Second)
	if up.StreamID != st.ID() || up.Name != "app.log" || up.From != "alice" {
		t.Fatalf("stream update header = %+v", up)
	}
	if len(up.Lines) != 2 || up.Seq != 1 {
		t.Fatalf("stream update = %d lines, seq %d, want 2 lines seq 1", len(up.Lines), up.Seq)
	}

	// A second update carries the WHOLE buffer again (replace-in-place), seq bumped.
	st.AddLine("2026-06-10 03:14:24 ERROR retry failed")
	st.flush()
	up2 := waitFor[EvStreamUpdate](t, watcher, 5*time.Second)
	if up2.Seq != 2 || len(up2.Lines) != 3 {
		t.Fatalf("second update = seq %d, %d lines, want seq 2, 3 lines", up2.Seq, len(up2.Lines))
	}

	st.End(protocol.StreamEndDisconnected)
	end := waitFor[EvStreamEnd](t, watcher, 5*time.Second)
	if end.StreamID != st.ID() || end.Reason != protocol.StreamEndDisconnected {
		t.Fatalf("stream end = %+v, want disconnected", end)
	}
}

// TestStreamExcludedFromPersistence proves that, even with the optional history
// store enabled, a stream update is NEVER persisted: a member who joins later gets
// the ordinary message replayed from history but no stream content (§2.2).
func TestStreamExcludedFromPersistence(t *testing.T) {
	cfg := config.Default()
	cfg.Persistence.Enabled = true // in-memory store (no path)
	cfg.Persistence.History = 100
	ts := httptest.NewServer(server.Handler(cfg, quietLog()))
	defer ts.Close()

	streamer := dialClient(t, ts.URL, "ops", "alice")
	waitFor[EvKeyReady](t, streamer, 5*time.Second)
	early := dialClient(t, ts.URL, "ops", "bob")
	waitFor[EvKeyReady](t, early, 5*time.Second)

	// A normal message (will be stored) and a stream update (must not be).
	if err := streamer.Send("a normal message"); err != nil {
		t.Fatalf("send: %v", err)
	}
	waitFor[EvMessage](t, early, 5*time.Second) // relay processed + stored the message
	st := streamer.NewStream("app.log", 200)
	st.AddLine("secret log line nobody should replay")
	st.flush()
	waitFor[EvStreamUpdate](t, early, 5*time.Second) // relay processed the stream update

	// A latecomer joins and receives history replay.
	late := dialClient(t, ts.URL, "ops", "carol")
	gotMessage, gotStream := false, false
	deadline := time.After(3 * time.Second)
loop:
	for {
		select {
		case ev := <-late.Events():
			switch e := ev.(type) {
			case EvMessage:
				if e.Text == "a normal message" {
					gotMessage = true
				}
			case EvStreamUpdate:
				gotStream = true
			}
		case <-deadline:
			break loop
		}
	}
	if !gotMessage {
		t.Fatal("expected the ordinary message to be replayed from history")
	}
	if gotStream {
		t.Fatal("a stream update must NOT be persisted or replayed to a latecomer")
	}
}

// TestStreamNoBackfill proves a member who joins mid-stream receives the NEXT update
// (with the full buffer), not a replay of stream history — streams are live-only,
// nothing is persisted (§2.2).
func TestStreamNoBackfill(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLog()))
	defer ts.Close()

	streamer := dialClient(t, ts.URL, "ops", "alice")
	waitFor[EvKeyReady](t, streamer, 5*time.Second)
	early := dialClient(t, ts.URL, "ops", "bob")
	waitFor[EvKeyReady](t, early, 5*time.Second)

	st := streamer.NewStream("app.log", 200)
	st.AddLine("before the latecomer joined")
	st.flush()
	waitFor[EvStreamUpdate](t, early, 5*time.Second) // the early watcher saw it

	// A new member joins mid-stream.
	late := dialClient(t, ts.URL, "ops", "carol")
	waitFor[EvKeyReady](t, late, 5*time.Second)

	// The next update reaches the latecomer with the FULL buffer (catch-up), and it
	// is the FIRST stream event they ever see — there was no backfill on join.
	st.AddLine("after the latecomer joined")
	st.flush()
	up := waitFor[EvStreamUpdate](t, late, 5*time.Second)
	if up.Seq != 2 || len(up.Lines) != 2 || up.Lines[0] != "before the latecomer joined" {
		t.Fatalf("latecomer update = seq %d, lines %v, want the full 2-line buffer at seq 2", up.Seq, up.Lines)
	}
}
