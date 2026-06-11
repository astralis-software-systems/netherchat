package app

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/tui/client"
)

// TestStreamUpdatesInPlace proves a live-log stream is ONE block updated in place,
// not a flood of messages: repeated StreamUpdates replace the content without
// adding lines, and StreamEnd makes the block static (§2.2).
func TestStreamUpdatesInPlace(t *testing.T) {
	m := newModel("ws://x", "alice", "", "ops", "")
	r := m.session["ops"]
	at := time.Now()

	streamLines := func() int {
		n := 0
		for _, l := range r.lines {
			if l.kind == lineStream {
				n++
			}
		}
		return n
	}

	m.handleRoomEvent("ops", client.EvStreamUpdate{StreamID: "abcd1234abcd1234", Name: "app.log", From: "bob", Lines: []string{"ERROR boom"}, Seq: 1, At: at})
	if r.streams["abcd1234abcd1234"] == nil || streamLines() != 1 {
		t.Fatalf("first update should create one stream block; lines=%d", streamLines())
	}

	// A second update replaces the content with no new line in the flow.
	m.handleRoomEvent("ops", client.EvStreamUpdate{StreamID: "abcd1234abcd1234", Name: "app.log", From: "bob", Lines: []string{"ERROR boom", "WARN retry"}, Seq: 2, At: at})
	if streamLines() != 1 {
		t.Fatalf("an update must not add a buffer line; got %d stream lines", streamLines())
	}
	if got := r.streams["abcd1234abcd1234"].lines; len(got) != 2 {
		t.Fatalf("content not replaced in place: %v", got)
	}

	out := m.renderLines(r)
	if !strings.Contains(out, "stream: app.log") {
		t.Fatalf("render missing the live stream header:\n%s", out)
	}

	// A stale (lower-seq) update is ignored.
	m.handleRoomEvent("ops", client.EvStreamUpdate{StreamID: "abcd1234abcd1234", Name: "app.log", From: "bob", Lines: []string{"only one"}, Seq: 1, At: at})
	if len(r.streams["abcd1234abcd1234"].lines) != 2 {
		t.Fatal("a stale lower-seq update must be ignored")
	}

	// End makes the block static.
	m.handleRoomEvent("ops", client.EvStreamEnd{StreamID: "abcd1234abcd1234", Reason: "manual_stop"})
	if !r.streams["abcd1234abcd1234"].ended {
		t.Fatal("StreamEnd should mark the block ended")
	}
	if out := m.renderLines(r); !strings.Contains(out, "stream ended: app.log") {
		t.Fatalf("ended stream should show a static header:\n%s", out)
	}
}

// TestExpandStream proves a long stream collapses with a /expand stream-N
// affordance and that /expand stream-1 expands it (§2.2).
func TestExpandStream(t *testing.T) {
	m := newModel("ws://x", "alice", "", "ops", "")
	r := m.session["ops"]
	many := make([]string, 20)
	for i := range many {
		many[i] = fmt.Sprintf("2026-06-10 03:14:%02d INFO line %d", i, i)
	}
	m.handleRoomEvent("ops", client.EvStreamUpdate{StreamID: "abcd1234abcd1234", Name: "app.log", From: "bob", Lines: many, Seq: 1, At: time.Now()})

	if out := m.renderLines(r); !strings.Contains(out, "/expand stream-1") {
		t.Fatalf("a long stream should fold with a /expand affordance:\n%s", out)
	}
	m.runExpand(r, "stream-1")
	if !m.streamExpanded["abcd1234abcd1234"] {
		t.Fatal("/expand stream-1 should expand the block")
	}
}
