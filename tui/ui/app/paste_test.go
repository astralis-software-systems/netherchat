package app

import (
	"fmt"
	"strings"
	"testing"
)

// fencedGo builds an n-line fenced Go block, used to exercise the collapse path.
func fencedGo(n int) string {
	var b strings.Builder
	b.WriteString("```go\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "v%d := %d\n", i, i)
	}
	b.WriteString("```")
	return b.String()
}

// TestRenderLineBlockIDs proves collapse ids are sequential across the room
// buffer (only chat messages with collapsible blocks consume ids) and that
// renderLines records the high-water mark for /expand to validate against.
func TestRenderLineBlockIDs(t *testing.T) {
	m := newModel("ws://localhost:3000", "me", "", "ops", "")
	m.resize(100, 30) // sets the viewport + renderer width and marks ready
	r := m.activeRoom()
	r.lines = []line{
		{at: at(3, 47), kind: lineMessage, from: "alice", text: fencedGo(25), signed: true},
		{at: at(3, 48), kind: lineMessage, from: "bob", text: "just a normal line", signed: true},
		{at: at(3, 49), kind: lineSelf, from: "me", text: fencedGo(25), signed: true},
	}

	out := m.renderLines(r)
	if r.maxBlockID != 2 {
		t.Fatalf("expected 2 collapsible blocks across the buffer, got maxBlockID=%d", r.maxBlockID)
	}
	if !strings.Contains(out, "/expand 1") || !strings.Contains(out, "/expand 2") {
		t.Errorf("expected fold ids 1 and 2 in the render:\n%s", out)
	}
}

// TestRenderLinePlainNoRegression proves a plain message renders exactly as the
// pre-feature inline path did: header + inline-styled body, wrapped, on one line.
func TestRenderLinePlainNoRegression(t *testing.T) {
	m := newModel("ws://localhost:3000", "me", "", "ops", "")
	m.resize(100, 30)
	r := m.activeRoom()

	l := line{at: at(3, 47), kind: lineMessage, from: "alice", text: "hello `world` ok", fpr: testFpr, signed: true}
	got, blocks := m.renderLine(r, l, 1)
	if blocks != 0 {
		t.Fatalf("a plain message must consume no block ids, got %d", blocks)
	}

	ts := m.st(m.theme.Muted).Render(l.at.Format("15:04") + " ")
	header := ts + m.user(l.from) + m.badge(l) + m.st(m.theme.Text).Render(": ")
	want := m.wrap(header + m.inlineCode(l.text))
	if got != want {
		t.Errorf("plain message rendering changed:\n got=%q\nwant=%q", got, want)
	}
}

// TestExpandCommand proves /expand <id> flips fold state and the re-render shows
// the full block, while an out-of-range id reports an error.
func TestExpandCommand(t *testing.T) {
	m := newModel("ws://localhost:3000", "me", "", "ops", "")
	m.resize(100, 30)
	r := m.activeRoom()
	r.lines = []line{{at: at(3, 47), kind: lineMessage, from: "alice", text: fencedGo(25), signed: true}}

	_ = m.renderLines(r) // assigns ids; sets maxBlockID = 1
	if r.collapse.Expanded(1) {
		t.Fatal("block should start collapsed")
	}

	m.runExpand(r, "1")
	if !r.collapse.Expanded(1) {
		t.Error("/expand 1 should expand block 1")
	}
	out := m.renderLines(r)
	if strings.Contains(out, "more lines") {
		t.Error("expanded block should no longer fold")
	}
	if !strings.Contains(out, "v24") {
		t.Error("expanded block should show every line (v24 missing)")
	}

	// Out-of-range id reports a helpful error and changes no state.
	m.runExpand(r, "9")
	last := r.lines[len(r.lines)-1]
	if last.kind != lineError || !strings.Contains(last.text, "no block #9") {
		t.Errorf("expected an out-of-range error line, got %+v", last)
	}
}

// TestVanishResetsCollapse proves clearing history also resets fold ids so a
// reused id #1 doesn't inherit a previous block's expanded state.
func TestVanishResetsCollapse(t *testing.T) {
	m := newModel("ws://localhost:3000", "me", "", "ops", "")
	m.resize(100, 30)
	r := m.activeRoom()
	r.collapse.Expand(1)

	r.lines = nil
	r.collapse.Reset() // mirrors the /vanish and /clear handlers

	if r.collapse.Expanded(1) {
		t.Error("collapse state should reset when history is cleared")
	}
}
