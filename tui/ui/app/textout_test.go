package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/salehkreiner/netherchat/tui/eventlog"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

// a valid-format fingerprint (SHA256: + 43 base64 chars) so exported events pass
// the eventlog schema's fpr pattern.
const testFpr = "SHA256:zz6S5e54kc2bpWt6SqcgqSNN/Yrx91Vko0Kz6g3IVWM"

func at(h, m int) time.Time { return time.Date(2026, 6, 8, h, m, 0, 0, time.UTC) }

// sampleRoom builds a model whose active room holds a representative buffer:
// peer chat, own chat, a webhook (unsigned), a record entry, a replayed record
// entry, and a system line (which must NOT export).
func sampleRoom(t *testing.T) (*Model, *room) {
	t.Helper()
	m := newModel("ws://localhost:3000", "me", "", "ops", "")
	m.fingerprint = testFpr
	r := m.activeRoom()
	r.lines = []line{
		{at: at(3, 47), kind: lineMessage, from: "alice", text: "the database is on fire", fpr: testFpr, signed: true},
		{at: at(3, 48), kind: lineSelf, from: "me", text: "rolling back", signed: true},
		{at: at(3, 49), kind: lineServer, from: "ci-bot", text: "build #4821 passed", signed: false},
		{at: at(3, 50), kind: lineRecord, from: "alice", text: "rolled back to v2.3.1", fpr: testFpr, signed: true, recordKind: "decision"},
		{at: at(3, 51), kind: lineRecord, from: "bob", text: "earlier decision", fpr: testFpr, signed: true, replayed: true},
		{at: at(3, 52), kind: lineSystem, text: "alice joined"}, // not a message — excluded
	}
	return m, r
}

// TestRoomMessagesExcludesNonMessages proves /copy and /export see only message
// lines, and that self lines get our fingerprint filled in.
func TestRoomMessagesExcludesNonMessages(t *testing.T) {
	m, r := sampleRoom(t)
	msgs := m.roomMessages(r)
	if len(msgs) != 5 {
		t.Fatalf("got %d messages, want 5 (system line excluded)", len(msgs))
	}
	if msgs[1].sender != "me" || msgs[1].fpr != testFpr {
		t.Errorf("self message fpr not filled: %+v", msgs[1])
	}
}

// TestSelectCopyMessage covers the three /copy selectors and the miss cases.
func TestSelectCopyMessage(t *testing.T) {
	msgs := []exportMsg{
		{sender: "alice", body: "first"},
		{sender: "bob", body: "second"},
		{sender: "alice", body: "third"},
	}
	cases := []struct {
		arg      string
		wantBody string
		wantOK   bool
	}{
		{"", "third", true},       // most recent
		{"1", "third", true},      // 1 = most recent
		{"2", "second", true},     // 2nd most recent
		{"3", "first", true},      // 3rd most recent
		{"@alice", "third", true}, // most recent FROM alice
		{"@bob", "second", true},  // most recent FROM bob
		{"@nobody", "", false},    // no such sender
		{"9", "", false},          // out of range
		{"0", "", false},          // 0 is not valid (1-based)
		{"notanumber", "", false}, // garbage
	}
	for _, c := range cases {
		msg, ok := selectCopyMessage(msgs, c.arg)
		if ok != c.wantOK || msg.body != c.wantBody {
			t.Errorf("selectCopyMessage(%q) = (%q,%v), want (%q,%v)", c.arg, msg.body, ok, c.wantBody, c.wantOK)
		}
	}
	if _, ok := selectCopyMessage(nil, ""); ok {
		t.Error("empty buffer should yield no message")
	}
}

// TestRunCopyNoMessage proves /copy on an empty room reports the miss (and never
// touches the clipboard).
func TestRunCopyNoMessage(t *testing.T) {
	m := newModel("ws://localhost:3000", "me", "", "ops", "")
	m.runCopy(m.activeRoom(), "")
	lines := m.activeRoom().lines
	if len(lines) == 0 {
		t.Fatal("expected a system line")
	}
	last := lines[len(lines)-1]
	if last.kind != lineSystem || last.text != "✗ no message found" {
		t.Fatalf("last line = %+v, want system '✗ no message found'", last)
	}
}

// TestExportTextFormat proves the plain-text format: [HH:MM] sender: body, with a
// "?" for unsigned and "[replay]" for replayed entries; signed carries no marker.
func TestExportTextFormat(t *testing.T) {
	m, r := sampleRoom(t)
	out := exportText(m.roomMessages(r))
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")

	// The signed peer message matches the baseline pattern exactly.
	pat := regexp.MustCompile(`^\[\d{2}:\d{2}\] alice: the database is on fire$`)
	if !pat.MatchString(lines[0]) {
		t.Errorf("line 0 = %q, does not match [HH:MM] sender: body", lines[0])
	}
	// The webhook is unsigned → "?" marker.
	if !strings.HasPrefix(lines[2], "[03:49] ? ci-bot: ") {
		t.Errorf("unsigned line = %q, want a '?' marker", lines[2])
	}
	// The replayed record entry → "[replay]" marker.
	if !strings.HasPrefix(lines[4], "[03:51] [replay] bob: ") {
		t.Errorf("replayed line = %q, want a '[replay]' marker", lines[4])
	}
	// Signed, non-replayed record entry carries no marker.
	if !strings.HasPrefix(lines[3], "[03:50] alice: ") {
		t.Errorf("signed record line = %q, should have no marker", lines[3])
	}
}

// TestExportJSONSchema proves every exported JSON line is a valid eventlog
// "message" event: it round-trips with DisallowUnknownFields AND validates
// against the embedded draft-07 schema — so the file is tail --json compatible.
func TestExportJSONSchema(t *testing.T) {
	m, r := sampleRoom(t)
	out := exportJSON(r.name, m.roomMessages(r))

	c := jsonschema.NewCompiler()
	c.Draft = jsonschema.Draft7
	if err := c.AddResource("event.json", strings.NewReader(eventlog.SchemaJSON())); err != nil {
		t.Fatalf("add schema: %v", err)
	}
	sch, err := c.Compile("event.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 5 {
		t.Fatalf("exported %d JSON lines, want 5", len(lines))
	}
	for _, ln := range lines {
		// 1) no field the eventlog.Event struct doesn't know.
		dec := json.NewDecoder(strings.NewReader(ln))
		dec.DisallowUnknownFields()
		var e eventlog.Event
		if err := dec.Decode(&e); err != nil {
			t.Fatalf("DisallowUnknownFields failed: %v\n%s", err, ln)
		}
		if e.Type != "message" {
			t.Errorf("event type = %q, want message", e.Type)
		}
		// 2) validates against the published schema.
		var doc any
		_ = json.Unmarshal([]byte(ln), &doc)
		if err := sch.Validate(doc); err != nil {
			t.Fatalf("schema validation failed: %v\n%s", err, ln)
		}
	}
}

// TestExportJSONUsesMessageTime proves the exported event carries the message's
// own timestamp (not export-time now()), so the timeline is faithful.
func TestExportJSONUsesMessageTime(t *testing.T) {
	m, r := sampleRoom(t)
	first := strings.SplitN(exportJSON(r.name, m.roomMessages(r)), "\n", 2)[0]
	var e eventlog.Event
	if err := json.Unmarshal([]byte(first), &e); err != nil {
		t.Fatal(err)
	}
	if e.TS != "2026-06-08T03:47:00Z" {
		t.Errorf("ts = %q, want the message's own time 2026-06-08T03:47:00Z", e.TS)
	}
}

// TestRunExportWritesFile proves /export --all --out writes the full buffer to
// disk and confirms the count, exercising the full command path.
func TestRunExportWritesFile(t *testing.T) {
	m, r := sampleRoom(t)
	path := filepath.Join(t.TempDir(), "out.txt")
	m.runExport(r, "--all --out "+path)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("export file not written: %v", err)
	}
	if string(data) != exportText(m.roomMessages(r)) {
		t.Errorf("file content does not match exportText:\n%s", data)
	}
	last := r.lines[len(r.lines)-1]
	if last.kind != lineSystem || !strings.Contains(last.text, "exported 5 messages to "+path) {
		t.Errorf("confirmation line = %+v", last)
	}
}

// TestExportDefaultSealedOnly proves /export with no flag exports only sealed
// decisions — zero when a room holds chat but nothing was promoted (§7).
func TestExportDefaultSealedOnly(t *testing.T) {
	m := newModel("ws://localhost:3000", "me", "", "ops", "")
	m.fingerprint = testFpr
	r := m.activeRoom()
	r.lines = []line{
		{at: at(3, 47), kind: lineMessage, from: "alice", text: "the db is on fire", fpr: testFpr, signed: true},
		{at: at(3, 48), kind: lineSelf, from: "me", text: "rolling back", signed: true},
	}
	path := filepath.Join(t.TempDir(), "sealed.txt")
	m.runExport(r, "--out "+path)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("export file not written: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("default export wrote %d bytes, want 0 (no sealed items)", len(data))
	}
	last := r.lines[len(r.lines)-1]
	if last.kind != lineSystem || !strings.Contains(last.text, "exported 0 messages") {
		t.Errorf("confirmation line = %+v, want 'exported 0 messages'", last)
	}
}

// TestExportAllShowsWarning proves --all prints the persistence warning before
// the export confirmation (§7).
func TestExportAllShowsWarning(t *testing.T) {
	m, r := sampleRoom(t)
	before := len(r.lines)
	path := filepath.Join(t.TempDir(), "all.txt")
	m.runExport(r, "--all --out "+path)

	// The first line appended by the command is the warning; the last is the
	// confirmation — so the warning precedes the export.
	warn := r.lines[before]
	if warn.kind != lineSystem || !strings.Contains(warn.text, "exporting full message history") {
		t.Errorf("first appended line = %+v, want the full-history warning", warn)
	}
	last := r.lines[len(r.lines)-1]
	if !strings.Contains(last.text, "exported 5 messages") {
		t.Errorf("last line = %+v, want the 5-message confirmation", last)
	}
}

// TestMouseToggle proves the per-OS default (off on Windows so native terminal
// selection works, on elsewhere) and that /mouse flips state and returns the
// correct Bubble Tea command for each direction on every platform.
func TestMouseToggle(t *testing.T) {
	m := newModel("ws://localhost:3000", "me", "", "ops", "")
	wantDefault := runtime.GOOS != "windows"
	if m.mouseOn != wantDefault {
		t.Fatalf("default mouseOn = %v, want %v on %s", m.mouseOn, wantDefault, runtime.GOOS)
	}

	cmd := m.runMouse("off")
	if m.mouseOn {
		t.Error("/mouse off should set mouseOn=false")
	}
	if !sameCmd(cmd, tea.DisableMouse) {
		t.Error("/mouse off should return tea.DisableMouse")
	}

	cmd = m.runMouse("on")
	if !m.mouseOn {
		t.Error("/mouse on should set mouseOn=true")
	}
	if !sameCmd(cmd, tea.EnableMouseCellMotion) {
		t.Error("/mouse on should return tea.EnableMouseCellMotion")
	}

	// No arg just reports state and issues no command.
	if cmd := m.runMouse(""); cmd != nil {
		t.Error("/mouse with no arg should not issue a command")
	}
}

// sameCmd reports whether two tea.Cmd values are the same underlying function.
func sameCmd(a, b tea.Cmd) bool {
	return a != nil && b != nil && reflect.ValueOf(a).Pointer() == reflect.ValueOf(b).Pointer()
}
