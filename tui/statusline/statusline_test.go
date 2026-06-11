package statusline

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func sample() State {
	return State{Rooms: []Room{
		{Name: "ops", Unread: 3, IC: "alice", Encrypted: true, Transport: "relay"},
		{Name: "alerts", Unread: 0, Encrypted: true, Transport: "relay"},
	}}
}

func TestPlainFormat(t *testing.T) {
	if got := Format(sample(), "plain"); got != "⚡#ops 3↑ IC:alice" {
		t.Fatalf("plain = %q", got)
	}
	// No unread, no IC → just the room.
	if got := Format(State{Rooms: []Room{{Name: "ops"}}}, "plain"); got != "⚡#ops" {
		t.Fatalf("plain (bare) = %q", got)
	}
}

func TestTmuxFormatHasColorCodes(t *testing.T) {
	got := Format(sample(), "tmux")
	if !strings.Contains(got, "#[fg=colour") || !strings.Contains(got, "⚡#ops") || !strings.Contains(got, "3↑") {
		t.Fatalf("tmux = %q", got)
	}
}

func TestStarshipFormatIsValidJSON(t *testing.T) {
	got := Format(sample(), "starship")
	if !json.Valid([]byte(got)) {
		t.Fatalf("starship output is not valid JSON: %q", got)
	}
	var seg struct {
		Text  string `json:"text"`
		Style string `json:"style"`
		When  bool   `json:"when"`
	}
	if err := json.Unmarshal([]byte(got), &seg); err != nil {
		t.Fatalf("decode starship: %v", err)
	}
	if seg.Text != "⚡#ops 3↑" || seg.Style != "bold purple" || !seg.When {
		t.Fatalf("starship segment = %+v", seg)
	}
}

func TestJSONParsesStrict(t *testing.T) {
	out := JSON(sample())
	dec := json.NewDecoder(strings.NewReader(out))
	dec.DisallowUnknownFields()
	var s State
	if err := dec.Decode(&s); err != nil {
		t.Fatalf("strict decode of --json output: %v\n%s", err, out)
	}
	if len(s.Rooms) != 2 || s.Rooms[0].Name != "ops" || s.Rooms[0].Unread != 3 || s.Rooms[0].IC != "alice" {
		t.Fatalf("decoded state = %+v", s)
	}
}

func TestEmptyStateFormatsEmpty(t *testing.T) {
	for _, f := range []string{"plain", "tmux", "starship"} {
		if got := Format(State{}, f); got != "" {
			t.Fatalf("empty %s = %q, want empty", f, got)
		}
	}
}

func TestWriteReadRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "status.json")

	// Absent file reads as not-exists, no error.
	if _, exists, err := Read(path); err != nil || exists {
		t.Fatalf("Read(absent) = exists %v, err %v", exists, err)
	}

	if err := Write(path, sample()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, exists, err := Read(path)
	if err != nil || !exists {
		t.Fatalf("Read after Write: exists %v, err %v", exists, err)
	}
	if len(got.Rooms) != 2 || got.Rooms[0].Name != "ops" {
		t.Fatalf("round-tripped state = %+v", got)
	}

	// Clean exit removes the file.
	Remove(path)
	if _, exists, _ := Read(path); exists {
		t.Fatal("status file should be gone after Remove")
	}
}
