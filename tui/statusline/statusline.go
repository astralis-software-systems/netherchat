// Package statusline is the bridge between the running TUI and a prompt segment
// (§2.3): the client writes a tiny JSON state file on every state change, and
// `netherchat status` reads it and formats a compact segment for tmux, starship,
// or a shell prompt. The status command never connects to a server — it only reads
// local state, so it returns instantly and is safe to call from a prompt on every
// keypress.
package statusline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
)

// State is the whole snapshot the TUI writes. Rooms are ordered with the active
// room first, so a prompt segment can show Rooms[0].
type State struct {
	Rooms []Room `json:"rooms"`
}

// Room is one room's glanceable state. The JSON shape is the stable contract for
// `netherchat status --json`.
type Room struct {
	Name      string `json:"name"`
	Unread    int    `json:"unread"`
	IC        string `json:"ic,omitempty"`
	Encrypted bool   `json:"encrypted"`
	Transport string `json:"transport"` // "relay" | "direct" | ""
}

// DefaultPath is where the TUI writes its status, alongside the identity file
// (%AppData%\netherchat on Windows, ~/.config/netherchat on Linux, …).
func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "netherchat", "status.json"), nil
}

// Write atomically writes the state to path (creating the directory), so a prompt
// reading concurrently never sees a half-written file.
func Write(path string, s State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".status-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

// Read loads the state from path. exists is false (with a nil error) when the file
// is absent — the normal case when no client is running.
func Read(path string) (s State, exists bool, err error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return State{}, false, nil
	}
	if err != nil {
		return State{}, false, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return State{}, false, err
	}
	return s, true, nil
}

// Remove deletes the state file (called when the client exits cleanly). A missing
// file is not an error.
func Remove(path string) {
	if path != "" {
		_ = os.Remove(path)
	}
}

// JSON renders the state as the `--json` output (the documented {"rooms":[…]} shape).
func JSON(s State) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// starshipSegment is the custom-module shape starship expects.
type starshipSegment struct {
	Text  string `json:"text"`
	Style string `json:"style"`
	When  bool   `json:"when"`
}

// Format renders the active room (Rooms[0]) as a prompt segment in the given format
// ("plain", "tmux", or "starship"). It returns "" when there is no active room, so
// a prompt shows nothing when no war room is open.
func Format(s State, format string) string {
	if len(s.Rooms) == 0 {
		return ""
	}
	r := s.Rooms[0]
	switch format {
	case "tmux":
		seg := "#[fg=colour135]⚡#" + r.Name + "#[fg=colour240]"
		if r.Unread > 0 {
			seg += " " + strconv.Itoa(r.Unread) + "↑"
		}
		return seg
	case "starship":
		b, _ := json.Marshal(starshipSegment{Text: compact(r), Style: "bold purple", When: true})
		return string(b)
	default: // plain
		return plain(r)
	}
}

// plain is "⚡#ops 3↑ IC:alice" — name, unread (when >0), and IC holder (when set).
func plain(r Room) string {
	s := "⚡#" + r.Name
	if r.Unread > 0 {
		s += " " + strconv.Itoa(r.Unread) + "↑"
	}
	if r.IC != "" {
		s += " IC:" + r.IC
	}
	return s
}

// compact is "⚡#ops 3↑" — name and unread only (for tmux/starship segments).
func compact(r Room) string {
	s := "⚡#" + r.Name
	if r.Unread > 0 {
		s += " " + strconv.Itoa(r.Unread) + "↑"
	}
	return s
}
