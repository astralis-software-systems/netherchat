// Package notify fires NATIVE desktop notifications for in-room events (§2.1):
// mentions, decisions, acks, and break-glass war rooms. It is entirely
// client-side — there is no push server, no APNs/FCM, no outbound network call.
// It shells out to the OS notifier (notify-send / osascript / BurntToast) and
// falls back to the terminal bell when none is available.
//
// This is the honest version of "notifications": local-only costs nothing and
// needs no infrastructure, which is exactly why APNs/FCM were rejected.
package notify

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode"
)

// title is the notification title used for every event.
const title = "⚡ Netherchat"

// Notifier delivers desktop notifications for the configured event types. The nil
// Notifier is usable and silent — every method is a no-op — so callers need not
// nil-check.
type Notifier struct {
	on   map[string]bool
	name string // this client's display name, for mention detection

	// Injectable for tests; default to the real OS notifier and terminal bell.
	osName string
	run    func(name string, args ...string) error
	bell   func()
}

// validEvents is the set of trigger names accepted in [notify] on = [...].
var validEvents = map[string]bool{
	"mention": true, "decision": true, "ack": true, "break_glass": true,
}

// New builds a Notifier for the given event triggers and this client's display
// name. Unknown trigger names are ignored. With no triggers the Notifier is silent.
func New(on []string, name string) *Notifier {
	set := make(map[string]bool)
	for _, e := range on {
		e = strings.TrimSpace(e)
		if validEvents[e] {
			set[e] = true
		}
	}
	return &Notifier{
		on:     set,
		name:   name,
		osName: runtime.GOOS,
		run:    realRun,
		bell:   realBell,
	}
}

func (n *Notifier) enabled(event string) bool { return n != nil && n.on[event] }

// Message fires a mention notification when text mentions this client's display
// name and "mention" is enabled. Only inbound messages should be passed (never
// your own echo).
func (n *Notifier) Message(room, from, text string) {
	if body, ok := n.messageBody(room, from, text); ok {
		n.fire(body)
	}
}

// Decision fires a notification for a recorded /decide.
func (n *Notifier) Decision(room, text string) {
	if body, ok := n.decisionBody(room, text); ok {
		n.fire(body)
	}
}

// Ack fires a notification for a coordination ack; quorum is the "<acked>/<members>"
// count carried by the event.
func (n *Notifier) Ack(room, tag, quorum string) {
	if body, ok := n.ackBody(room, tag, quorum); ok {
		n.fire(body)
	}
}

// BreakGlass fires a notification when a war room is created.
func (n *Notifier) BreakGlass(room string) {
	if body, ok := n.breakGlassBody(room); ok {
		n.fire(body)
	}
}

// The *Body helpers compute the notification text and whether it should fire,
// separated from the async delivery so the trigger logic is unit-tested directly.

func (n *Notifier) messageBody(room, from, text string) (string, bool) {
	if !n.enabled("mention") || !mentioned(text, n.name) {
		return "", false
	}
	return fmt.Sprintf("@%s mentioned you in #%s", from, room), true
}

func (n *Notifier) decisionBody(room, text string) (string, bool) {
	if !n.enabled("decision") {
		return "", false
	}
	return fmt.Sprintf("Decision in #%s: %s", room, truncate(text, 60)), true
}

func (n *Notifier) ackBody(room, tag, quorum string) (string, bool) {
	if !n.enabled("ack") {
		return "", false
	}
	return fmt.Sprintf("Quorum reached in #%s: %s (%s)", room, tag, quorum), true
}

func (n *Notifier) breakGlassBody(room string) (string, bool) {
	if !n.enabled("break_glass") {
		return "", false
	}
	return fmt.Sprintf("War room opened: #%s", room), true
}

// Summary renders the /whoami line, e.g. "on (mention, decision)" or "off".
func (n *Notifier) Summary() string {
	if n == nil || len(n.on) == 0 {
		return "off"
	}
	events := make([]string, 0, len(n.on))
	for e := range n.on {
		events = append(events, e)
	}
	sort.Strings(events)
	return "on (" + strings.Join(events, ", ") + ")"
}

// fire delivers a notification asynchronously so it never blocks the UI loop.
func (n *Notifier) fire(body string) { go n.deliver(title, body) }

// deliver runs the OS notifier for this platform, falling back to the terminal
// bell when there is no notifier or it fails (e.g. notify-send not installed,
// BurntToast module absent).
func (n *Notifier) deliver(title, body string) {
	if name, args := commandFor(n.osName, title, body); name != "" {
		if n.run(name, args...) == nil {
			return
		}
	}
	n.bell()
}

// commandFor returns the OS notifier command + args for an event, or ("",nil) when
// the platform has no known notifier (callers then ring the bell). It is a pure
// function so the per-OS routing is unit-tested without spawning processes.
func commandFor(osName, title, body string) (string, []string) {
	switch osName {
	case "darwin":
		// AppleScript string literals use the same \" / \\ escaping Go's %q emits.
		script := fmt.Sprintf("display notification %q with title %q", body, title)
		return "osascript", []string{"-e", script}
	case "windows":
		// BurntToast if the module is installed; Import-Module -ErrorAction Stop makes
		// its absence a non-zero exit, which deliver turns into the bell fallback.
		ps := "Import-Module BurntToast -ErrorAction Stop; New-BurntToastNotification -Text " +
			psQuote(title) + "," + psQuote(body)
		return "powershell", []string{"-NoProfile", "-NonInteractive", "-Command", ps}
	default:
		// Linux and other unix-likes.
		return "notify-send", []string{title, body}
	}
}

// mentioned reports whether text mentions name as a whole token (case-insensitive),
// so "@alice", "alice," and "hey alice!" all match but "alicebob" does not.
func mentioned(text, name string) bool {
	if name == "" {
		return false
	}
	lname := strings.ToLower(name)
	sep := func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '-'
	}
	for _, tok := range strings.FieldsFunc(strings.ToLower(text), sep) {
		if tok == lname {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return strings.TrimSpace(s[:n]) + "…"
}

// psQuote single-quotes a string for PowerShell, doubling embedded quotes.
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// realRun executes the notifier command with a short timeout (it must never hang
// the UI's notification goroutine).
func realRun(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Run()
}

// realBell rings the terminal bell on stderr (a control byte, so it does not
// disturb the alt-screen UI on stdout).
func realBell() { fmt.Fprint(os.Stderr, "\a") }
