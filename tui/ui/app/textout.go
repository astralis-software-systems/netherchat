package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/salehkreiner/netherchat/tui/eventlog"
	"github.com/salehkreiner/netherchat/tui/internal/clip"
)

// This file implements the "get text out of the chat" commands: /copy (one
// message to the system clipboard), /export (the room buffer to a file), and the
// /mouse capture toggle (off restores native terminal selection). Bubble Tea
// captures the keyboard and (by default) the mouse, so these are the supported
// ways to lift text out of a running session.

// exportMsg is one message in a form both /copy and /export can render. It is
// derived from the room's line buffer (in-memory only — you cannot export what
// the room never held).
type exportMsg struct {
	at       time.Time
	sender   string
	body     string
	fpr      string
	signed   bool
	replayed bool
	sealed   bool // promoted into the record chain (/decide /action /mark) — a "sealed decision"
}

// roomMessages extracts the room buffer's message lines — peer and own chat,
// webhook/system plaintext, and sealed-record entries — i.e. the things said in
// the room. System notices, errors, and UI blocks (invite QR, banners) are
// excluded. Order is preserved (oldest first).
func (m *Model) roomMessages(r *room) []exportMsg {
	out := make([]exportMsg, 0, len(r.lines))
	for _, l := range r.lines {
		switch l.kind {
		case lineMessage, lineServer, lineRecord:
			// Record-chain entries (/decide /action /mark) are the "sealed decisions"
			// the default export keeps; everything else is full history (--all only).
			out = append(out, exportMsg{
				at: l.at, sender: l.from, body: l.text, fpr: l.fpr,
				signed: l.signed, replayed: l.replayed, sealed: l.kind == lineRecord,
			})
		case lineSelf:
			// Self lines don't cache our own fingerprint; fill it in for export.
			out = append(out, exportMsg{
				at: l.at, sender: l.from, body: l.text, fpr: m.fingerprint,
				signed: l.signed, replayed: l.replayed,
			})
		}
	}
	return out
}

// sealedOnly keeps just the record-chain entries (the deliberately-promoted
// decisions/actions/notes). It is the default /export set: persisting full chat
// history is a quiet escape hatch around "you choose what becomes a record", so
// it is gated behind --all (§7).
func sealedOnly(msgs []exportMsg) []exportMsg {
	out := make([]exportMsg, 0, len(msgs))
	for _, m := range msgs {
		if m.sealed {
			out = append(out, m)
		}
	}
	return out
}

// exportAllWarning is shown before a full-history export so the persistence
// decision is visible at the moment it is made (§7).
const exportAllWarning = "⚠ exporting full message history — this creates a persistent record. " +
	"Use /export (no flag) to export sealed decisions only."

// --- /copy ------------------------------------------------------------------

// selectCopyMessage resolves which message /copy refers to: the most recent (no
// arg), the Nth most recent (1 = most recent), or the most recent from @handle.
func selectCopyMessage(msgs []exportMsg, arg string) (exportMsg, bool) {
	arg = strings.TrimSpace(arg)
	switch {
	case arg == "":
		if n := len(msgs); n > 0 {
			return msgs[n-1], true
		}
	case strings.HasPrefix(arg, "@"):
		name := strings.TrimPrefix(arg, "@")
		for i := len(msgs) - 1; i >= 0; i-- {
			if strings.EqualFold(msgs[i].sender, name) {
				return msgs[i], true
			}
		}
	default:
		if n, err := strconv.Atoi(arg); err == nil && n >= 1 && n <= len(msgs) {
			return msgs[len(msgs)-n], true
		}
	}
	return exportMsg{}, false
}

// runCopy implements /copy [N|@handle]: copy a single message's BODY (no
// timestamp, sender, or badge) to the system clipboard.
func (m *Model) runCopy(r *room, arg string) {
	if r == nil {
		return
	}
	msg, ok := selectCopyMessage(m.roomMessages(r), arg)
	if !ok {
		m.addSystem("✗ no message found")
		return
	}
	if clip.Copy(msg.body) == "stdout" {
		m.addSystem("clipboard unavailable — message text printed to the terminal")
	} else {
		m.addSystem("✓ copied to clipboard")
	}
}

// --- /export ----------------------------------------------------------------

// runExport implements /export [--json] [--out <path>]: write the room's current
// message buffer to a file in the working directory (it does NOT clear history —
// /vanish does that).
func (m *Model) runExport(r *room, arg string) {
	if r == nil {
		return
	}
	all, asJSON, outPath, err := parseExportArgs(arg)
	if err != nil {
		m.addError(err.Error())
		return
	}

	msgs := m.roomMessages(r)
	if all {
		m.addSystem(exportAllWarning)
	} else {
		msgs = sealedOnly(msgs)
	}
	path := outPath
	if path == "" {
		ext := "txt"
		if asJSON {
			ext = "json"
		}
		path = fmt.Sprintf("netherchat-%s-%s.%s", exportRoomName(r.name), time.Now().Format("20060102-150405"), ext)
	}

	content := exportText(msgs)
	if asJSON {
		content = exportJSON(r.name, msgs)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		m.addError("export failed: " + err.Error())
		return
	}
	noun := "messages"
	if len(msgs) == 1 {
		noun = "message"
	}
	m.addSystem(fmt.Sprintf("✓ exported %d %s to %s", len(msgs), noun, path))
}

// parseExportArgs parses "--all", "--json" and "--out <path>" from the command
// argument. Without --all the export is limited to sealed decisions (§7).
func parseExportArgs(arg string) (all, asJSON bool, out string, err error) {
	fields := strings.Fields(arg)
	for i := 0; i < len(fields); i++ {
		switch fields[i] {
		case "--all":
			all = true
		case "--json":
			asJSON = true
		case "--out":
			if i+1 >= len(fields) {
				return false, false, "", errors.New("usage: /export [--all] [--json] [--out <path>]")
			}
			out = fields[i+1]
			i++
		default:
			return false, false, "", fmt.Errorf("unknown option %q  ·  usage: /export [--all] [--json] [--out <path>]", fields[i])
		}
	}
	return all, asJSON, out, nil
}

// exportText renders the buffer as one human line per message:
//
//	[HH:MM] sender: body
//
// with a leading "[replay]" tag for replayed entries and a "?" tag for unsigned
// messages (signed is the baseline, so it carries no marker).
func exportText(msgs []exportMsg) string {
	var b strings.Builder
	for _, msg := range msgs {
		var prefix string
		if msg.replayed {
			prefix += "[replay] "
		}
		if !msg.signed {
			prefix += "? "
		}
		fmt.Fprintf(&b, "[%s] %s%s: %s\n", msg.at.Format("15:04"), prefix, msg.sender, msg.body)
	}
	return b.String()
}

// exportJSON renders the buffer as newline-delimited JSON using the exact
// eventlog "message" event schema (§1.7), so the file drops into the same
// tail --json pipelines. The message's own timestamp replaces the now() default.
func exportJSON(room string, msgs []exportMsg) string {
	var b strings.Builder
	for _, msg := range msgs {
		e := eventlog.Message(room, msg.sender, msg.fpr, msg.signed, false, msg.body, true)
		e.TS = msg.at.UTC().Format(time.RFC3339)
		j, _ := json.Marshal(e)
		b.Write(j)
		b.WriteByte('\n')
	}
	return b.String()
}

// exportRoomName makes a room name safe to drop into a filename.
func exportRoomName(s string) string {
	s = strings.TrimPrefix(s, "#")
	return strings.NewReplacer("/", "-", "\\", "-", " ", "-", ":", "-").Replace(s)
}

// --- /mouse -----------------------------------------------------------------

// runMouse toggles Bubble Tea mouse capture. With capture off, the terminal
// emulator handles the mouse, so the user can select and copy text natively —
// the simplest answer to "how do I get text out". No arg reports current state.
func (m *Model) runMouse(arg string) tea.Cmd {
	switch strings.ToLower(strings.TrimSpace(arg)) {
	case "off":
		m.mouseOn = false
		m.addSystem("mouse capture off — native terminal selection enabled (/mouse on to re-enable)")
		return tea.DisableMouse
	case "on":
		m.mouseOn = true
		m.addSystem("mouse capture on — click rooms and scroll in the TUI")
		return tea.EnableMouseCellMotion
	case "":
		m.addSystem("mouse: " + mouseState(m.mouseOn))
		return nil
	default:
		m.addError("usage: /mouse [on|off]")
		return nil
	}
}

// mouseState renders the capture flag for /mouse and /whoami.
func mouseState(on bool) string {
	if on {
		return "on"
	}
	return "off"
}
