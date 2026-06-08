package app

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mdp/qrterminal/v3"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/record"
	"github.com/salehkreiner/netherchat/tui/ui/command"
	"github.com/salehkreiner/netherchat/tui/ui/theme"
)

// defaultBreakGlassTTL is used when /break-glass is run without --ttl. It matches
// the canonical "vanishes in 4 hours" war-room example.
const defaultBreakGlassTTL = 4 * time.Hour

func buildCommands() *command.Set {
	return command.New(
		command.Command{Name: "help", Help: "list commands"},
		command.Command{Name: "theme", Args: "<name>", Help: "switch color theme",
			Complete: func(p string) []string { return command.FilterPrefix(theme.Names(), p) }},
		command.Command{Name: "font", Help: "show the recommended terminal font"},
		command.Command{Name: "whoami", Help: "show your fingerprint and session info"},
		command.Command{Name: "invite", Help: "generate a one-time invite token (with QR)"},
		command.Command{Name: "break-glass", Args: "--invite a,b --ttl 4h", Help: "stand up an ephemeral war room with one-time join links"},
		command.Command{Name: "vanish", Help: "rotate the room key and clear history"},
		command.Command{Name: "scuttle", Args: "[now|arm <dur>]", Help: "burn the room's keys and close it (dead-man's switch)",
			Complete: func(p string) []string { return command.FilterPrefix([]string{"now", "arm"}, p) }},
		command.Command{Name: "ttl", Args: "<dur|off>", Help: "set a message display TTL",
			Complete: func(p string) []string { return command.FilterPrefix([]string{"off", "10m", "1h", "24h"}, p) }},
		command.Command{Name: "exec", Args: "<action>", Help: "request an edge agent run a runbook action (signed, E2E)"},
		command.Command{Name: "send", Args: "<path>", Help: "relay a file to the room as a secure artifact transfer (E2E, relay-blind)",
			Complete: completeFilePath},
		command.Command{Name: "ack", Args: "[tag]", Help: "ack a coordination tag (typed quorum, not a reaction); no arg lists active tags"},
		command.Command{Name: "handoff", Args: "@handle", Help: "transfer the incident-commander (IC) token"},
		command.Command{Name: "ic", Help: "show who currently holds incident command"},
		command.Command{Name: "decide", Args: "<text>", Help: "promote a decision into the signed record chain"},
		command.Command{Name: "action", Args: "@handle <text>", Help: "record an action item assigned to someone"},
		command.Command{Name: "mark", Help: "promote the most recent message into the record as a note"},
		command.Command{Name: "seal", Help: "seal the record: collect signatures, write record.json + minutes.md"},
		command.Command{Name: "whois", Args: "[@handle]", Help: "show an identity's fingerprint, pin status, and published-key match"},
		command.Command{Name: "verify", Args: "[@handle [ok]]", Help: "out-of-band verify a peer via a 5-word SAS read over a side channel"},
		command.Command{Name: "join", Args: "<room>", Help: "join another room"},
		command.Command{Name: "leave", Help: "leave the current room"},
		command.Command{Name: "clear", Help: "clear the current room view"},
		command.Command{Name: "copy", Args: "[N|@handle]", Help: "copy a message body to the system clipboard"},
		command.Command{Name: "export", Args: "[--json] [--out <path>]", Help: "write this room's messages to a file"},
		command.Command{Name: "mouse", Args: "[on|off]", Help: "toggle mouse capture (off = native terminal text selection)",
			Complete: func(p string) []string { return command.FilterPrefix([]string{"on", "off"}, p) }},
		command.Command{Name: "quit", Help: "quit netherchat"},
	)
}

// runCommand executes a parsed slash command, mutating the model and optionally
// returning a tea.Cmd (for joins and quitting).
func (m *Model) runCommand(input string) tea.Cmd {
	name, arg, _ := m.cmds.Parse(input)
	r := m.activeRoom()

	switch name {
	case "help":
		m.addSystem(m.helpText())
	case "theme":
		m.runTheme(arg)
	case "font":
		m.addSystem(fmt.Sprintf("recommended font for %q: %s\n  set it in your terminal's preferences — a TUI cannot change the terminal font.\n  (the web client honors per-theme fonts directly.)", m.theme.Name, m.theme.Font))
	case "whoami":
		m.addSystem(m.whoamiText(r))
	case "invite":
		if !m.connected(r) {
			break
		}
		r.client.RequestInvite()
	case "break-glass":
		if !m.connected(r) {
			break
		}
		invitees, ttl, err := parseBreakGlass(arg)
		if err != nil {
			m.addError(err.Error())
			break
		}
		r.client.BreakGlass(invitees, int(ttl.Seconds()))
		who := "no one yet"
		if len(invitees) > 0 {
			who = strings.Join(invitees, ", ")
		}
		m.addSystem(fmt.Sprintf("break-glass: standing up a war room (ttl %s) for %s …", ttl, who))
	case "vanish":
		if !m.connected(r) {
			break
		}
		r.client.Vanish()
	case "scuttle":
		m.runScuttle(r, arg)
	case "ttl":
		m.runTTL(r, arg)
	case "exec":
		if !m.connected(r) {
			break
		}
		if arg == "" {
			m.addError("usage: /exec <action>   (a runbook action a netherchat agent allows)")
			break
		}
		if _, err := r.client.RequestExec(arg); err != nil {
			m.addError(err.Error())
		}
	case "send":
		m.runSend(r, arg)
	case "ack":
		m.runAck(r, arg)
	case "handoff":
		m.runHandoff(r, arg)
	case "ic":
		m.runIC(r)
	case "decide":
		m.runDecide(r, arg)
	case "action":
		m.runAction(r, arg)
	case "mark":
		m.runMark(r)
	case "seal":
		m.runSeal(r)
	case "whois":
		return m.runWhois(arg)
	case "verify":
		return m.runVerify(arg)
	case "join":
		if arg == "" {
			m.addError("usage: /join <room>")
			break
		}
		return m.joinRoom(arg, "")
	case "leave":
		return m.leaveRoom(m.active)
	case "clear":
		if r != nil {
			r.lines = nil
			m.syncViewport()
		}
	case "copy":
		m.runCopy(r, arg)
	case "export":
		m.runExport(r, arg)
	case "mouse":
		return m.runMouse(arg)
	case "quit":
		m.closeAll()
		return tea.Quit
	default:
		m.addError("unknown command /" + name + "  (try /help)")
	}
	return nil
}

func (m *Model) connected(r *room) bool {
	if r == nil || r.client == nil || !r.connected {
		m.addError("not connected to this room yet")
		return false
	}
	return true
}

func (m *Model) runTheme(arg string) {
	if arg == "" {
		m.addSystem("current theme: " + m.theme.Name + "  ·  available: " + strings.Join(theme.Names(), ", "))
		return
	}
	th, ok := theme.Get(arg)
	if !ok {
		m.addError("unknown theme " + arg + "  ·  available: " + strings.Join(theme.Names(), ", "))
		return
	}
	m.theme = th
	m.applyInputTheme()
	m.addSystem("theme set to " + th.Name + "  (font: " + th.Font + ")")
	m.syncViewport()
}

func (m *Model) runTTL(r *room, arg string) {
	if !m.connected(r) {
		return
	}
	switch arg {
	case "":
		if r.ttl > 0 {
			m.addSystem("message ttl: " + r.ttl.String())
		} else {
			m.addSystem("message ttl: off")
		}
	case "off", "0":
		r.ttl = 0
		r.client.SetTTL(0)
	default:
		d, err := time.ParseDuration(arg)
		if err != nil || d <= 0 {
			m.addError("bad duration " + arg + "  (e.g. 10m, 1h, 24h, off)")
			return
		}
		r.ttl = d
		r.client.SetTTL(int(d.Seconds()))
	}
}

// runScuttle implements /scuttle (§1.6): the dead-man's switch under manual
// control. "/scuttle now" burns the room immediately; "/scuttle arm <dur>" shows
// a visible countdown to everyone and auto-burns when it reaches zero. Both are
// server-orchestrated, so the burn arrives back as a scuttle control the whole
// room renders identically.
func (m *Model) runScuttle(r *room, arg string) {
	if !m.connected(r) {
		return
	}
	fields := strings.Fields(arg)
	sub := "now"
	if len(fields) > 0 {
		sub = strings.ToLower(fields[0])
	}
	switch sub {
	case "now":
		r.client.ScuttleNow()
		m.addSystem("scuttling the room now — keys will be destroyed")
	case "arm":
		if len(fields) < 2 {
			m.addError("usage: /scuttle arm <dur>   (e.g. 10m)")
			return
		}
		d, err := time.ParseDuration(fields[1])
		if err != nil || d <= 0 {
			m.addError("bad duration " + fields[1] + "  (e.g. 30s, 10m, 1h)")
			return
		}
		r.client.ScuttleArm(int(d.Seconds()))
	default:
		m.addError("usage: /scuttle [now|arm <dur>]")
	}
}

// scuttleReasonSuffix renders the human reason a room scuttled, for the
// attestation line. An empty/unknown reason yields no suffix.
func scuttleReasonSuffix(reason string) string {
	switch reason {
	case "idle":
		return " (idle timeout)"
	case "owner_loss":
		return " (owner disconnected)"
	case "manual":
		return " (triggered)"
	case "armed":
		return " (armed countdown elapsed)"
	default:
		return ""
	}
}

// runAck implements /ack (§2.2). With a tag it sends a signed, E2E ack and the
// member list shows the running quorum; with no argument it lists active tags.
// /ack is a typed coordination primitive — deliberately NOT a reaction emoji.
func (m *Model) runAck(r *room, arg string) {
	if !m.connected(r) {
		return
	}
	if arg == "" {
		m.addSystem(m.ackStatusText(r))
		return
	}
	tag := strings.Fields(arg)[0]
	if err := r.client.Ack(tag); err != nil {
		m.addError(err.Error())
	}
}

// ackStatusText lists the active ack tags and their quorum counts.
func (m *Model) ackStatusText(r *room) string {
	acks := r.client.AckState()
	if len(acks) == 0 {
		return "no active ack tags"
	}
	var b strings.Builder
	b.WriteString("active acks:\n")
	for _, tag := range sortedKeys(acks) {
		b.WriteString(fmt.Sprintf("  %-20s %s\n", tag, acks[tag]))
	}
	return strings.TrimRight(b.String(), "\n")
}

// runHandoff implements /handoff @handle (§2.2): transfer the IC token.
func (m *Model) runHandoff(r *room, arg string) {
	if !m.connected(r) {
		return
	}
	if arg == "" {
		m.addError("usage: /handoff @handle")
		return
	}
	handle := strings.TrimPrefix(strings.Fields(arg)[0], "@")
	if err := r.client.Handoff(handle); err != nil {
		m.addError(err.Error())
	}
}

// runIC implements /ic: show who currently holds incident command.
func (m *Model) runIC(r *room) {
	if !m.connected(r) {
		return
	}
	name, fpr, isSelf, ok := r.client.ICHolder()
	if !ok {
		m.addSystem("incident commander: (none yet)")
		return
	}
	who := "@" + name
	if isSelf {
		who += " (you)"
	}
	m.addSystem("incident commander: " + who + "  " + shortFpr(fpr))
}

// runDecide implements /decide <text> (§1.4): promote a decision into the signed
// record chain.
func (m *Model) runDecide(r *room, arg string) {
	if !m.connected(r) {
		return
	}
	if strings.TrimSpace(arg) == "" {
		m.addError("usage: /decide <what was decided>")
		return
	}
	if err := r.client.Decide(arg); err != nil {
		m.addError(err.Error())
	}
}

// runAction implements /action @handle <text>: record an attributed action item.
func (m *Model) runAction(r *room, arg string) {
	if !m.connected(r) {
		return
	}
	fields := strings.Fields(arg)
	if len(fields) < 2 {
		m.addError("usage: /action @handle <text>")
		return
	}
	handle := fields[0]
	text := strings.TrimSpace(strings.TrimPrefix(arg, handle))
	if err := r.client.Action(handle, text); err != nil {
		m.addError(err.Error())
	}
}

// runMark implements /mark: promote the most recent message into the record.
func (m *Model) runMark(r *room) {
	if !m.connected(r) {
		return
	}
	if err := r.client.Mark(); err != nil {
		m.addError(err.Error())
	}
}

// runSeal implements /seal (§1.4): initiate a seal, or co-sign a pending one.
func (m *Model) runSeal(r *room) {
	if !m.connected(r) {
		return
	}
	if err := r.client.Seal(); err != nil {
		m.addError(err.Error())
	}
}

// renderRecordEntry styles a sealed-record entry for the room view. Live entries
// are marked with a 📌 and the kind; replayed entries (§2.7) are dimmed with a
// bracketed original timestamp and cannot be marked again.
func (m *Model) renderRecordEntry(e client.EvRecordEntry) string {
	ts := e.At.UTC().Format("15:04")
	if e.Replayed {
		tail := "  [" + e.Kind + "]"
		return m.st(m.theme.Muted).Render(fmt.Sprintf("[REPLAY %s] %s: %s%s", ts, e.AuthorName, e.Body, tail))
	}
	pin := m.st(m.theme.Accent).Bold(true).Render("📌 " + e.Kind)
	who := m.st(m.theme.Accent2).Bold(true).Render(e.AuthorName)
	detail := ": " + e.Body
	if e.Kind == record.KindAction && e.Actionee != "" {
		detail = " → @" + e.Actionee + ": " + e.Body
	}
	return m.st(m.theme.Muted).Render(ts+" ") + pin + " " + who + m.st(m.theme.Text).Render(detail)
}

// writeSealedRecord writes the two seal artifacts to the current directory:
// record.json (machine-readable) and minutes.md (human-readable). The record is a
// deliberately-created artifact the operator chose to keep, so it lands in cwd.
func writeSealedRecord(rec *record.SealedRecord) error {
	jb, err := rec.Marshal()
	if err != nil {
		return err
	}
	if err := os.WriteFile("record.json", jb, 0o644); err != nil {
		return err
	}
	return os.WriteFile("minutes.md", []byte(record.RenderMinutes(rec)), 0o644)
}

// renderRouteFired builds the banner shown in an intake room when an inbound
// alert matched a [[route]] rule and spawned an incident war room (§1.3).
func (m *Model) renderRouteFired(e client.EvRouteFired) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("🔥 auto-war-room: alert matched rule %d → #%s spawned\n", e.TriggerRule, e.Room))
	b.WriteString("   ephemeral · invite-only · end-to-end encrypted\n")
	if len(e.Invitees) > 0 {
		b.WriteString("   invited: " + strings.Join(e.Invitees, ", ") + "\n")
	}
	b.WriteString(fmt.Sprintf("   ttl: %s  ·  one-time join links were delivered to the alert source",
		(time.Duration(e.TTLSeconds) * time.Second)))
	return b.String()
}

// sourceLabel describes where the identity key came from, for /whoami and /whois.
func (m *Model) sourceLabel() string {
	if m.source == "" {
		return "(connecting…)"
	}
	return m.source
}

func (m *Model) helpText() string {
	var b strings.Builder
	b.WriteString("commands:\n")
	for _, c := range m.cmds.Commands() {
		name := "/" + c.Name
		if c.Args != "" {
			name += " " + c.Args
		}
		b.WriteString(fmt.Sprintf("  %-18s %s\n", name, c.Help))
	}
	b.WriteString("keys: tab complete · ↑/↓ scroll or pick suggestion · ctrl+n/ctrl+p switch room · ctrl+c quit")
	return b.String()
}

func (m *Model) whoamiText(r *room) string {
	var b strings.Builder
	b.WriteString("fingerprint: " + m.fingerprint + "\n")
	b.WriteString("identity:    " + m.sourceLabel() + "\n")
	b.WriteString("name:        " + m.name + "\n")
	b.WriteString("server:      " + m.url + "\n")
	b.WriteString("mouse:       " + mouseState(m.mouseOn) + "\n")
	if r != nil {
		enc := "establishing…"
		if r.keyReady {
			enc = "end-to-end encrypted (NaCl: X25519 + XChaCha20-Poly1305)"
		}
		b.WriteString("room:        #" + r.name + "\n")
		b.WriteString("encryption:  " + enc + "\n")
		b.WriteString(fmt.Sprintf("verified:    %d of %d peers (SAS)\n", m.verifiedCount(), len(r.order)))
		caps := []string{}
		if r.inviteOnly {
			caps = append(caps, "invite-only")
		}
		if r.webhook {
			caps = append(caps, "webhook")
		}
		if len(caps) > 0 {
			b.WriteString("policy:      " + strings.Join(caps, ", "))
		} else {
			b.WriteString("policy:      open")
		}
	}
	return b.String()
}

// parseBreakGlass parses the /break-glass argument string, e.g.
// "--invite alice,bob --ttl 4h". Both "--flag value" and "--flag=value" forms are
// accepted. Invitees are comma-separated. TTL defaults to 4h when omitted; the
// server clamps it to a sane range regardless.
func parseBreakGlass(arg string) (invitees []string, ttl time.Duration, err error) {
	ttl = defaultBreakGlassTTL
	fields := strings.Fields(arg)
	for i := 0; i < len(fields); i++ {
		flag := fields[i]
		val := ""
		if eq := strings.IndexByte(flag, '='); eq >= 0 {
			flag, val = flag[:eq], flag[eq+1:]
		} else if i+1 < len(fields) && !strings.HasPrefix(fields[i+1], "-") {
			val = fields[i+1]
			i++
		}
		switch strings.TrimLeft(flag, "-") {
		case "invite", "invitees", "i":
			for _, part := range strings.Split(val, ",") {
				if p := strings.TrimSpace(part); p != "" {
					invitees = append(invitees, p)
				}
			}
		case "ttl", "t":
			d, perr := time.ParseDuration(val)
			if perr != nil || d <= 0 {
				return nil, 0, fmt.Errorf("bad --ttl %q  (e.g. 30m, 4h, 24h)", val)
			}
			ttl = d
		default:
			return nil, 0, fmt.Errorf("unknown flag %q  ·  usage: /break-glass --invite alice,bob --ttl 4h", fields[i])
		}
	}
	return invitees, ttl, nil
}

// renderBreakGlass builds the war-room banner: the new room, its hard deadline,
// and a one-time join link per invitee, ready to paste to each person.
func (m *Model) renderBreakGlass(e client.EvBreakGlass) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("🔥 break-glass war room: #%s\n", e.Room))
	b.WriteString("   ephemeral · invite-only · end-to-end encrypted · vanishes on a timer\n")
	if !e.Expires.IsZero() {
		b.WriteString(fmt.Sprintf("   expires: %s  (in %s)\n", e.Expires.Format("2006-01-02 15:04"), remaining(e.Expires)))
	}
	if len(e.Invites) == 0 {
		b.WriteString("\n   no invitees named — add people with /invite once you're in the room.\n")
	} else {
		b.WriteString("\n   send each person their one-time link:\n")
		width := 0
		for _, in := range e.Invites {
			if len(in.Name) > width {
				width = len(in.Name)
			}
		}
		for _, in := range e.Invites {
			b.WriteString(fmt.Sprintf("     %-*s  %s\n", width, in.Name, m.joinLink(e.Room, in.Token)))
		}
	}
	b.WriteString(fmt.Sprintf("\n   you're in #%s (background) — switch to it with ctrl+n", e.Room))
	return b.String()
}

// joinLink builds the browser join URL for a room + one-time token.
func (m *Model) joinLink(room, token string) string {
	base := strings.TrimRight(m.webBase(), "/")
	q := url.Values{"room": {room}, "token": {token}}
	return base + "/join?" + q.Encode()
}

// webBase is the base URL of the browser join client. It uses --web-url when
// provided, otherwise derives it from the relay URL (ws→http, wss→https, path
// dropped) — correct for the common deployment where the web client and relay
// share an origin.
func (m *Model) webBase() string {
	if m.webURL != "" {
		return m.webURL
	}
	return deriveWebBase(m.url)
}

// deriveWebBase maps a relay URL to the web client's origin.
func deriveWebBase(serverURL string) string {
	u, err := url.Parse(serverURL)
	if err != nil || u.Host == "" {
		return serverURL
	}
	switch u.Scheme {
	case "ws":
		u.Scheme = "http"
	case "wss":
		u.Scheme = "https"
	}
	return u.Scheme + "://" + u.Host
}

// remaining formats the duration from now until t, rounded to the minute.
func remaining(t time.Time) string {
	d := time.Until(t).Round(time.Minute)
	if d < 0 {
		d = 0
	}
	return d.String()
}

// renderInvite builds the multi-line block (hint + QR) shown for an invite.
func (m *Model) renderInvite(room string, e client.EvInvite) string {
	var qr strings.Builder
	qrterminal.GenerateHalfBlock(e.Token, qrterminal.L, &qr)

	var b strings.Builder
	b.WriteString(fmt.Sprintf("one-time invite for #%s:\n", room))
	b.WriteString("  token: " + e.Token + "\n")
	b.WriteString(fmt.Sprintf("  join:  netherchat connect %s --room %s --invite %s\n", m.url, room, e.Token))
	if !e.Expires.IsZero() {
		b.WriteString("  expires: " + e.Expires.Format("2006-01-02 15:04") + "\n")
	}
	b.WriteString(qr.String())
	return b.String()
}
