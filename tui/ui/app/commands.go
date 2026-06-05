package app

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mdp/qrterminal/v3"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/ui/command"
	"github.com/salehkreiner/netherchat/tui/ui/theme"
)

func buildCommands() *command.Set {
	return command.New(
		command.Command{Name: "help", Help: "list commands"},
		command.Command{Name: "theme", Args: "<name>", Help: "switch color theme",
			Complete: func(p string) []string { return command.FilterPrefix(theme.Names(), p) }},
		command.Command{Name: "font", Help: "show the recommended terminal font"},
		command.Command{Name: "whoami", Help: "show your fingerprint and session info"},
		command.Command{Name: "invite", Help: "generate a one-time invite token (with QR)"},
		command.Command{Name: "vanish", Help: "rotate the room key and clear history"},
		command.Command{Name: "ttl", Args: "<dur|off>", Help: "set a message display TTL",
			Complete: func(p string) []string { return command.FilterPrefix([]string{"off", "10m", "1h", "24h"}, p) }},
		command.Command{Name: "exec", Args: "<command>", Help: "run an allow-listed command on the server"},
		command.Command{Name: "join", Args: "<room>", Help: "join another room"},
		command.Command{Name: "leave", Help: "leave the current room"},
		command.Command{Name: "clear", Help: "clear the current room view"},
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
	case "vanish":
		if !m.connected(r) {
			break
		}
		r.client.Vanish()
	case "ttl":
		m.runTTL(r, arg)
	case "exec":
		if !m.connected(r) {
			break
		}
		if arg == "" {
			m.addError("usage: /exec <command>")
			break
		}
		r.client.Exec(arg)
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
	b.WriteString("name:        " + m.name + "\n")
	b.WriteString("server:      " + m.url + "\n")
	if r != nil {
		enc := "establishing…"
		if r.keyReady {
			enc = "end-to-end encrypted (NaCl: X25519 + XChaCha20-Poly1305)"
		}
		b.WriteString("room:        #" + r.name + "\n")
		b.WriteString("encryption:  " + enc + "\n")
		caps := []string{}
		if r.inviteOnly {
			caps = append(caps, "invite-only")
		}
		if r.webhook {
			caps = append(caps, "webhook")
		}
		if r.execEnabled {
			caps = append(caps, "exec")
		}
		if len(caps) > 0 {
			b.WriteString("policy:      " + strings.Join(caps, ", "))
		} else {
			b.WriteString("policy:      open")
		}
	}
	return b.String()
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
