// Package app is the M1 Bubble Tea TUI: a scrollback viewport plus a message
// input, wired to the client core. It is intentionally minimal — no themes, no
// slash commands, no member sidebar. Those arrive at M3. The point of M1 is to
// see encrypted messages flow between two terminals.
package app

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/salehkreiner/netherchat/tui/client"
)

// A restrained slice of the brand palette. The full, switchable theme system is
// M3; here we only colour the chrome so the M1 client doesn't look like 1998.
var (
	cViolet = lipgloss.Color("#7c3aed")
	cSoft   = lipgloss.Color("#a78bfa")
	cMuted  = lipgloss.Color("#7c6fa0")
	cErr    = lipgloss.Color("#ff6b6b")

	titleStyle = lipgloss.NewStyle().Foreground(cViolet).Bold(true)
	mutedStyle = lipgloss.NewStyle().Foreground(cMuted)
	otherStyle = lipgloss.NewStyle().Foreground(cSoft).Bold(true)
	selfStyle  = lipgloss.NewStyle().Foreground(cMuted).Bold(true)
	sysStyle   = lipgloss.NewStyle().Foreground(cMuted).Italic(true)
	errStyle   = lipgloss.NewStyle().Foreground(cErr)
)

type eventMsg struct{ ev client.Event }
type disconnectedMsg struct{}

// Model is the Bubble Tea model for the chat view.
type Model struct {
	c    *client.Client
	room string
	name string
	fpr  string

	vp    viewport.Model
	input textinput.Model

	lines    []string
	keyReady bool
	selfID   string
	ready    bool
	width    int
}

// New builds the model for a connected client.
func New(c *client.Client, room, name, fingerprint string) Model {
	ti := textinput.New()
	ti.Placeholder = "Type a message and press Enter…"
	ti.Prompt = mutedStyle.Render("> ")
	ti.CharLimit = 4000
	ti.Focus()
	return Model{c: c, room: room, name: name, fpr: fingerprint, input: ti}
}

// Run starts the Bubble Tea program (alt screen + mouse scroll).
func Run(c *client.Client, room, name, fingerprint string) error {
	p := tea.NewProgram(New(c, room, name, fingerprint), tea.WithAltScreen(), tea.WithMouseCellMotion())
	_, err := p.Run()
	return err
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(textinput.Blink, listen(m.c))
}

// listen blocks for the next client event (or disconnect) and turns it into a
// tea.Msg. Re-issued after each event to keep the stream flowing.
func listen(c *client.Client) tea.Cmd {
	return func() tea.Msg {
		select {
		case ev := <-c.Events():
			return eventMsg{ev}
		case <-c.Done():
			return disconnectedMsg{}
		}
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		header, footer := m.headerView(), m.footerView()
		vpHeight := msg.Height - lipgloss.Height(header) - lipgloss.Height(footer)
		if vpHeight < 1 {
			vpHeight = 1
		}
		if !m.ready {
			m.vp = viewport.New(msg.Width, vpHeight)
			m.ready = true
		} else {
			m.vp.Width = msg.Width
			m.vp.Height = vpHeight
		}
		m.input.Width = msg.Width - 4
		m.renderContent()
		return m, nil

	case tea.MouseMsg:
		var cmd tea.Cmd
		m.vp, cmd = m.vp.Update(msg)
		return m, cmd

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			_ = m.c.Close()
			return m, tea.Quit
		case "enter":
			text := strings.TrimSpace(m.input.Value())
			if text != "" {
				if err := m.c.Send(text); err != nil {
					m.appendLine(errStyle.Render("⚠ " + err.Error()))
				}
				m.input.Reset()
			}
			return m, nil
		case "pgup", "pgdown", "home", "end", "ctrl+u", "ctrl+d":
			var cmd tea.Cmd
			m.vp, cmd = m.vp.Update(msg)
			return m, cmd
		default:
			var cmd tea.Cmd
			m.input, cmd = m.input.Update(msg)
			return m, cmd
		}

	case eventMsg:
		m.handleEvent(msg.ev)
		return m, listen(m.c)

	case disconnectedMsg:
		m.appendLine(sysStyle.Render("* connection closed"))
		return m, tea.Quit
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m *Model) handleEvent(e client.Event) {
	switch ev := e.(type) {
	case client.EvConnected:
		m.selfID = ev.SelfID
		if len(ev.Members) == 0 {
			m.appendSys(fmt.Sprintf("connected to #%s — you're the first one here", m.room))
		} else {
			m.appendSys("connected — present: " + strings.Join(ev.Members, ", "))
		}
	case client.EvKeyReady:
		m.keyReady = true
		m.appendSys(fmt.Sprintf("🔒 end-to-end encryption ready (epoch %d)", ev.Epoch))
	case client.EvMessage:
		m.appendLine(m.formatMessage(ev))
	case client.EvMemberJoined:
		m.appendSys(ev.Name + " joined")
	case client.EvMemberLeft:
		name := ev.Name
		if name == "" {
			name = ev.ID
		}
		m.appendSys(name + " left")
	case client.EvError:
		m.appendLine(errStyle.Render("⚠ " + ev.Err.Error()))
	case client.EvDisconnected:
		// Done() will follow with disconnectedMsg; nothing to add here.
	}
}

func (m Model) formatMessage(ev client.EvMessage) string {
	ts := mutedStyle.Render(ev.At.Format("15:04") + " ")
	if ev.Self {
		return ts + selfStyle.Render(ev.FromName+": ") + ev.Text
	}
	return ts + otherStyle.Render(ev.FromName+": ") + ev.Text
}

func (m *Model) appendLine(s string) {
	m.lines = append(m.lines, s)
	m.renderContent()
}

func (m *Model) appendSys(s string) { m.appendLine(sysStyle.Render("* " + s)) }

func (m *Model) renderContent() {
	if !m.ready {
		return
	}
	wrapped := lipgloss.NewStyle().Width(m.vp.Width).Render(strings.Join(m.lines, "\n"))
	m.vp.SetContent(wrapped)
	m.vp.GotoBottom()
}

func (m Model) View() string {
	if !m.ready {
		return "initializing…"
	}
	return lipgloss.JoinVertical(lipgloss.Left, m.headerView(), m.vp.View(), m.footerView())
}

func (m Model) headerView() string {
	lock := mutedStyle.Render("establishing encryption…")
	if m.keyReady {
		lock = lipgloss.NewStyle().Foreground(cSoft).Render("🔒 E2E")
	}
	title := titleStyle.Render(" netherchat ") +
		mutedStyle.Render(fmt.Sprintf("#%s · you: %s · %s", m.room, m.name, "")) + lock
	return title + "\n" + mutedStyle.Render(divider(m.width))
}

func (m Model) footerView() string {
	return mutedStyle.Render(divider(m.width)) + "\n" + m.input.View()
}

func divider(w int) string {
	if w < 1 {
		w = 1
	}
	return strings.Repeat("─", w)
}
