// Package app is the Netherchat terminal UI: a themed, multi-room Bubble Tea
// client. It holds one client core per joined room (one WebSocket each), a room
// sidebar with unread counts, a member list, slash commands with autocomplete,
// and inline code rendering. The 8 themes switch instantly (R2).
package app

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/ui/command"
	"github.com/salehkreiner/netherchat/tui/ui/theme"
)

// Model is the Bubble Tea model for the whole client.
type Model struct {
	url, name, identityPath, notifyCmd string
	webURL                             string // base URL of the web join client, for /break-glass links
	fingerprint                        string
	source                             string                  // where the identity came from (ssh-agent, key file, generated)
	trust                              []TrustEntry            // client-side identity pins from netherchat.toml
	verified                           map[string]*verifyEntry // SAS-verification state, keyed by peer fingerprint

	cmds  *command.Set
	theme theme.Theme

	session map[string]*room
	order   []string
	active  string

	input textinput.Model
	vp    viewport.Model

	suggestions []command.Suggestion
	suggestIdx  int

	width, height             int
	sidebarW, membersW, bodyH int
	ready                     bool

	initialInvite string
}

// Run connects to the initial room and runs the TUI. invite is the one-time
// token for the initial room (empty for open rooms). webURL is the base URL of
// the browser join client, used to build /break-glass invite links. trust holds
// the client-side identity pins parsed from netherchat.toml.
func Run(url, name, identityPath, room, notifyCmd, invite, webURL string, trust []TrustEntry) error {
	m := newModel(url, name, identityPath, room, notifyCmd)
	m.initialInvite = invite
	m.webURL = webURL
	m.trust = trust
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion())
	_, err := p.Run()
	return err
}

func newModel(url, name, identityPath, roomName, notifyCmd string) *Model {
	m := &Model{
		url: url, name: name, identityPath: identityPath, notifyCmd: notifyCmd,
		cmds:     buildCommands(),
		theme:    theme.Default(),
		session:  map[string]*room{},
		verified: map[string]*verifyEntry{},
		input:    textinput.New(),
	}
	m.input.Placeholder = "Message, or /command (try /help)…"
	m.input.Prompt = "> "
	m.input.CharLimit = 4000
	m.input.Focus()
	m.applyInputTheme()

	m.session[roomName] = newRoom(roomName)
	m.order = []string{roomName}
	m.active = roomName
	return m
}

// --- Bubble Tea messages ----------------------------------------------------

type roomConnectedMsg struct {
	name string
	c    *client.Client
	err  error
}
type roomEventMsg struct {
	name string
	ev   client.Event
}
type roomGoneMsg struct{ name string }
type tickMsg time.Time

func connectRoom(url, room, name, idPath, token string) tea.Cmd {
	return func() tea.Msg {
		c, err := client.New(url, room, name, idPath)
		if err != nil {
			return roomConnectedMsg{room, nil, err}
		}
		if token != "" {
			c.UseInviteToken(token)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := c.Connect(ctx); err != nil {
			return roomConnectedMsg{room, nil, err}
		}
		return roomConnectedMsg{room, c, nil}
	}
}

func listenRoom(name string, c *client.Client) tea.Cmd {
	return func() tea.Msg {
		select {
		case ev := <-c.Events():
			return roomEventMsg{name, ev}
		case <-c.Done():
			return roomGoneMsg{name}
		}
	}
}

func tickEvery() tea.Cmd {
	return tea.Tick(15*time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m *Model) Init() tea.Cmd {
	return tea.Batch(textinput.Blink, connectRoom(m.url, m.active, m.name, m.identityPath, m.initialInvite), tickEvery())
}

// --- Update -----------------------------------------------------------------

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.resize(msg.Width, msg.Height)
		return m, nil

	case tea.KeyMsg:
		return m.onKey(msg)

	case tea.MouseMsg:
		if msg.Action == tea.MouseActionPress && msg.Button == tea.MouseButtonLeft {
			m.handleClick(msg.X, msg.Y)
			return m, nil
		}
		var cmd tea.Cmd
		m.vp, cmd = m.vp.Update(msg)
		return m, cmd

	case roomConnectedMsg:
		return m, m.onRoomConnected(msg)

	case roomEventMsg:
		cmd := m.handleRoomEvent(msg.name, msg.ev)
		var listen tea.Cmd
		if r, ok := m.session[msg.name]; ok && r.client != nil {
			listen = listenRoom(msg.name, r.client)
		}
		return m, tea.Batch(cmd, listen)

	case roomGoneMsg:
		if r, ok := m.session[msg.name]; ok {
			r.connected = false
			r.keyReady = false
			r.appendSystem("disconnected")
			if msg.name == m.active {
				m.syncViewport()
			}
		}
		return m, nil

	case tickMsg:
		now := time.Now()
		changed := false
		for _, r := range m.session {
			if r.pruneExpired(now) && r.name == m.active {
				changed = true
			}
		}
		if changed {
			m.syncViewport()
		}
		return m, tickEvery()

	case whoisFetchMsg:
		switch {
		case msg.err != nil:
			m.addError(fmt.Sprintf("  keys for @%s: fetch failed (%v)", msg.handle, msg.err))
		case msg.found:
			m.addSystem(fmt.Sprintf("  @%s: fingerprint FOUND among %d published key(s) at %s ✓", msg.handle, msg.count, msg.url))
		default:
			m.addSystem(fmt.Sprintf("  @%s: fingerprint NOT in %d published key(s) at %s ✗", msg.handle, msg.count, msg.url))
		}
		return m, nil
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m *Model) onKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		m.closeAll()
		return m, tea.Quit

	case "enter":
		val := strings.TrimSpace(m.input.Value())
		m.input.Reset()
		m.suggestions = nil
		m.suggestIdx = 0
		if val == "" {
			return m, nil
		}
		if command.IsCommand(val) {
			return m, m.runCommand(val)
		}
		if r := m.activeRoom(); r != nil && r.client != nil {
			if err := r.client.Send(val); err != nil {
				m.addError(err.Error())
			}
		} else {
			m.addError("not connected")
		}
		return m, nil

	case "tab":
		if len(m.suggestions) > 0 {
			m.input.SetValue(m.suggestions[m.suggestIdx].Value)
			m.input.CursorEnd()
			m.recomputeSuggestions()
		}
		return m, nil

	case "up":
		if len(m.suggestions) > 0 {
			m.suggestIdx = (m.suggestIdx - 1 + len(m.suggestions)) % len(m.suggestions)
			return m, nil
		}
		var cmd tea.Cmd
		m.vp, cmd = m.vp.Update(msg)
		return m, cmd

	case "down":
		if len(m.suggestions) > 0 {
			m.suggestIdx = (m.suggestIdx + 1) % len(m.suggestions)
			return m, nil
		}
		var cmd tea.Cmd
		m.vp, cmd = m.vp.Update(msg)
		return m, cmd

	case "pgup", "pgdown", "home", "end", "ctrl+u", "ctrl+d":
		var cmd tea.Cmd
		m.vp, cmd = m.vp.Update(msg)
		return m, cmd

	case "ctrl+n":
		m.cycleRoom(1)
		return m, nil
	case "ctrl+p":
		m.cycleRoom(-1)
		return m, nil

	default:
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		m.recomputeSuggestions()
		return m, cmd
	}
}

func (m *Model) onRoomConnected(msg roomConnectedMsg) tea.Cmd {
	r, ok := m.session[msg.name]
	if !ok {
		// Room was left before the connection completed; tidy up.
		if msg.c != nil {
			_ = msg.c.Close()
		}
		return nil
	}
	if msg.err != nil {
		r.failed = true
		r.appendError("connection failed: " + msg.err.Error())
		if msg.name == m.active {
			m.syncViewport()
		}
		return nil
	}
	r.client = msg.c
	r.connected = true
	if m.fingerprint == "" {
		m.fingerprint = msg.c.Fingerprint()
		m.source = msg.c.Source()
	}
	return listenRoom(msg.name, msg.c)
}

func (m *Model) handleRoomEvent(name string, ev client.Event) tea.Cmd {
	r := m.session[name]
	if r == nil {
		return nil
	}
	var notify tea.Cmd

	switch e := ev.(type) {
	case client.EvConnected:
		r.connected = true
		r.inviteOnly, r.webhook = e.InviteOnly, e.Webhook
		if e.TTLSeconds > 0 {
			r.ttl = time.Duration(e.TTLSeconds) * time.Second
		}
		for _, mem := range e.Members {
			r.addMember(mem.ID, mem.Name, mem.Fingerprint)
		}
		if len(e.Members) == 0 {
			r.appendSystem("connected — you are the first one here")
		} else {
			r.appendSystem("connected — present: " + joinNames(e.Members))
		}

	case client.EvKeyReady:
		r.keyReady = true
		r.appendSystem(fmt.Sprintf("🔒 end-to-end encryption ready (epoch %d)", e.Epoch))

	case client.EvMessage:
		k := lineMessage
		if e.Self {
			k = lineSelf
		}
		r.appendLine(line{at: e.At, kind: k, from: e.FromName, text: e.Text})
		if !e.Self {
			if name != m.active {
				r.unread++
			}
			notify = m.notify(name, e.FromName, e.Text)
		}

	case client.EvServerMessage:
		r.appendLine(line{at: e.At, kind: lineServer, from: e.From, text: e.Text})
		if name != m.active {
			r.unread++
		}

	case client.EvMemberJoined:
		r.addMember(e.ID, e.Name, e.Fingerprint)
		r.appendSystem(e.Name + " joined")

	case client.EvMemberLeft:
		nm := r.removeMember(e.ID)
		if nm == "" {
			nm = e.Name
		}
		if nm == "" {
			nm = e.ID
		}
		r.appendSystem(nm + " left")

	case client.EvControl:
		switch e.Action {
		case "vanish":
			r.lines = nil
			who := e.ByName
			if e.Self {
				who = "you"
			}
			r.appendSystem("🌀 " + who + " vanished the room — key rotated, history cleared")
		case "ttl":
			if e.TTLSeconds <= 0 {
				r.ttl = 0
				r.appendSystem("message ttl disabled")
			} else {
				r.ttl = time.Duration(e.TTLSeconds) * time.Second
				r.appendSystem("message ttl set to " + r.ttl.String())
			}
		}

	case client.EvExecRequest:
		who := e.FromName
		if e.Self {
			who = "you"
		}
		r.appendLine(line{at: e.At, kind: lineExec, from: who + " requested", text: e.Cmd})

	case client.EvExecResult:
		var head string
		if !e.Allowed {
			head = e.Cmd + " → denied (not in agent runbook)"
		} else {
			head = fmt.Sprintf("%s → exit %d", e.Cmd, e.ExitCode)
		}
		head += "  " + shortFpr(e.FromFingerprint)
		txt := head
		if out := strings.TrimRight(e.Output, "\n"); out != "" {
			txt += "\n" + out
		}
		r.appendLine(line{at: e.At, kind: lineExec, from: "exec", text: txt})

	case client.EvInvite:
		r.appendLine(line{at: time.Now(), kind: lineRaw, text: m.renderInvite(name, e)})

	case client.EvBreakGlass:
		// Show the war-room banner (links + deadline) in the room where the command
		// was run, then bring the new room up in the background so it lands in the
		// sidebar without yanking focus away from the links the user needs to copy.
		r.appendLine(line{at: time.Now(), kind: lineRaw, text: m.renderBreakGlass(e)})
		notify = m.joinRoomOpts(e.Room, e.HostToken, false)

	case client.EvError:
		r.appendError(e.Err.Error())

	case client.EvDisconnected:
		r.connected = false
	}

	if name == m.active {
		m.syncViewport()
	}
	return notify
}

// --- room management --------------------------------------------------------

func (m *Model) activeRoom() *room { return m.session[m.active] }

func (m *Model) joinRoom(name, token string) tea.Cmd {
	return m.joinRoomOpts(name, token, true)
}

// joinRoomOpts joins (or focuses) a room. When activate is false the room is
// connected in the background without stealing focus — used by /break-glass so
// the freshly created war room appears in the sidebar while the creator keeps
// reading the printed invite links in the current room.
func (m *Model) joinRoomOpts(name, token string, activate bool) tea.Cmd {
	if r, ok := m.session[name]; ok {
		if activate {
			m.active = name
			r.unread = 0
			m.syncViewport()
		}
		return nil
	}
	m.session[name] = newRoom(name)
	m.order = append(m.order, name)
	if activate {
		m.active = name
	}
	m.syncViewport()
	return connectRoom(m.url, name, m.name, m.identityPath, token)
}

func (m *Model) leaveRoom(name string) tea.Cmd {
	r, ok := m.session[name]
	if !ok {
		return nil
	}
	if r.client != nil {
		_ = r.client.Close()
	}
	delete(m.session, name)
	for i, x := range m.order {
		if x == name {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
	if len(m.order) == 0 {
		return tea.Quit
	}
	if m.active == name {
		m.active = m.order[0]
	}
	m.syncViewport()
	return nil
}

func (m *Model) cycleRoom(dir int) {
	if len(m.order) < 2 {
		return
	}
	idx := 0
	for i, n := range m.order {
		if n == m.active {
			idx = i
			break
		}
	}
	idx = (idx + dir + len(m.order)) % len(m.order)
	m.active = m.order[idx]
	if r := m.session[m.active]; r != nil {
		r.unread = 0
	}
	m.syncViewport()
}

func (m *Model) closeAll() {
	for _, r := range m.session {
		if r.client != nil {
			_ = r.client.Close()
		}
	}
}

func (m *Model) addSystem(s string) {
	if r := m.activeRoom(); r != nil {
		r.appendSystem(s)
		m.syncViewport()
	}
}

func (m *Model) addError(s string) {
	if r := m.activeRoom(); r != nil {
		r.appendError(s)
		m.syncViewport()
	}
}

func (m *Model) recomputeSuggestions() {
	if command.IsCommand(m.input.Value()) {
		m.suggestions = m.cmds.Suggest(m.input.Value())
	} else {
		m.suggestions = nil
	}
	if m.suggestIdx >= len(m.suggestions) {
		m.suggestIdx = 0
	}
}

func (m *Model) handleClick(x, y int) {
	// The sidebar occupies columns [0, sidebarW); its first row (the "rooms"
	// title) is at screen row 2 (header is 2 rows), so room i is at row 3+i.
	if m.sidebarW > 0 && x < m.sidebarW && y >= 3 {
		idx := y - 3
		if idx >= 0 && idx < len(m.order) {
			m.active = m.order[idx]
			if r := m.session[m.active]; r != nil {
				r.unread = 0
			}
			m.syncViewport()
		}
	}
}

// --- notifications ----------------------------------------------------------

func (m *Model) notify(room, from, text string) tea.Cmd {
	if m.notifyCmd == "" {
		return nil
	}
	cmdStr := m.notifyCmd
	return func() tea.Msg {
		var c *exec.Cmd
		if runtime.GOOS == "windows" {
			c = exec.Command("cmd", "/c", cmdStr)
		} else {
			c = exec.Command("sh", "-c", cmdStr)
		}
		c.Env = append(os.Environ(),
			"NETHERCHAT_ROOM="+room,
			"NETHERCHAT_FROM="+from,
			"NETHERCHAT_TEXT="+text,
		)
		_ = c.Run()
		return nil
	}
}

// --- layout / rendering -----------------------------------------------------

func (m *Model) resize(w, h int) {
	m.width, m.height = w, h
	m.sidebarW, m.membersW = 18, 18
	if w < 76 {
		m.membersW = 0
	}
	if w < 44 {
		m.sidebarW = 0
	}
	sidePanes := 0
	if m.sidebarW > 0 {
		sidePanes++
	}
	if m.membersW > 0 {
		sidePanes++
	}
	msgW := w - m.sidebarW - m.membersW - sidePanes
	if msgW < 20 {
		msgW = 20
	}
	m.bodyH = h - 5 // header(2) + footer(3)
	if m.bodyH < 3 {
		m.bodyH = 3
	}
	if !m.ready {
		m.vp = viewport.New(msgW, m.bodyH)
		m.ready = true
	} else {
		m.vp.Width = msgW
		m.vp.Height = m.bodyH
	}
	m.input.Width = w - 3
	m.syncViewport()
}

func (m *Model) syncViewport() {
	if !m.ready {
		return
	}
	r := m.activeRoom()
	if r == nil {
		m.vp.SetContent("")
		return
	}
	m.vp.SetContent(m.renderLines(r))
	m.vp.GotoBottom()
}

func (m *Model) View() string {
	if !m.ready {
		return "initializing…"
	}
	var parts []string
	if m.sidebarW > 0 {
		parts = append(parts, m.sidebarView(), m.vsep())
	}
	parts = append(parts, m.vp.View())
	if m.membersW > 0 {
		parts = append(parts, m.vsep(), m.membersView())
	}
	body := lipgloss.JoinHorizontal(lipgloss.Top, parts...)
	return lipgloss.JoinVertical(lipgloss.Left, m.headerView(), body, m.footerView())
}

func (m *Model) headerView() string {
	r := m.activeRoom()
	status := m.st(m.theme.Muted).Render("connecting…")
	switch {
	case r == nil:
	case r.failed:
		status = m.st(m.theme.Error).Render("disconnected")
	case r.keyReady:
		status = m.st(m.theme.Success).Render("🔒 E2E")
	case r.connected:
		status = m.st(m.theme.Warn).Render("connected (awaiting key)")
	}
	title := m.st(m.theme.Accent).Bold(true).Render(" netherchat ")
	meta := m.st(m.theme.Muted).Render(fmt.Sprintf("#%s · %s · theme:%s ", m.active, m.name, m.theme.Name))
	return title + meta + status + "\n" + m.divider()
}

func (m *Model) footerView() string {
	return m.divider() + "\n" + m.suggestBar() + "\n" + m.input.View()
}

func (m *Model) suggestBar() string {
	if len(m.suggestions) == 0 {
		return m.st(m.theme.Muted).Render("tab complete · ↑↓ scroll · ctrl+n/p room · /help · ctrl+c quit")
	}
	var parts []string
	for i, s := range m.suggestions {
		if i > 6 {
			parts = append(parts, m.st(m.theme.Muted).Render("…"))
			break
		}
		if i == m.suggestIdx {
			parts = append(parts, m.st(m.theme.Accent).Bold(true).Render(s.Display))
		} else {
			parts = append(parts, m.st(m.theme.Muted).Render(s.Display))
		}
	}
	return strings.Join(parts, "  ")
}

func (m *Model) sidebarView() string {
	lines := []string{m.st(m.theme.Accent).Bold(true).Render("rooms")}
	for _, name := range m.order {
		r := m.session[name]
		var row string
		if name == m.active {
			row = m.st(m.theme.Accent).Render("▸ ") + m.st(m.theme.Accent).Bold(true).Render("#"+name)
		} else {
			row = "  " + m.st(m.theme.Text).Render("#"+name)
			if r != nil && r.unread > 0 {
				row += m.st(m.theme.Warn).Render(" " + strconv.Itoa(r.unread))
			}
		}
		if r != nil && r.failed {
			row += m.st(m.theme.Error).Render(" ✕")
		} else if r != nil && !r.connected {
			row += m.st(m.theme.Muted).Render(" …")
		}
		lines = append(lines, row)
	}
	return m.pane(m.sidebarW, strings.Join(lines, "\n"))
}

func (m *Model) membersView() string {
	r := m.activeRoom()
	lines := []string{m.st(m.theme.Accent).Bold(true).Render("members")}
	if r != nil {
		dot := m.st(m.theme.Success).Render("● ")
		lines = append(lines, dot+m.user(m.name)+m.st(m.theme.Muted).Render(" (you)"))
		for _, id := range r.order {
			mem := r.members[id]
			row := dot + m.user(mem.name)
			if m.isVerified(mem.fpr) {
				row += m.st(m.theme.Success).Render(" ✓")
			}
			lines = append(lines, row)
		}
	}
	return m.pane(m.membersW, strings.Join(lines, "\n"))
}

func (m *Model) renderLines(r *room) string {
	lines := make([]string, 0, len(r.lines))
	for _, l := range r.lines {
		lines = append(lines, m.renderLine(l))
	}
	return strings.Join(lines, "\n")
}

func (m *Model) renderLine(l line) string {
	switch l.kind {
	case lineRaw:
		return l.text
	case lineSystem:
		return m.wrap(m.st(m.theme.Muted).Italic(true).Render("* " + l.text))
	case lineError:
		return m.wrap(m.st(m.theme.Error).Render("⚠ " + l.text))
	}
	ts := m.st(m.theme.Muted).Render(l.at.Format("15:04") + " ")
	switch l.kind {
	case lineSelf:
		return m.wrap(ts + m.st(m.theme.Accent2).Bold(true).Render(l.from+": ") + m.inlineCode(l.text))
	case lineServer:
		tag := m.st(m.theme.Warn).Render("⚙ " + l.from + " (plaintext) ")
		return m.wrap(ts + tag + m.inlineCode(l.text))
	case lineExec:
		tag := m.st(m.theme.Accent2).Bold(true).Render("⚡ " + l.from + " ")
		return m.wrap(ts + tag + m.inlineCode(l.text))
	default: // lineMessage
		return m.wrap(ts + m.user(l.from) + m.st(m.theme.Text).Render(": ") + m.inlineCode(l.text))
	}
}

// inlineCode styles `code` spans within a message.
func (m *Model) inlineCode(s string) string {
	if !strings.Contains(s, "`") {
		return s
	}
	parts := strings.Split(s, "`")
	var b strings.Builder
	for i, p := range parts {
		if i%2 == 1 {
			b.WriteString(m.st(m.theme.Accent2).Render(p))
		} else {
			b.WriteString(p)
		}
	}
	return b.String()
}

func (m *Model) user(name string) string {
	return lipgloss.NewStyle().Foreground(m.theme.UserColor(name)).Bold(true).Render(name)
}

func (m *Model) st(c lipgloss.Color) lipgloss.Style { return lipgloss.NewStyle().Foreground(c) }

func (m *Model) wrap(s string) string { return lipgloss.NewStyle().Width(m.vp.Width).Render(s) }

func (m *Model) pane(w int, content string) string {
	return lipgloss.NewStyle().Width(w).Height(m.bodyH).MaxHeight(m.bodyH).Render(content)
}

func (m *Model) vsep() string {
	bar := m.st(m.theme.Muted).Render("│")
	lines := make([]string, m.bodyH)
	for i := range lines {
		lines[i] = bar
	}
	return strings.Join(lines, "\n")
}

func (m *Model) divider() string {
	return m.st(m.theme.Muted).Render(strings.Repeat("─", max(m.width, 1)))
}

func (m *Model) applyInputTheme() {
	m.input.PromptStyle = lipgloss.NewStyle().Foreground(m.theme.Accent)
	m.input.PlaceholderStyle = lipgloss.NewStyle().Foreground(m.theme.Muted)
	m.input.TextStyle = lipgloss.NewStyle().Foreground(m.theme.Text)
}
