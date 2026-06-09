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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/ui/command"
	"github.com/salehkreiner/netherchat/tui/ui/render"
	"github.com/salehkreiner/netherchat/tui/ui/theme"
)

// Model is the Bubble Tea model for the whole client.
type Model struct {
	url, name, identityPath, notifyCmd string
	webURL                             string // base URL of the web join client, for /break-glass links
	torProxy                           string // when set, dial every room through this Tor SOCKS5 proxy (§1.5)
	fingerprint                        string
	source                             string                  // where the identity came from (ssh-agent, key file, generated)
	trust                              []TrustEntry            // client-side identity pins from netherchat.toml
	verified                           map[string]*verifyEntry // SAS-verification state, keyed by peer fingerprint

	cmds     *command.Set
	theme    theme.Theme
	renderer *render.Renderer // message-body paste rendering (§2.6)

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
	mouseOn                   bool // Bubble Tea mouse capture (off restores native terminal selection)

	initialInvite string
}

// Run connects to the initial room and runs the TUI. invite is the one-time
// token for the initial room (empty for open rooms). webURL is the base URL of
// the browser join client, used to build /break-glass invite links. torProxy,
// when non-empty, routes every room's dial through that Tor SOCKS5 proxy so a
// ws://<addr>.onion relay is reachable (§1.5). trust holds the client-side
// identity pins parsed from netherchat.toml.
func Run(url, name, identityPath, room, notifyCmd, invite, webURL, torProxy string, trust []TrustEntry) error {
	m := newModel(url, name, identityPath, room, notifyCmd)
	m.initialInvite = invite
	m.webURL = webURL
	m.torProxy = torProxy
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
		renderer: render.New(theme.Default(), 80), // width set for real on first resize
		session:  map[string]*room{},
		verified: map[string]*verifyEntry{},
		input:    textinput.New(),
		mouseOn:  true, // matches tea.WithMouseCellMotion() in Run
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

func connectRoom(url, room, name, idPath, token, torProxy string) tea.Cmd {
	return func() tea.Msg {
		c, err := client.New(url, room, name, idPath)
		if err != nil {
			return roomConnectedMsg{room, nil, err}
		}
		if torProxy != "" {
			if err := c.UseTorProxy(torProxy); err != nil {
				return roomConnectedMsg{room, nil, err}
			}
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
	return tea.Batch(textinput.Blink, connectRoom(m.url, m.active, m.name, m.identityPath, m.initialInvite, m.torProxy), tickEvery())
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
		r.appendLine(line{at: e.At, kind: k, from: e.FromName, text: e.Text, fpr: r.members[e.FromID].fpr, signed: e.Signed})
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
			r.collapse.Reset() // block ids reset with the cleared history (§2.6)
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
		case "scuttle":
			// The dead-man's switch fired (§1.6): the client already ran the /vanish
			// ratchet on this event. Render the attestation and the scuttled state;
			// the room is gone server-side.
			r.scuttled = true
			r.appendSystem("⚡ room scuttled — keys destroyed, no record kept" + scuttleReasonSuffix(e.Reason))
			r.appendSystem("⚡ This room has been scuttled. Keys destroyed.")
			if name != m.active {
				r.unread++
			}
		case "scuttle_arm":
			who := e.ByName
			if who == "" {
				who = "someone"
			}
			d := time.Duration(e.TTLSeconds) * time.Second
			r.appendSystem(fmt.Sprintf("⏳ %s armed auto-scuttle — this room burns in %s", who, d))
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

	case client.EvRouteFired:
		// An inbound alert in this (intake) room spawned an incident war room.
		r.appendLine(line{at: e.At, kind: lineRaw, text: m.renderRouteFired(e)})
		if name != m.active {
			r.unread++
		}

	case client.EvAck:
		who := e.Actor
		if e.Self {
			who = "you"
		}
		r.appendSystem(fmt.Sprintf("✓ %s acked %s  (%s)", who, e.Tag, e.Quorum))

	case client.EvHandoff:
		from := e.FromName
		if e.Self {
			from = "you"
		}
		r.appendSystem(fmt.Sprintf("⚡ incident command: %s → %s", from, e.ToName))

	case client.EvRecordEntry:
		// Store the entry's structure (not a frozen rendered string) so it restyles
		// on /theme like a message and /export can decompose it.
		r.appendLine(line{
			at: e.At, kind: lineRecord, from: e.AuthorName, text: e.Body,
			fpr: e.AuthorFpr, signed: true,
			recordKind: e.Kind, actionee: e.Actionee, replayed: e.Replayed,
		})
		if !e.Self && name != m.active {
			r.unread++
		}

	case client.EvSealRequest:
		if e.Self {
			r.appendSystem(fmt.Sprintf("📋 sealing the record (%d entries) — waiting for co-signers…", e.NumEntries))
		} else if e.Matches {
			r.appendSystem(fmt.Sprintf("📋 %s proposes sealing the record (%d entries) — type /seal to co-sign", e.ByName, e.NumEntries))
		} else {
			r.appendSystem(fmt.Sprintf("📋 %s proposes a seal, but your record differs from theirs — /seal will report the divergence", e.ByName))
		}

	case client.EvSealAck:
		if e.Self {
			r.appendSystem("✓ you co-signed the seal")
		} else {
			r.appendSystem(fmt.Sprintf("✓ %s co-signed the seal  (%d/%d)", e.ByName, e.Count, e.Total))
		}

	case client.EvSealComplete:
		if err := writeSealedRecord(e.Record); err != nil {
			r.appendError("seal complete but writing files failed: " + err.Error())
		} else {
			r.appendSystem(fmt.Sprintf("🔏 sealed — record.json + minutes.md written (%d entries, %d signature(s)). Verify: netherchat verify record.json", e.Entries, e.Signers))
		}

	case client.EvRosterRequest:
		if !e.Self {
			r.appendSystem(fmt.Sprintf("📋 a roster attestation was proposed (%d member set) — co-signing", e.Members))
		}

	case client.EvRosterAck:
		if !e.Self {
			r.appendSystem(fmt.Sprintf("✓ %s co-signed the roster  (%d/%d)", e.ByName, e.Count, e.Total))
		}

	case client.EvRosterComplete:
		path := r.rosterOut
		if path == "" {
			path = "roster.json"
		}
		r.rosterOut = ""
		if err := writeArtifact(path, e.Attestation); err != nil {
			r.appendError("roster complete but writing " + path + " failed: " + err.Error())
		} else {
			r.appendSystem(fmt.Sprintf("✓ %s written — %d of %d members co-signed. Verify: netherchat verify %s", path, e.Signers, e.Total, path))
		}

	case client.EvScuttleReceiptAck:
		if !e.Self {
			r.appendSystem(fmt.Sprintf("✓ %s co-signed the scuttle receipt  (%d/%d)", e.ByName, e.Count, e.Total))
		}

	case client.EvScuttleReceipt:
		// The room is being destroyed; the receipt is the only surviving artifact
		// (§1.5). Write it to the working directory, like a sealed record.
		path := receiptFilename(e.Receipt.Room)
		if err := writeArtifact(path, e.Receipt); err != nil {
			r.appendError("scuttle receipt write failed: " + err.Error())
		} else {
			r.appendSystem(fmt.Sprintf("⚡ Room scuttled. Receipt written to %s\nVerify with: netherchat verify %s", path, path))
			if name != m.active {
				r.unread++
			}
		}

	case client.EvFileOffer:
		r.appendSystem(renderFileOffer(e))
		if name != m.active {
			r.unread++
		}

	case client.EvFileSent:
		r.appendSystem(fmt.Sprintf("✓ %s sent (%s, %s)", e.Filename, humanBytes(e.Size), e.Elapsed.Round(time.Second)))

	case client.EvFileFailed:
		r.appendError("transfer failed: " + e.Reason)

	case client.EvFileComplete:
		if e.OK {
			r.appendSystem(renderFileComplete(e))
			if name != m.active {
				r.unread++
			}
		} else {
			r.appendError(renderFileComplete(e))
		}

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
	return connectRoom(m.url, name, m.name, m.identityPath, token, m.torProxy)
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
	m.renderer.SetWidth(msgW) // keep paste-rendering geometry in step with the viewport
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
		// The incident commander is marked with a ⚡ prefix (§2.2).
		var icFpr string
		var icSelf bool
		if r.client != nil {
			if _, fpr, isSelf, ok := r.client.ICHolder(); ok {
				icFpr, icSelf = fpr, isSelf
			}
		}
		dot := m.st(m.theme.Success).Render("● ")
		lines = append(lines, m.icMark(icSelf)+dot+m.user(m.name)+m.st(m.theme.Muted).Render(" (you)"))
		for _, id := range r.order {
			mem := r.members[id]
			row := m.icMark(!icSelf && icFpr != "" && mem.fpr == icFpr) + dot + m.user(mem.name)
			if m.isVerified(mem.fpr) {
				row += m.st(m.theme.Success).Render(" ✓")
			}
			lines = append(lines, row)
		}
		// A running quorum count per active ack tag (§2.2).
		if r.client != nil {
			if acks := r.client.AckState(); len(acks) > 0 {
				lines = append(lines, "", m.st(m.theme.Accent).Bold(true).Render("acks"))
				for _, tag := range sortedKeys(acks) {
					label := truncate(tag, m.membersW-5)
					lines = append(lines, m.st(m.theme.Text).Render(label)+" "+m.st(m.theme.Warn).Render(acks[tag]))
				}
			}
		}
	}
	return m.pane(m.membersW, strings.Join(lines, "\n"))
}

// icMark returns the incident-commander prefix: a ⚡ for the holder, a blank slot
// otherwise (so rows stay aligned).
func (m *Model) icMark(isIC bool) string {
	if isIC {
		return m.st(m.theme.Warn).Render("⚡")
	}
	return " "
}

func (m *Model) renderLines(r *room) string {
	lines := make([]string, 0, len(r.lines))
	blockID := 1 // sequential collapse ids, scoped to the room session (§2.6)
	for _, l := range r.lines {
		rendered, blocks := m.renderLine(r, l, blockID)
		blockID += blocks
		lines = append(lines, rendered)
	}
	r.maxBlockID = blockID - 1
	return strings.Join(lines, "\n")
}

// renderLine renders one buffer line. For chat messages it routes the body
// through the paste renderer (§2.6), numbering any collapsible code blocks or
// stack traces from baseID; it returns the rendered text and how many block ids
// it consumed so the caller can advance the room-wide counter.
func (m *Model) renderLine(r *room, l line, baseID int) (string, int) {
	switch l.kind {
	case lineRaw:
		return l.text, 0
	case lineRecord:
		// Re-render from the stored entry structure (identical to append-time output).
		return m.renderRecordEntry(client.EvRecordEntry{
			Kind: l.recordKind, AuthorName: l.from, Actionee: l.actionee,
			Body: l.text, Replayed: l.replayed, At: l.at,
		}), 0
	case lineSystem:
		return m.wrap(m.st(m.theme.Muted).Italic(true).Render("* " + l.text)), 0
	case lineError:
		return m.wrap(m.st(m.theme.Error).Render("⚠ " + l.text)), 0
	}
	ts := m.st(m.theme.Muted).Render(l.at.Format("15:04") + " ")
	switch l.kind {
	case lineSelf:
		header := ts + m.st(m.theme.Accent2).Bold(true).Render(l.from+": ")
		return m.renderBody(r, header, l.text, baseID)
	case lineServer:
		tag := m.st(m.theme.Warn).Render("⚙ " + l.from + " (plaintext) ")
		return m.wrap(ts + tag + m.inlineCode(l.text)), 0
	case lineExec:
		tag := m.st(m.theme.Accent2).Bold(true).Render("⚡ " + l.from + " ")
		return m.wrap(ts + tag + m.inlineCode(l.text)), 0
	default: // lineMessage
		header := ts + m.user(l.from) + m.badge(l) + m.st(m.theme.Text).Render(": ")
		return m.renderBody(r, header, l.text, baseID)
	}
}

// renderBody composes a message header with its rendered body. A plain message
// stays a single line — header then inline body — exactly as before (no
// regression). A body that carries a structural block (code, diff, stack trace)
// puts the header on its own line with the formatted block(s) below it.
func (m *Model) renderBody(r *room, header, body string, baseID int) (string, int) {
	out, blocks, isBlock := m.renderer.RenderBody(body, baseID, r.collapse)
	if !isBlock {
		return m.wrap(header + out), 0
	}
	return m.wrap(header) + "\n" + out, blocks
}

// badge returns the trust indicator drawn after a message sender's name (§3.3):
//
//	✓✓  signed + SAS-verified (you read the words out of band)
//	✓   signed + trust-pinned (fingerprint matches a [[trust]] pin)
//	(none) signed but neither pinned nor verified — signed is the baseline
//	?   unsigned (legacy / pre-v3 sender)
func (m *Model) badge(l line) string {
	if !l.signed {
		return m.st(m.theme.Warn).Render(" ?")
	}
	if m.isVerified(l.fpr) {
		return m.st(m.theme.Success).Bold(true).Render(" ✓✓")
	}
	if m.isPinned(l.from, l.fpr) {
		return m.st(m.theme.Success).Render(" ✓")
	}
	return ""
}

// isPinned reports whether fpr matches a [[trust]] pin for the given handle.
func (m *Model) isPinned(handle, fpr string) bool {
	entry, ok := m.trustFor(handle)
	return ok && entry.Fpr != "" && entry.Fpr == fpr
}

// inlineCode styles `code` spans within a message, delegating to the render
// package so inline code looks identical everywhere it appears (§2.6 item 2).
func (m *Model) inlineCode(s string) string { return m.renderer.Inline(s) }

func (m *Model) user(name string) string {
	return lipgloss.NewStyle().Foreground(m.theme.UserColor(name)).Bold(true).Render(name)
}

func (m *Model) st(c lipgloss.Color) lipgloss.Style { return lipgloss.NewStyle().Foreground(c) }

// sortedKeys returns the keys of a string-keyed map in sorted order, for stable
// rendering of the ack panel.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// truncate shortens s to at most n display columns, appending "…" when cut.
func truncate(s string, n int) string {
	if n < 1 {
		n = 1
	}
	if len(s) <= n {
		return s
	}
	if n == 1 {
		return "…"
	}
	return s[:n-1] + "…"
}

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
