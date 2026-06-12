package app

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/qr"
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
		command.Command{Name: "invite", Args: "[--qr]", Help: "generate a one-time invite token; --qr renders the join link as a QR code",
			Complete: func(p string) []string { return command.FilterPrefix([]string{"--qr"}, p) }},
		command.Command{Name: "break-glass", Args: "--invite a,b --ttl 4h", Help: "stand up an ephemeral war room with one-time join links"},
		command.Command{Name: "vanish", Help: "rotate the room key and clear history"},
		command.Command{Name: "scuttle", Args: "[now|arm <dur>]", Help: "burn the room's keys and close it (dead-man's switch)",
			Complete: func(p string) []string { return command.FilterPrefix([]string{"now", "arm"}, p) }},
		command.Command{Name: "approve", Args: "<id> [confirm]", Help: "approve a pending privileged action (two-person rule); 'confirm' signs it"},
		command.Command{Name: "veto", Args: "<id> [reason]", Help: "cancel a pending privileged action immediately"},
		command.Command{Name: "pending", Help: "list pending privileged-action requests awaiting quorum"},
		command.Command{Name: "ttl", Args: "<dur|off>", Help: "set a message display TTL",
			Complete: func(p string) []string { return command.FilterPrefix([]string{"off", "10m", "1h", "24h"}, p) }},
		command.Command{Name: "beacon", Args: `set "<text>" | clear | status | link [--ttl 2h]`, Help: "out-of-band read-only status beacon (encrypted to a separate key)",
			Complete: func(p string) []string { return command.FilterPrefix([]string{"set", "clear", "status", "link"}, p) }},
		command.Command{Name: "exec", Args: "<action>", Help: "request an edge agent run a runbook action (signed, E2E)"},
		command.Command{Name: "send", Args: "<path>", Help: "relay a file to the room as a secure artifact transfer (E2E, relay-blind)",
			Complete: completeFilePath},
		command.Command{Name: "stream", Args: "<file>|stop", Help: "tail a local log into the room as one live, ephemeral block (§2.2)",
			Complete: func(p string) []string {
				if strings.HasPrefix("stop", p) {
					return append([]string{"stop"}, completeFilePath(p)...)
				}
				return completeFilePath(p)
			}},
		command.Command{Name: "ack", Args: "[tag]", Help: "ack a coordination tag (typed quorum, not a reaction); no arg lists active tags"},
		command.Command{Name: "handoff", Args: "@handle", Help: "transfer the incident-commander (IC) token"},
		command.Command{Name: "ic", Help: "show who currently holds incident command"},
		command.Command{Name: "clock", Args: "[start|stop]", Help: "incident clock; captures duration into the sealed record on /seal (A1)",
			Complete: func(p string) []string { return command.FilterPrefix([]string{"start", "stop"}, p) }},
		command.Command{Name: "decide", Args: "<text>", Help: "promote a decision into the signed record chain"},
		command.Command{Name: "action", Args: "@handle <text>", Help: "record an action item assigned to someone"},
		command.Command{Name: "mark", Help: "promote the most recent message into the record as a note"},
		command.Command{Name: "propose", Args: "--source <agent> --ref <ref> --hash <sha256> [--summary <line>]", Help: "propose an agent-produced artifact for human approval (NC-W1)"},
		command.Command{Name: "approve-artifact", Args: "<proposal-id>", Help: "approve a pending artifact proposal (an agent can never self-approve)"},
		command.Command{Name: "reject-artifact", Args: "<proposal-id> [reason]", Help: "reject a pending artifact proposal; no record entry is written"},
		command.Command{Name: "seal", Help: "seal the record: collect signatures, write record.json + minutes.md"},
		command.Command{Name: "roster", Args: "[--signed] [--out <path>]", Help: "show who holds the keys; --signed writes a co-signed attestation",
			Complete: func(p string) []string { return command.FilterPrefix([]string{"--signed", "--out"}, p) }},
		command.Command{Name: "peers", Help: "list room members and the transport (relay or direct, §1.1)"},
		command.Command{Name: "pair", Help: "connect without a relay — how to start a Sneakernet session (§1.1)"},
		command.Command{Name: "whois", Args: "[@handle]", Help: "show an identity's fingerprint, pin status, and published-key match"},
		command.Command{Name: "verify", Args: "[@handle [ok]]", Help: "out-of-band verify a peer via a 5-word SAS read over a side channel"},
		command.Command{Name: "join", Args: "<room>", Help: "join another room"},
		command.Command{Name: "leave", Help: "leave the current room"},
		command.Command{Name: "clear", Help: "clear the current room view"},
		command.Command{Name: "expand", Args: "<id|all>", Help: "expand a collapsed code block or stack trace",
			Complete: func(p string) []string { return command.FilterPrefix([]string{"all"}, p) }},
		command.Command{Name: "copy", Args: "[N|@handle]", Help: "copy a message body to the system clipboard"},
		command.Command{Name: "export", Args: "[--all] [--json] [--out <path>]", Help: "write sealed decisions to a file (--all for full history, with a warning)"},
		command.Command{Name: "mouse", Args: "[on|off]", Help: "toggle mouse capture (off = native terminal text selection)",
			Complete: func(p string) []string { return command.FilterPrefix([]string{"on", "off"}, p) }},
		command.Command{Name: "quit", Help: "quit netherchat"},
	)
}

// runCommand executes a parsed slash command, mutating the model and optionally
// returning a tea.Cmd (for joins and quitting).
func (m *Model) runCommand(input string) tea.Cmd {
	name, arg, _ := m.cmds.Parse(input)

	// Macro expansion happens BEFORE dispatch (§2.5): a macro expands to one or more
	// concrete commands run in sequence. Expansion is transparent to the rest of the
	// system — each expanded command re-enters runCommand as if typed.
	if expanded, ok := m.macros.Expand(name); ok {
		var batch []tea.Cmd
		for _, sub := range expanded {
			if c := m.runCommand(sub); c != nil {
				batch = append(batch, c)
			}
		}
		if len(batch) == 0 {
			return nil
		}
		return tea.Batch(batch...)
	}

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
	case "peers":
		m.runPeers(r)
	case "pair":
		m.addSystem("This room is connected through the relay.\n" +
			"To form a relay-LESS war room (Sneakernet, §1.1) when the relay is down or suspect:\n" +
			"  netherchat pair --lan      discover peers on the local network, then /pair one\n" +
			"  netherchat pair --manual   exchange a signed offer/answer blob (VPN / direct reachability)\n" +
			"Same end-to-end crypto, no server. See docs/self-hosting.md → Sneakernet Mode.")
	case "invite":
		if !m.connected(r) {
			break
		}
		r.inviteQR = strings.Contains(arg, "--qr") // render the join link as a QR (§2.4)
		r.client.RequestInvite()
	case "break-glass":
		m.runBreakGlass(r, arg)
	case "vanish":
		if !m.connected(r) {
			break
		}
		r.client.Vanish()
	case "scuttle":
		m.runScuttle(r, arg)
	case "approve":
		m.runApprove(r, arg)
	case "veto":
		m.runVeto(r, arg)
	case "pending":
		m.runPending(r)
	case "ttl":
		m.runTTL(r, arg)
	case "beacon":
		m.runBeacon(r, arg)
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
	case "stream":
		m.runStream(r, arg)
	case "ack":
		m.runAck(r, arg)
	case "handoff":
		m.runHandoff(r, arg)
	case "ic":
		m.runIC(r)
	case "clock":
		m.runClock(r, arg)
	case "decide":
		m.runDecide(r, arg)
	case "action":
		m.runAction(r, arg)
	case "mark":
		m.runMark(r)
	case "propose":
		m.runPropose(r, arg)
	case "approve-artifact":
		m.runApproveArtifact(r, arg)
	case "reject-artifact":
		m.runRejectArtifact(r, arg)
	case "seal":
		m.runSeal(r)
	case "roster":
		m.runRoster(r, arg)
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
			r.collapse.Reset()
			m.syncViewport()
		}
	case "expand":
		m.runExpand(r, arg)
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
	m.renderer.SetTheme(th) // invalidates the render cache → code blocks re-highlight (§2.6)
	m.applyInputTheme()
	m.addSystem("theme set to " + th.Name + "  (font: " + th.Font + ")")
	m.syncViewport()
}

// runExpand implements /expand <id|all> (§2.6): unfold a collapsed code block or
// stack trace in place. Ids are the sequential numbers shown in the fold
// affordance, scoped to the current room session. Re-rendering shows the change.
func (m *Model) runExpand(r *room, arg string) {
	if r == nil {
		return
	}
	arg = strings.TrimSpace(arg)
	switch {
	case arg == "":
		m.addError("usage: /expand <id|all>")
	case strings.EqualFold(arg, "all"):
		r.collapse.ExpandAll()
		m.addSystem("expanded all collapsed blocks")
		for id := range r.streams {
			m.streamExpanded[id] = true // /expand all covers live blocks too (§2.2)
		}
	case strings.HasPrefix(strings.ToLower(arg), "stream-"):
		m.expandStream(r, arg)
	default:
		id, err := strconv.Atoi(arg)
		if err != nil || id < 1 {
			m.addError("usage: /expand <id|all>   (id is the number shown in the collapsed block)")
			return
		}
		if id > r.maxBlockID {
			if r.maxBlockID == 0 {
				m.addError("no collapsed blocks in this room")
			} else {
				m.addError(fmt.Sprintf("no block #%d — this room has blocks 1–%d", id, r.maxBlockID))
			}
			return
		}
		r.collapse.Expand(id)
		m.addSystem(fmt.Sprintf("expanded block #%d", id))
	}
}

// expandStream expands a live-log block by its "stream-<n>" id (§2.2).
func (m *Model) expandStream(r *room, arg string) {
	n, err := strconv.Atoi(arg[len("stream-"):])
	if err != nil || n < 1 {
		m.addError("usage: /expand stream-<n>   (the number shown in the collapsed block)")
		return
	}
	for _, id := range r.streamOrder {
		if sv := r.streams[id]; sv != nil && sv.num == n {
			m.streamExpanded[id] = true
			m.addSystem(fmt.Sprintf("expanded stream-%d", n))
			return
		}
	}
	m.addError(fmt.Sprintf("no stream-%d in this room", n))
}

// runRoster implements /roster (§1.4). With no flag it prints the current
// member list with fingerprints and verification status (no artifact). With
// --signed it starts a co-signing round; the finished roster.json is written
// when EvRosterComplete arrives. --out chooses the path.
func (m *Model) runRoster(r *room, arg string) {
	signed, out, err := parseRosterArgs(arg)
	if err != nil {
		m.addError(err.Error())
		return
	}
	if !signed {
		if r == nil {
			m.addError("not in a room")
			return
		}
		m.addSystem(m.rosterText(r))
		return
	}
	if !m.connected(r) {
		return
	}
	r.rosterOut = out
	if err := r.client.SignRoster(m.verifiedFprSet()); err != nil {
		m.addError(err.Error())
		return
	}
	m.addSystem("roster: collecting co-signatures from present members…")
}

// parseRosterArgs parses "--signed" and "--out <path>" from /roster.
func parseRosterArgs(arg string) (signed bool, out string, err error) {
	fields := strings.Fields(arg)
	for i := 0; i < len(fields); i++ {
		switch fields[i] {
		case "--signed":
			signed = true
		case "--out":
			if i+1 >= len(fields) {
				return false, "", fmt.Errorf("usage: /roster [--signed] [--out <path>]")
			}
			out = fields[i+1]
			i++
		default:
			return false, "", fmt.Errorf("unknown option %q  ·  usage: /roster [--signed] [--out <path>]", fields[i])
		}
	}
	return signed, out, nil
}

// rosterText renders the live roster: every member that holds the room key this
// epoch, with fingerprint and SAS-verification status. It is the cryptographic
// answer to "who can read this right now" (§1.4), printed locally.
func (m *Model) rosterText(r *room) string {
	var b strings.Builder
	fmt.Fprintf(&b, "roster of #%s (%d member(s)) — who holds the keys this epoch:\n", r.name, len(r.order)+1)
	fmt.Fprintf(&b, "  %-16s %s  (you)\n", m.name, m.fingerprint)
	for _, id := range r.order {
		mem := r.members[id]
		status := "unverified"
		if m.isVerified(mem.fpr) {
			status = "✓ verified"
		}
		fmt.Fprintf(&b, "  %-16s %s  %s\n", mem.name, mem.fpr, status)
	}
	b.WriteString("  (run /roster --signed to write a co-signed attestation)")
	return b.String()
}

// verifiedFprSet returns the set of peer fingerprints this client has
// SAS-verified, for stamping the roster's per-member "verified" flag.
func (m *Model) verifiedFprSet() map[string]bool {
	out := make(map[string]bool, len(m.verified))
	for fpr, e := range m.verified {
		if e != nil && e.verified {
			out[fpr] = true
		}
	}
	return out
}

// artifact is anything that can render itself to canonical JSON bytes for
// /seal, /roster --signed, and the scuttle receipt — written by writeArtifact.
type artifact interface{ Marshal() ([]byte, error) }

// writeArtifact marshals a signed artifact and writes it to path (0644). The
// artifact is a deliberately-created file the operator chose to keep.
func writeArtifact(path string, a artifact) error {
	b, err := a.Marshal()
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// receiptFilename is the scuttle-receipt output path (§1.5):
// netherchat-receipt-<room>-<timestamp>.json in the working directory.
func receiptFilename(room string) string {
	return fmt.Sprintf("netherchat-receipt-%s-%s.json", exportRoomName(room), time.Now().Format("20060102-150405"))
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
// a visible countdown to everyone and auto-burns when it reaches zero.
//
// When [action.scuttle] quorum > 1 (the Two-Person Rule, §1.3) the burn is gated:
// the command opens an ActionRequest and the scuttle only fires once a second
// authorized member independently approves. quorum <= 1 keeps the existing
// single-actor behavior; quorum 0 disables the command.
func (m *Model) runScuttle(r *room, arg string) {
	if !m.connected(r) {
		return
	}
	q := m.quorumFor(protocol.ActionScuttleAction)
	if q == 0 {
		m.addError("scuttle is disabled by policy ([action.scuttle] quorum = 0)")
		return
	}
	fields := strings.Fields(arg)
	sub := "now"
	if len(fields) > 0 {
		sub = strings.ToLower(fields[0])
	}
	switch sub {
	case "now":
		if q > 1 {
			params := fmt.Sprintf("room=%s, reason=manual", r.name)
			if _, err := r.client.RequestAction(protocol.ActionScuttleAction, params, q, r.client.ScuttleNow); err != nil {
				m.addError(err.Error())
			}
			return
		}
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
		secs := int(d.Seconds())
		if q > 1 {
			params := fmt.Sprintf("room=%s, reason=armed, after=%s", r.name, d)
			if _, err := r.client.RequestAction(protocol.ActionScuttleAction, params, q, func() { r.client.ScuttleArm(secs) }); err != nil {
				m.addError(err.Error())
			}
			return
		}
		r.client.ScuttleArm(secs)
	default:
		m.addError("usage: /scuttle [now|arm <dur>]")
	}
}

// runBreakGlass implements /break-glass with Two-Person Rule gating (§1.3). When
// [action.break_glass] quorum > 1 the war room is not created until a second
// authorized member approves the request.
func (m *Model) runBreakGlass(r *room, arg string) {
	if !m.connected(r) {
		return
	}
	q := m.quorumFor(protocol.ActionBreakGlass)
	if q == 0 {
		m.addError("break-glass is disabled by policy ([action.break_glass] quorum = 0)")
		return
	}
	invitees, ttl, err := parseBreakGlass(arg)
	if err != nil {
		m.addError(err.Error())
		return
	}
	secs := int(ttl.Seconds())
	if q > 1 {
		who := "no one"
		if len(invitees) > 0 {
			who = strings.Join(invitees, ",")
		}
		params := fmt.Sprintf("invite=%s, ttl=%s", who, ttl)
		if _, err := r.client.RequestAction(protocol.ActionBreakGlass, params, q, func() { r.client.BreakGlass(invitees, secs) }); err != nil {
			m.addError(err.Error())
		}
		return
	}
	r.client.BreakGlass(invitees, secs)
	who := "no one yet"
	if len(invitees) > 0 {
		who = strings.Join(invitees, ", ")
	}
	m.addSystem(fmt.Sprintf("break-glass: standing up a war room (ttl %s) for %s …", ttl, who))
}

// runApprove implements /approve <id> [confirm] (§1.3). Without "confirm" it shows
// exactly what would be endorsed — the double-confirm that prevents an accidental
// approval. With "confirm" it signs and sends the approval. The initiator cannot
// approve their own request.
func (m *Model) runApprove(r *room, arg string) {
	if !m.connected(r) {
		return
	}
	fields := strings.Fields(arg)
	if len(fields) == 0 {
		m.addError("usage: /approve <id> [confirm]   (see /pending)")
		return
	}
	id := fields[0]
	p, ok := m.findPending(r, id)
	if !ok {
		m.addError(fmt.Sprintf("no pending request matching %q  (see /pending)", id))
		return
	}
	if p.Initiator {
		m.addError("you cannot approve your own request — it needs a second authorized approver")
		return
	}
	if p.Approved {
		m.addError("you have already approved this request")
		return
	}
	if !(len(fields) > 1 && strings.EqualFold(fields[1], "confirm")) {
		m.addSystem(fmt.Sprintf("you are approving: %s  (%s)\n  type  /approve %s confirm  to sign and send your approval",
			shortAction(p.Action), p.Params, shortID(p.RequestID)))
		return
	}
	if err := r.client.ApproveAction(id); err != nil {
		m.addError(err.Error())
	}
}

// runVeto implements /veto <id> [reason] (§1.3): cancel a pending request now.
func (m *Model) runVeto(r *room, arg string) {
	if !m.connected(r) {
		return
	}
	fields := strings.Fields(arg)
	if len(fields) == 0 {
		m.addError("usage: /veto <id> [reason]")
		return
	}
	id := fields[0]
	reason := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(arg), id))
	if err := r.client.VetoAction(id, reason); err != nil {
		m.addError(err.Error())
	}
}

// runPending implements /pending (§1.3): list pending action requests with their
// current endorsement counts and time remaining.
func (m *Model) runPending(r *room) {
	if !m.connected(r) {
		return
	}
	pend := r.client.PendingActions()
	if len(pend) == 0 {
		m.addSystem("no pending action requests")
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "pending action requests (%d):\n", len(pend))
	now := time.Now()
	for _, p := range pend {
		secs := remainingSecs(p.ExpiresUnix, now)
		role := ""
		switch {
		case p.Initiator:
			role = "  (yours)"
		case p.Approved:
			role = "  (you approved)"
		}
		fmt.Fprintf(&b, "  [%s] %s · by %s · %d/%d · %ds remaining%s\n     params: %s\n     /approve %s confirm   ·   /veto %s\n",
			shortID(p.RequestID), shortAction(p.Action), p.RequesterName, p.Count, p.Needed, secs, role,
			p.Params, shortID(p.RequestID), shortID(p.RequestID))
	}
	m.addSystem(strings.TrimRight(b.String(), "\n"))
}

// findPending resolves an id prefix to a unique pending request in the room.
func (m *Model) findPending(r *room, idPrefix string) (client.PendingAction, bool) {
	var match client.PendingAction
	n := 0
	for _, p := range r.client.PendingActions() {
		if strings.HasPrefix(p.RequestID, idPrefix) {
			match = p
			n++
		}
	}
	return match, n == 1
}

// renderActionRequest builds the announcement shown to the whole room when a
// quorum-gated action is proposed (§1.3).
func (m *Model) renderActionRequest(e client.EvActionRequest) string {
	who := "@" + e.RequesterName
	if e.Self {
		who = "you"
	}
	sid := shortID(e.RequestID)
	var b strings.Builder
	fmt.Fprintf(&b, "⚡ %s request%s: %s  (needs %d endorsers — the requester plus %d more)\n",
		who, requestVerb(e.Self), shortAction(e.Action), e.QuorumNeeded, e.QuorumNeeded-1)
	fmt.Fprintf(&b, "   params: %s\n", e.Params)
	if e.Self {
		fmt.Fprintf(&b, "   awaiting independent approval — share id %s; cancel with /veto %s\n", sid, sid)
	} else {
		fmt.Fprintf(&b, "   approve: /approve %s confirm    ·    veto: /veto %s [reason]\n", sid, sid)
	}
	fmt.Fprintf(&b, "   expires in %ds", remainingSecs(e.ExpiresUnix, time.Now()))
	return b.String()
}

func requestVerb(self bool) string {
	if self {
		return ""
	}
	return "s"
}

// shortID is the 4-hex display prefix of a request id (e.g. "a3f9"); the slash
// commands accept this prefix.
func shortID(id string) string {
	if len(id) >= 4 {
		return id[:4]
	}
	return id
}

// shortAction renders an action name for display (break_glass → break-glass).
func shortAction(a string) string {
	if a == protocol.ActionBreakGlass {
		return "break-glass"
	}
	return a
}

// remainingSecs is the whole seconds until expiresUnix from now, floored at 0.
func remainingSecs(expiresUnix int64, now time.Time) int {
	s := int(time.Unix(expiresUnix, 0).Sub(now).Seconds())
	if s < 0 {
		return 0
	}
	return s
}

// defaultBeaconTTL is the beacon link's default lifetime, and the persistence
// requested by /beacon set (the server clamps it to the room's beacon_ttl). The
// hard ceiling is 24h.
const defaultBeaconTTL = time.Hour
const maxBeaconTTL = 24 * time.Hour

// runBeacon implements /beacon (§1.2): publish, clear, read, or link an out-of-band
// status beacon. The status is encrypted to a beacon key DISTINCT from the room key
// and stored on the relay as opaque ciphertext, so a beacon reader can see status
// without ever reading room messages.
func (m *Model) runBeacon(r *room, arg string) {
	if !m.connected(r) {
		return
	}
	sub, rest, _ := strings.Cut(strings.TrimSpace(arg), " ")
	switch strings.ToLower(sub) {
	case "set":
		status := unquote(strings.TrimSpace(rest))
		if status == "" {
			m.addError(`usage: /beacon set "<status text>"`)
			return
		}
		r.client.SetBeacon(status, int(defaultBeaconTTL.Seconds()))
	case "clear":
		r.client.ClearBeacon()
	case "status":
		r.client.FetchBeaconStatus()
	case "link":
		m.runBeaconLink(r, rest)
	case "":
		m.addError(`usage: /beacon set "<text>" | clear | status | link [--ttl 2h]`)
	default:
		m.addError("unknown /beacon subcommand " + sub + `  ·  set "<text>" | clear | status | link`)
	}
}

// runBeaconLink mints the read-only beacon URL embedding the beacon key — the only
// thing a reader needs to decrypt the status (and nothing else). The link confers
// no room membership and cannot read messages.
func (m *Model) runBeaconLink(r *room, arg string) {
	ttl, err := parseBeaconLinkTTL(arg)
	if err != nil {
		m.addError(err.Error())
		return
	}
	key, ok := r.client.BeaconKeyB64()
	if !ok {
		m.addError("room key not established yet — cannot derive the beacon key")
		return
	}
	link := m.beaconLink(r.name, key, int(ttl.Seconds()))
	m.addSystem("beacon read-only link (status only — confers no room access; share out of band):\n  " + link)
}

// beaconLink builds the browser read URL for a room beacon: the web /beacon page
// with the room, the base64 beacon key, and the link's stated lifetime.
func (m *Model) beaconLink(room, keyB64 string, ttlSeconds int) string {
	base := strings.TrimRight(m.webBase(), "/")
	q := url.Values{"room": {room}, "key": {keyB64}, "ttl": {strconv.Itoa(ttlSeconds)}}
	return base + "/beacon?" + q.Encode()
}

// parseBeaconLinkTTL parses an optional "--ttl <dur>" (default 1h, max 24h).
func parseBeaconLinkTTL(arg string) (time.Duration, error) {
	fields := strings.Fields(arg)
	ttl := defaultBeaconTTL
	for i := 0; i < len(fields); i++ {
		flag := fields[i]
		val := ""
		if eq := strings.IndexByte(flag, '='); eq >= 0 {
			flag, val = flag[:eq], flag[eq+1:]
		} else if i+1 < len(fields) {
			val = fields[i+1]
			i++
		}
		if strings.TrimLeft(flag, "-") != "ttl" {
			return 0, fmt.Errorf("usage: /beacon link [--ttl 2h]")
		}
		d, perr := time.ParseDuration(val)
		if perr != nil || d <= 0 {
			return 0, fmt.Errorf("bad --ttl %q  (e.g. 30m, 1h, 24h)", val)
		}
		ttl = d
	}
	if ttl > maxBeaconTTL {
		ttl = maxBeaconTTL
	}
	return ttl, nil
}

// unquote strips one layer of surrounding single or double quotes from s.
func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
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

// runPropose implements /propose (NC-W1): propose an agent-produced artifact for
// human approval. It carries only the artifact's hash — never its content.
func (m *Model) runPropose(r *room, arg string) {
	if !m.connected(r) {
		return
	}
	source, ref, hash, summary, err := parseProposeArgs(arg)
	if err != nil {
		m.addError(err.Error())
		return
	}
	q := m.quorumFor(protocol.ActionArtifact)
	if q == 0 {
		m.addError("artifact approval is disabled by policy ([action.artifact] quorum = 0)")
		return
	}
	if _, err := r.client.Propose(source, ref, hash, summary, q); err != nil {
		m.addError(err.Error())
	}
}

// runApproveArtifact implements /approve-artifact <id> (NC-W1).
func (m *Model) runApproveArtifact(r *room, arg string) {
	if !m.connected(r) {
		return
	}
	id := strings.TrimSpace(arg)
	if id == "" {
		m.addError("usage: /approve-artifact <proposal-id>   (see the proposal notice)")
		return
	}
	if err := r.client.ApproveArtifact(id); err != nil {
		m.addError(err.Error())
	}
}

// runRejectArtifact implements /reject-artifact <id> [reason] (NC-W1).
func (m *Model) runRejectArtifact(r *room, arg string) {
	if !m.connected(r) {
		return
	}
	fields := strings.Fields(arg)
	if len(fields) == 0 {
		m.addError("usage: /reject-artifact <proposal-id> [reason]")
		return
	}
	id := fields[0]
	reason := strings.TrimSpace(strings.TrimPrefix(arg, id))
	if err := r.client.RejectArtifact(id, reason); err != nil {
		m.addError(err.Error())
	}
}

// parseProposeArgs parses the /propose flags. --source/--ref/--hash each take one
// token; --summary takes the rest of the line. Quote-free values (the TUI form);
// the headless `netherchat propose` CLI uses a real flag parser for quoted values.
func parseProposeArgs(arg string) (source, ref, hash, summary string, err error) {
	toks := strings.Fields(arg)
	for i := 0; i < len(toks); i++ {
		switch toks[i] {
		case "--source":
			if i+1 < len(toks) {
				i++
				source = toks[i]
			}
		case "--ref":
			if i+1 < len(toks) {
				i++
				ref = toks[i]
			}
		case "--hash":
			if i+1 < len(toks) {
				i++
				hash = toks[i]
			}
		case "--summary":
			summary = strings.Join(toks[i+1:], " ")
			i = len(toks)
		}
	}
	if source == "" || ref == "" || hash == "" {
		return "", "", "", "", fmt.Errorf("usage: /propose --source <agent> --ref <ref> --hash <sha256> [--summary <line>]")
	}
	return source, ref, hash, summary, nil
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

// msgWidth is the column width of the message pane (mirrors the layout math in
// resize), used to decide whether a QR code fits (§2.4).
func (m *Model) msgWidth() int {
	sidePanes := 0
	if m.sidebarW > 0 {
		sidePanes++
	}
	if m.membersW > 0 {
		sidePanes++
	}
	w := m.width - m.sidebarW - m.membersW - sidePanes
	if w < 1 {
		return m.width
	}
	return w
}

// transportLabel renders how the active room is connected: the relay URL, or
// "direct (… no relay)" in a Sneakernet session (§1.1). In the TUI this is the
// relay; the direct transport is used by `netherchat pair`.
func (m *Model) transportLabel(r *room) string {
	if r == nil || r.client == nil {
		return "relay " + m.url + " (connecting…)"
	}
	t := r.client.Transport()
	if t == nil {
		return "relay " + m.url + " (connecting…)"
	}
	if t.PeerID() != "" { // a direct peer connection has a peer fingerprint
		return "direct (" + t.RemoteAddr() + ", no relay)"
	}
	return "relay (" + t.RemoteAddr() + ")"
}

// runPeers lists the room members and the transport, for /peers. It is
// transport-agnostic — the same view in relay and Sneakernet (direct) mode.
func (m *Model) runPeers(r *room) {
	if !m.connected(r) {
		return
	}
	var b strings.Builder
	b.WriteString("transport: " + m.transportLabel(r) + "\n")
	peers := r.client.Members()
	if len(peers) == 0 {
		b.WriteString("no other peers in this room yet")
	} else {
		for _, p := range peers {
			name := p.Name
			if name == "" {
				name = "(unnamed)"
			}
			b.WriteString(fmt.Sprintf("  %-16s %s\n", name, p.Fingerprint))
		}
	}
	m.addSystem(strings.TrimRight(b.String(), "\n"))
}

func (m *Model) whoamiText(r *room) string {
	var b strings.Builder
	b.WriteString("fingerprint: " + m.fingerprint + "\n")
	b.WriteString("identity:    " + m.sourceLabel() + "\n")
	b.WriteString("name:        " + m.name + "\n")
	b.WriteString("transport:   " + m.transportLabel(r) + "\n")
	b.WriteString("notifications: " + m.notifier.Summary() + "\n")
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

// renderInvite builds the multi-line block shown for a minted invite: the token,
// the browser join link, the CLI join command, and — when /invite --qr was used —
// the join link as a scannable terminal QR (§2.4), falling back to text if the
// pane is too narrow.
func (m *Model) renderInvite(room string, e client.EvInvite) string {
	link := m.joinLink(room, e.Token)

	var b strings.Builder
	b.WriteString(fmt.Sprintf("one-time invite for #%s:\n", room))
	b.WriteString("  token: " + e.Token + "\n")
	b.WriteString("  join:  " + link + "\n")
	b.WriteString(fmt.Sprintf("  cli:   netherchat connect %s --room %s --invite %s\n", m.url, room, e.Token))
	if !e.Expires.IsZero() {
		b.WriteString("  expires: " + e.Expires.Format("2006-01-02 15:04") + "\n")
	}
	if r := m.session[room]; r != nil && r.inviteQR {
		r.inviteQR = false
		if code, ok := qr.Render(link, m.msgWidth()); ok {
			b.WriteString("\n" + code + "\n")
		} else {
			b.WriteString("\n  (terminal too narrow for a QR — scan or share the join link above)\n")
		}
	}
	return b.String()
}
