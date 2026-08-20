package app

import (
	"time"

	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/ui/render"
)

// lineKind classifies a rendered line so the view can style it.
type lineKind int

const (
	lineMessage lineKind = iota // E2E message from another member
	lineSelf                    // our own E2E message
	lineSystem                  // local notices (joins/leaves/status)
	lineServer                  // webhook/system output — NOT E2E (plaintext marker)
	lineExec                    // edge-exec request/result — E2E, signed, attributable
	lineRecord                  // sealed-record entry (/decide /action /mark, or a /replay)
	lineError
	lineRaw    // pre-rendered multi-line block (e.g. an invite QR), not wrapped
	lineStream // a live-log stream block (§2.2); text holds the stream_id, content is in room.streams
)

type line struct {
	at   time.Time
	kind lineKind
	from string
	text string

	// For message lines: the sender's identity fingerprint and whether the
	// message carried a valid signature. The trust/verify badge is computed at
	// render time from these + current verification state, so verifying a peer
	// updates the badge on their earlier messages too.
	fpr    string
	signed bool

	// For lineRecord: the record entry's structure, kept so the entry re-renders
	// (and exports) from data rather than a frozen pre-rendered string. recordKind
	// is decision|action|note; replayed marks an entry streamed in by /replay.
	recordKind string
	actionee   string
	replayed   bool
}

// memberView is the per-room cache of a member's display name and identity
// fingerprint, so the member list and message badges can be drawn without
// re-querying the client.
type memberView struct {
	name string
	fpr  string

	// identity is the D-I attribution for this member, resolved once when they
	// join rather than on every frame the pane redraws. It is always an
	// unverified state here — see attribution.go on why a live room cannot reach
	// a verified one — and holding it as an attest.IdentityDisplay rather than as
	// raw bytes is what keeps the pane from re-deciding the question.
	identity attest.IdentityDisplay
}

// displayName is the name D-I says to draw for this member: the signed one when
// an issuer's statement about their key was checked here, the one they chose
// otherwise. Today the two are always the same string, because no live surface
// holds an issuer key (attribution.go). The call is routed through the decision
// anyway so that the day one appears, the panes already ask the right question.
//
// The ADDRESSABLE handle stays `name` — /verify @bob, /whois @bob and the
// [[trust]] lookup all key on what the sender chose, because that is what is on
// the wire. If a signed name ever renders here they can differ, and deciding
// what an operator types then is part of D-L rather than of this change.
func (v memberView) displayName() string {
	if v.identity.Name != "" {
		return v.identity.Name
	}
	return v.name
}

// room is the per-room client + view state. The TUI holds one client core per
// joined room (one WebSocket each), so every room is an independent E2E session.
type room struct {
	name   string
	client *client.Client

	lines   []line
	members map[string]memberView // id -> {display name, fingerprint} (excludes self)
	order   []string              // member ids in join order

	unread    int
	keyReady  bool
	connected bool

	inviteOnly bool
	webhook    bool

	ttl      time.Duration // client-side message display TTL (0 = none)
	failed   bool
	scuttled bool // the room was scuttled (§1.6): keys destroyed, room gone

	// Paste-rendering fold state (§2.6): which collapsed code blocks / stack
	// traces are expanded, and the highest block id assigned by the last render
	// (so /expand can validate its argument). Reset when history is cleared.
	collapse   *render.CollapseState
	maxBlockID int

	// rosterOut is the --out path stashed by /roster --signed, applied when the
	// co-signed attestation finishes (§1.4). Empty means the default roster.json.
	rosterOut string

	// inviteQR is set by /invite --qr and consumed when the minted token arrives,
	// so the join link is rendered as a terminal QR code (§2.4).
	inviteQR bool

	// autoClock requests that the incident clock auto-start when this room's key is
	// ready (A1) — set for break-glass war rooms.
	autoClock bool

	// Live log streaming (§2.2). streams holds each live block by stream_id;
	// streamOrder is appearance order (for the "stream-N" /expand id). activeStream
	// is our OWN outbound /stream (file tail), nil when we are not streaming.
	streams      map[string]*streamView
	streamOrder  []string
	activeStream *streamSender
}

// streamView is the receiver-side state of one live-log stream block (§2.2): the
// current ring-buffer contents, updated in place by each StreamUpdate.
type streamView struct {
	id     string
	name   string // source label (e.g. "app.log")
	from   string // streamer display name
	self   bool
	lines  []string
	seq    uint64
	ended  bool
	reason string
	num    int // 1-based appearance index, for /expand stream-<num>
}

func newRoom(name string) *room {
	return &room{
		name:     name,
		members:  make(map[string]memberView),
		collapse: render.NewCollapseState(),
		streams:  make(map[string]*streamView),
	}
}

func (r *room) addMember(id, name, fpr string) {
	r.addMemberWithCredential(id, name, fpr, nil)
}

// addMemberWithCredential records a member and resolves their attribution once.
// carried is whatever rode on their Member frame, or nil.
func (r *room) addMemberWithCredential(id, name, fpr string, carried []byte) {
	if _, ok := r.members[id]; !ok {
		r.order = append(r.order, id)
	}
	r.members[id] = memberView{name: name, fpr: fpr, identity: parseCarried(name, fpr, carried)}
}

// parseCarried resolves the D-I attribution for a member of a live room.
//
// The nil verification result is the whole story of this surface: it is the
// verification result, and there is never one here. Netherchat holds no trust
// anchors (roadmap §6 rule 1) and has no issuer flag on connect (identity spec
// §9.4), so a room can say a credential ARRIVED and can show what it claims, and
// cannot say anything about whether it is true. Passing nil rather than
// inventing a local check is what keeps that honest, and routing through
// IdentityDisplayForBytes rather than reading the artifact directly is what
// makes the day an issuer key exists a change in one function.
func parseCarried(assertedName, fpr string, carried []byte) attest.IdentityDisplay {
	return attest.IdentityDisplayForBytes(assertedName, fpr, carried, nil)
}

func (r *room) removeMember(id string) string {
	name := r.members[id].name
	delete(r.members, id)
	for i, x := range r.order {
		if x == id {
			r.order = append(r.order[:i], r.order[i+1:]...)
			break
		}
	}
	return name
}

func (r *room) appendLine(l line)     { r.lines = append(r.lines, l) }
func (r *room) appendSystem(s string) { r.appendLine(line{at: time.Now(), kind: lineSystem, text: s}) }
func (r *room) appendError(s string)  { r.appendLine(line{at: time.Now(), kind: lineError, text: s}) }

// pruneExpired removes content lines older than the room's TTL.
func (r *room) pruneExpired(now time.Time) bool {
	if r.ttl <= 0 {
		return false
	}
	kept := make([]line, 0, len(r.lines))
	changed := false
	for _, l := range r.lines {
		content := l.kind == lineMessage || l.kind == lineSelf || l.kind == lineServer || l.kind == lineExec
		if content && now.Sub(l.at) > r.ttl {
			changed = true
			continue
		}
		kept = append(kept, l)
	}
	r.lines = kept
	return changed
}

func joinNames(members []client.ConnMember) string {
	names := make([]string, 0, len(members))
	for _, m := range members {
		names = append(names, m.Name)
	}
	return joinComma(names)
}

func joinComma(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}
