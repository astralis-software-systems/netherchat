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

	// identity is the D-I attribution for this member, decided when they join and
	// re-decided only when the clock crosses a window boundary — never on a
	// redraw. Holding it as an attest.IdentityDisplay rather than as raw bytes is
	// what keeps the pane from re-deciding the question every frame.
	identity attest.IdentityDisplay

	// carried is the credential that rode in on their Member frame, kept because
	// a re-check needs the artifact and a rendered decision is not one. nil for a
	// member who carried nothing, which is the common case.
	carried []byte

	// recheckAt is the earliest instant at which re-running the check could give
	// a different answer — a window opening or closing. The zero time means no
	// clock event can change this row, which is true of every row on a client
	// that pinned no issuer key. See nextClockEvent.
	recheckAt time.Time
}

// displayName is the name D-I says to draw for this member: the signed one when
// an issuer's statement about their key was checked here, the one they chose
// otherwise. On a client that pinned no issuer key the two are always the same
// string, and every surface is byte-identical to the tree before the pin existed.
//
// The ADDRESSABLE handle stays `name`. The relay routes on it, the SAS is
// computed from the key it came with, a [[trust]] entry keys on it, and a record
// entry carries the string an operator typed — none of which may vary with who
// pinned what. What D-L added is that /verify and /whois also ANSWER to the
// signed name, so a name a person can see is a name they can type; resolveHandle
// is that lookup, and it refuses a string that fits two people rather than
// picking one.
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

// admitMember records a member of r and decides their attribution once, at the
// given evaluation time. carried is whatever rode on their Member frame, or nil.
//
// It hangs off the Model rather than off room because deciding the attribution
// takes the issuer pin, and the pin is the session's, not the room's. It is the
// ONLY function that writes r.members, so a member cannot enter a room by a
// route that skipped the decision — the same reason tui/sneakernet builds its
// client in exactly one place.
func (m *Model) admitMember(r *room, id, name, fpr string, carried []byte, at time.Time) {
	if r == nil {
		return
	}
	if _, ok := r.members[id]; !ok {
		r.order = append(r.order, id)
	}
	d, next := m.attributeBytes(name, fpr, carried, at)
	r.members[id] = memberView{name: name, fpr: fpr, carried: carried, identity: d, recheckAt: next}
	m.lastCheckedAt = at
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
