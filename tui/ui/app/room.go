package app

import (
	"time"

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
	lineRaw // pre-rendered multi-line block (e.g. an invite QR), not wrapped
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
}

func newRoom(name string) *room {
	return &room{name: name, members: make(map[string]memberView), collapse: render.NewCollapseState()}
}

func (r *room) addMember(id, name, fpr string) {
	if _, ok := r.members[id]; !ok {
		r.order = append(r.order, id)
	}
	r.members[id] = memberView{name: name, fpr: fpr}
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
