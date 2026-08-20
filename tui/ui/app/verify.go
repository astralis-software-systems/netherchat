package app

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// verifyEntry is the in-memory SAS-verification state for one peer, keyed by the
// peer's identity fingerprint. It does NOT persist across sessions (by design).
type verifyEntry struct {
	handle     string
	sas        []string
	verified   bool
	verifiedAt time.Time
}

// isVerified reports whether the peer with this fingerprint has been SAS-verified
// this session.
func (m *Model) isVerified(fpr string) bool {
	if fpr == "" {
		return false
	}
	e := m.verified[fpr]
	return e != nil && e.verified
}

// runVerify implements /verify (§1.2):
//
//	/verify           → verification status of all current members
//	/verify @bob      → the 5-word SAS to read to bob over a trusted side channel
//	/verify @bob ok   → mark bob SAS-verified for this session
func (m *Model) runVerify(arg string) tea.Cmd {
	fields := strings.Fields(arg)
	if len(fields) == 0 {
		m.addSystem(m.verifyStatusText())
		return nil
	}
	handle := strings.TrimPrefix(fields[0], "@")
	r := m.activeRoom()
	if !m.connected(r) {
		return nil
	}
	if len(fields) >= 2 && strings.EqualFold(fields[1], "ok") {
		m.markVerified(handle)
		return nil
	}

	words, fpr, ok := r.client.SAS(handle)
	if !ok {
		m.addError("can't verify @" + handle + " — no such member here yet, or the room key isn't ready")
		return nil
	}
	e := m.verified[fpr]
	if e == nil {
		e = &verifyEntry{handle: handle}
		m.verified[fpr] = e
	}
	e.handle = handle
	e.sas = words
	m.addSystem(m.renderSAS(handle, words))
	return nil
}

// markVerified flags the named peer as SAS-verified for the session.
func (m *Model) markVerified(handle string) {
	r := m.activeRoom()
	_, fpr, ok := r.client.LookupMember(handle)
	if !ok {
		m.addError("no member named @" + handle + " in this room")
		return
	}
	e := m.verified[fpr]
	if e == nil {
		e = &verifyEntry{handle: handle}
		m.verified[fpr] = e
	}
	e.handle = handle
	e.verified = true
	e.verifiedAt = time.Now()
	m.addSystem("✓ @" + handle + " verified  (" + shortFpr(fpr) + ")")
}

// renderSAS formats the 5-word SAS one per line, numbered, with read-aloud
// instructions.
func (m *Model) renderSAS(handle string, words []string) string {
	var b strings.Builder
	b.WriteString("short authentication string for @" + handle + ":\n")
	for i, w := range words {
		b.WriteString(fmt.Sprintf("  %d. %s\n", i+1, w))
	}
	b.WriteString("Read these words to @" + handle + " over a trusted side channel.\n")
	b.WriteString("If they match, type:  /verify @" + handle + " ok")
	return b.String()
}

// verifyStatusText lists every current member with their verification status.
func (m *Model) verifyStatusText() string {
	r := m.activeRoom()
	if r == nil {
		return "not in a room"
	}
	var b strings.Builder
	b.WriteString("verification status:\n")
	if len(r.order) == 0 {
		b.WriteString("  (no other members)")
		return b.String()
	}
	for _, id := range r.order {
		mem := r.members[id]
		b.WriteString(fmt.Sprintf("  @%-14s %s\n", mem.displayName(), m.trustWords(mem.name, mem.fpr)))
	}
	return strings.TrimRight(b.String(), "\n")
}

// verifiedCount returns how many current members of the active room are verified.
func (m *Model) verifiedCount() int {
	r := m.activeRoom()
	if r == nil {
		return 0
	}
	n := 0
	for _, id := range r.order {
		if m.isVerified(r.members[id].fpr) {
			n++
		}
	}
	return n
}
