package app

import (
	"fmt"
	"strings"
)

// What an operator types when the rendered name and the addressable handle
// differ (D-L).
//
// Before a live surface could verify anything, the question could not arise: the
// D-I name was always the name the sender chose, so there was one string and it
// was both the label and the address. A verified row renders a name an ISSUER
// signed, and now there are two — "Rosa Alvarez" on the screen and "rosa" on the
// wire.
//
// A rendered name that cannot be typed is a worse surface than an unrendered
// one, so BOTH resolve here. What does not change is what goes out: this
// function answers with a participant, and every caller then addresses that
// participant by the name on their wire frame. The relay routes on that name,
// the SAS is computed from that key, and a record entry carries the string the
// operator typed — none of which may depend on whether anybody pinned anything.
// TestTheRecordPathTakesTheWireHandleOnly bounds where this function may be
// called from, and it is a short list.
//
// A [[trust]] pin is deliberately NOT on the list. Those handles sit in the
// operator's own netherchat.toml beside a fingerprint they compared themselves;
// if a signed name selected the entry, an issuer's choice of display string
// would decide which of the operator's pins applied to whom.

// cutHandle peels a leading @handle off a command argument and returns the rest.
// A signed name contains a space, so the quoted form has to work:
//
//	@rosa ok               → ("rosa", "ok")
//	@"Rosa Alvarez" ok     → ("Rosa Alvarez", "ok")
//
// An unterminated quote is returned verbatim rather than swallowing the line,
// so the resolver's "no such member" names what was actually typed.
func cutHandle(arg string) (handle, rest string) {
	s := strings.TrimSpace(arg)
	s = strings.TrimPrefix(s, "@")
	if s == "" {
		return "", ""
	}
	if q := s[0]; q == '"' || q == '\'' {
		if end := strings.IndexByte(s[1:], q); end >= 0 {
			return s[1 : 1+end], strings.TrimSpace(s[2+end:])
		}
		// No closing quote: nothing was delimited, so nothing is peeled.
		return strings.Fields(s)[0], strings.TrimSpace(strings.TrimPrefix(s, strings.Fields(s)[0]))
	}
	h, r, _ := strings.Cut(s, " ")
	return h, strings.TrimSpace(r)
}

// resolveHandle maps what an operator typed to exactly one participant of r.
//
// It matches, case-insensitively, against the name the sender chose AND the name
// D-I decided to render — which are the same string on every row this client has
// not verified, so with no issuer pinned the candidate set is exactly what it
// has always been.
//
// A string that fits two participants is REFUSED. Rendering a signed name
// creates a collision the wire never had: anyone may set their handle to the
// string an issuer signed for somebody else, and then two rows on one screen
// read the same. Picking the first match would pick silently, and the one the
// operator meant is the one they were pointing at — which this function cannot
// see. So it names both and lets them choose by fingerprint.
func (m *Model) resolveHandle(r *room, typed string) (memberView, error) {
	typed = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(typed), "@"))
	if r == nil || typed == "" {
		return memberView{}, fmt.Errorf("no member named @%s in this room", typed)
	}
	var hits []memberView
	for _, id := range r.order {
		mem := r.members[id]
		if strings.EqualFold(mem.name, typed) || strings.EqualFold(mem.displayName(), typed) {
			hits = append(hits, mem)
		}
	}
	switch len(hits) {
	case 1:
		return hits[0], nil
	case 0:
		// The room view is built from Member frames and the client core keeps its
		// own membership; falling back keeps a handle that resolved before this
		// function existed resolving now.
		if r.client != nil {
			if _, fpr, ok := r.client.LookupMember(typed); ok {
				return memberView{name: typed, fpr: fpr}, nil
			}
		}
		return memberView{}, fmt.Errorf("no member named @%s in this room", typed)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "@%s fits %d participants here — say which by handle:\n", typed, len(hits))
	for _, mem := range hits {
		fmt.Fprintf(&b, "  @%-14s %s  %s\n", mem.name, shortFpr(mem.fpr), m.trustWords(mem))
	}
	b.WriteString("  (a name an issuer signed and a name a sender chose can be the same string;\n")
	b.WriteString("   the fingerprint is the one that cannot be)")
	return memberView{}, fmt.Errorf("%s", strings.TrimRight(b.String(), "\n"))
}
