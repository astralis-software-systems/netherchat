package app

import (
	"fmt"
	"strings"

	"github.com/salehkreiner/netherchat/tui/attest"
)

// Presence attribution: one vocabulary for "what can this client say about the
// person behind this name", drawn identically wherever a name appears.
//
// # WHY THIS FILE EXISTS
//
// The marks were decided twice, one pane at a time, and drifted: ✓ meant
// SAS-verified in the participants panel and [[trust]]-pinned on a message,
// where ✓✓ meant SAS. Two meanings, one mark, two panes apart. Both panes now
// call trustMark, so a mark cannot mean two things without the disagreement
// being a change to this function.
//
// # THE VOCABULARY
//
//	◆   issuer-attested and checked here — an authority whose key this surface
//	    pinned signed a statement about this key, for a window containing the
//	    time this surface supplied
//	✓✓  SAS-verified — you read the words to them over a channel you trust
//	✓   [[trust]]-pinned — their fingerprint matches one in your netherchat.toml
//	◇   a credential arrived and nothing here checked it
//	    (nothing) — a signed frame and no more
//	?   unsigned — message lines only; a property of the frame, not of the peer
//
// Two families, and the split is the point. The ✓ family means THIS CLIENT
// CHECKED SOMETHING, and the count says how much of the checking was yours: two
// ticks for a human comparison out of band, one for a string you configured. The
// diamond family is somebody ELSE's statement, and it is filled when it has been
// checked and hollow when it has not — so a claim can never wear the shape of a
// check. Exactly one mark is drawn, the strongest thing this client can say, so
// a row never has to be parsed:
//
//	◆ > ✓✓ > ✓ > ◇ > nothing
//
// ◇ sits BELOW ✓ deliberately. A pin is a fingerprint this operator compared; a
// hollow diamond is an assertion nobody compared to anything. More words on a
// claim is not more trust.
//
// # ◆ IS NOT REACHABLE HERE, AND THAT IS A PROPERTY, NOT AN OMISSION
//
// Verification takes an issuer key and an evaluation time. Roadmap §6 rule 1 and
// identity spec §9.4 put both outside this program — "no --issuer flag on
// connect, no default key, no reader of an issuer-named file" — so a connected
// room evaluates every carried credential as no_issuer_pinned. The mark is
// defined here anyway, and tested, because the alternative is deciding it later
// in whichever surface acquires a pin first, which is how ✓ came to mean two
// things. TestTheVerifiedMarkIsUnreachableFromTheWire holds the line.

// trustLevel ranks what this client established about a peer's key, weakest
// first. It ranks only checks THIS CLIENT PERFORMED; a claim somebody else
// makes about the key is not on this scale.
type trustLevel int

const (
	trustNothing trustLevel = iota // a signed frame and no more
	trustPin                       // the fingerprint matches a [[trust]] pin
	trustSAS                       // SAS-verified out of band, this session
)

// trustLevelOf is the single evaluation both panes share. handle selects the
// [[trust]] entry, fpr is what is actually compared: a pin is a fingerprint
// match, never a name match.
func (m *Model) trustLevelOf(handle, fpr string) trustLevel {
	switch {
	case m.isVerified(fpr):
		return trustSAS
	case m.isPinned(handle, fpr):
		return trustPin
	default:
		return trustNothing
	}
}

// credentialStateOf returns the D-I state of the credential the peer with this
// fingerprint carried into the active room, resolved when they joined.
func (m *Model) credentialStateOf(fpr string) attest.IdentityDisplayState {
	r := m.activeRoom()
	if r == nil || fpr == "" {
		return attest.IdentityDisplayAsserted
	}
	for _, id := range r.order {
		if mem := r.members[id]; mem.fpr == fpr {
			if mem.identity.State == "" {
				return attest.IdentityDisplayAsserted
			}
			return mem.identity.State
		}
	}
	return attest.IdentityDisplayAsserted
}

// trustMark renders the mark for a peer, styled, with its leading space — or ""
// when this client has nothing to say. Both the participants panel and the
// message badge call it, which is what keeps them from disagreeing.
func (m *Model) trustMark(handle, fpr string) string {
	credential := attest.IdentityDisplayMark(m.credentialStateOf(fpr))
	if credential == "◆" {
		return m.st(m.theme.Success).Bold(true).Render(" ◆")
	}
	switch m.trustLevelOf(handle, fpr) {
	case trustSAS:
		return m.st(m.theme.Success).Bold(true).Render(" ✓✓")
	case trustPin:
		return m.st(m.theme.Success).Render(" ✓")
	}
	if credential == "◇" {
		// ✗ is this product's mark for "this client checked and it did not match"
		// (see pinStatus), so a credential about somebody else's key gets it. It is
		// two characters rather than a colour because a pane row is the one place a
		// colour is the only thing a reader has, and this is a finding.
		if m.credentialMismatch(fpr) {
			return m.st(m.theme.Warn).Render(" ◇✗")
		}
		// Muted, never Success. Colour carries meaning in this palette and nothing
		// here has succeeded at anything.
		return m.st(m.theme.Muted).Render(" ◇")
	}
	return ""
}

// credentialMismatch reports whether the peer's carried credential is about a
// different key than theirs — the one thing about a credential a surface with no
// issuer key can establish.
func (m *Model) credentialMismatch(fpr string) bool {
	r := m.activeRoom()
	if r == nil || fpr == "" {
		return false
	}
	for _, id := range r.order {
		if mem := r.members[id]; mem.fpr == fpr {
			return mem.identity.Reason == attest.ReasonSubjectMismatch
		}
	}
	return false
}

// trustWords is the same decision spelled out, for the detail surfaces that
// have room for a sentence (/verify, /roster). The mark comes first so the
// glyph a reader learned in the panes is the glyph they meet here, and the
// words are what stop a detail line from teaching a second vocabulary.
func (m *Model) trustWords(handle, fpr string) string {
	if attest.IdentityDisplayMark(m.credentialStateOf(fpr)) == "◆" {
		return "◆ issuer-attested"
	}
	switch m.trustLevelOf(handle, fpr) {
	case trustSAS:
		return "✓✓ SAS-verified"
	case trustPin:
		return "✓ [[trust]]-pinned"
	}
	if attest.IdentityDisplayMark(m.credentialStateOf(fpr)) == "◇" {
		if m.credentialMismatch(fpr) {
			return "◇✗ credential is about a different key"
		}
		return "◇ carries a credential, not checked here"
	}
	return "unverified"
}

// credentialBlock renders the claim a credential carries, for the two surfaces
// with room for sentences: /whois about a peer, /whoami about yourself.
//
// It states the claim and then states who checked it, in that order, because a
// reader who sees an enterprise principal and no qualifier will supply the
// qualifier themselves and supply the wrong one. Everything above the last line
// is what an issuer WROTE; the last line is what this program KNOWS, which on
// this surface is nothing.
//
// The wording of that last line follows ClassOf's rendering rule: the absence of
// a verified name here is a fact about this client's configuration, and dressing
// it as a finding would make a claim about the person that nothing checked.
func credentialBlock(indent string, d attest.IdentityDisplay) string {
	if d.State == attest.IdentityDisplayAsserted {
		return ""
	}
	var b strings.Builder
	// The subject mismatch goes FIRST, because it is the only thing this surface
	// actually established and everything below it is then a quotation of a claim
	// about somebody else. Trailing it under "not checked here" reads as a
	// footnote to an absence, when it is a finding.
	if d.Reason == attest.ReasonSubjectMismatch {
		fmt.Fprintf(&b, "%s◇✗ this credential is about a DIFFERENT key — whatever it claims below says\n"+
			"%s   nothing about this person.\n%s   %s\n", indent, indent, indent, d.Detail)
	}
	name := d.Principal
	if name == "" {
		name = "(the artifact named no principal)"
	}
	fmt.Fprintf(&b, "%scredential:  %s", indent, name)
	if d.DisplayName != "" {
		fmt.Fprintf(&b, "  (%s)", d.DisplayName)
	}
	b.WriteString("\n")
	if len(d.Roles) > 0 {
		fmt.Fprintf(&b, "%s  roles:     %s\n", indent, strings.Join(d.Roles, ", "))
	}
	if d.Issuer != "" {
		fmt.Fprintf(&b, "%s  issuer:    %s\n", indent, d.Issuer)
	}
	switch d.State {
	case attest.IdentityDisplayVerifiedNamed, attest.IdentityDisplayVerifiedUnnamed:
		fmt.Fprintf(&b, "%s  ◆ verified against a pinned issuer key\n", indent)
	default:
		fmt.Fprintf(&b, "%s  ◇ carried on this connection; not checked here — this client pins no "+
			"issuer key.\n%s    A reader with one checks it: netherchat verify <record> --issuer <key>\n",
			indent, indent)
		// Only when the detail adds something the two lines above did not. An
		// empty Reason means "nothing was attempted", which they already said, and
		// a mismatch has already had its own paragraph at the top.
		if d.Detail != "" && d.Reason != "" &&
			d.Reason != attest.ReasonNoIssuerPinned && d.Reason != attest.ReasonSubjectMismatch {
			fmt.Fprintf(&b, "%s    (%s)\n", indent, d.Detail)
		}
	}
	return b.String()
}

// whoisCredentialText is the /whois half: the credential a named peer carried,
// or "" when they carried none. A peer carrying nothing gets no block at all —
// an empty one would read as an absence somebody should act on.
func (m *Model) whoisCredentialText(r *room, handle string) string {
	if r == nil {
		return ""
	}
	for _, id := range r.order {
		if mem := r.members[id]; mem.name == handle {
			return credentialBlock("  ", mem.identity)
		}
	}
	return ""
}

// ownCredentialText is the /whoami half: what THIS operator is carrying, so they
// can see it before they act rather than after somebody reads the record. Empty
// when none is provisioned, which keeps /whoami byte-identical to before this
// phase on an unprovisioned client.
func (m *Model) ownCredentialText() string {
	if m.credential == nil {
		return ""
	}
	return credentialBlock("", attest.IdentityDisplayFor(m.name, m.fingerprint, m.credential, nil))
}
