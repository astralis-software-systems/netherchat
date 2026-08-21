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
// # ◆ IS REACHABLE ONLY WITH AN ISSUER PINNED, AND THAT IS THE POINT
//
// Verification takes an issuer key and an evaluation time. `connect --issuer
// <file>` supplies the first and the clock supplies the second (D-L; see
// issuerpin.go for why a screen may pin a key when a producer may not). With no
// such flag every carried credential in the room stays a claim, and every
// surface is byte-identical to the tree before the flag existed.
//
// So this vocabulary now says something about the READER as much as about the
// peer: two people in one room, looking at the same wire bytes, see different
// marks because one of them pinned their organization's CA. /issuer is where a
// person asks which of the two they are.
//
// TestTheVerifiedMarkIsReachableOnlyWithAnIssuerPinned holds both halves.

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
//
// It takes the member rather than a handle and a fingerprint because two of its
// answers need the attribution itself: the signed name a ◆ row renders under
// (which is not the name these surfaces address it by — see handle.go), and the
// reason a ◇ row is a ◇ once a pin exists to have produced one.
func (m *Model) trustWords(mem memberView) string {
	if attest.IdentityDisplayMark(m.credentialStateOf(mem.fpr)) == "◆" {
		// The panes render the signed name and these surfaces render the
		// addressable one, so this is where the two are put side by side. Without
		// it a reader looking at "Rosa Alvarez ◆" in the panel has no way to learn
		// that the thing to type is @rosa.
		if signed := mem.displayName(); signed != "" && signed != mem.name {
			return fmt.Sprintf("◆ issuer-attested as %q", signed)
		}
		return "◆ issuer-attested"
	}
	switch m.trustLevelOf(mem.name, mem.fpr) {
	case trustSAS:
		return "✓✓ SAS-verified"
	case trustPin:
		return "✓ [[trust]]-pinned"
	}
	if attest.IdentityDisplayMark(m.credentialStateOf(mem.fpr)) == "◇" {
		return carriedWords(mem.identity, m.pinned())
	}
	return "unverified"
}

// carriedWords says why a credential is a hollow diamond. Before an issuer could
// be pinned there was one answer and "not checked here" was always true; with a
// pin it is often false — the credential WAS checked and it did not verify — and
// a surface that kept saying it would be reassuring at exactly the point of
// failure, which this codebase has three prior instances of.
//
// pinned is an input rather than something inferred from the reason, because two
// outcomes reach here WITHOUT any key: the subject join and the parse are checks
// this client makes either way. Inferring from the reason class would have made
// an unpinned client claim it checked something against a key it does not hold —
// and TestPresenceInertWithCredentialsAndNoIssuerPinned caught exactly that.
//
// The pinned branches follow ClassOf, whose rendering rule is normative:
// unconfigured and unanchored are facts about this reader and must never read as
// findings about the person. Lifecycle is a fact about the credential.
func carriedWords(d attest.IdentityDisplay, pinned bool) string {
	if d.Reason == attest.ReasonSubjectMismatch {
		return "◇✗ credential is about a different key"
	}
	if d.Reason == attest.ReasonMalformedArtifact {
		// The other outcome reachable with NO key: the bytes did not parse. It
		// belongs above the `pinned` branch for the same reason the subject join
		// does — a reader who is told "not checked here" when the parse is what
		// failed has been reassured at the exact point of the failure, and this
		// was the only surface still doing it.
		return "◇ the bytes carried here are not an identity artifact"
	}
	if !pinned {
		return "◇ carries a credential, not checked here"
	}
	switch attest.ClassOf(d.Reason) {
	case attest.ClassUnanchored:
		return "◇ carries a credential from an authority this client has not pinned"
	case attest.ClassLifecycle:
		return "◇ credential checked here — " + string(d.Reason)
	case "", attest.ClassUnconfigured:
		return "◇ carries a credential, not checked here"
	default:
		return "◇ credential checked here and did not verify — " + string(d.Reason)
	}
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
func credentialBlock(indent string, d attest.IdentityDisplay, pinned bool) string {
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
		fmt.Fprintf(&b, "%s  ◆ checked here against a pinned issuer key, for a window that contained\n"+
			"%s    the evaluation time.  /issuer names the key and when.\n", indent, indent)
	default:
		switch {
		case !pinned:
			// The unpinned sentence, unchanged and unchangeable: every surface on a
			// client that pinned nothing is byte-identical to the tree before the
			// pin existed, and this line is the one most of them end on.
			fmt.Fprintf(&b, "%s  ◇ carried on this connection; not checked here — this client pins no "+
				"issuer key.\n%s    A reader with one checks it: netherchat verify <record> --issuer <key>\n",
				indent, indent)
		case d.Reason == attest.ReasonSubjectMismatch:
			fmt.Fprintf(&b, "%s  ◇ this client pins an issuer key and did not reach it: the credential is\n"+
				"%s    about another key, which is settled above and settles everything.\n", indent, indent)
		case attest.ClassOf(d.Reason) == attest.ClassUnanchored:
			fmt.Fprintf(&b, "%s  ◇ carried on this connection. It names an authority this client has not\n"+
				"%s    pinned, so nothing here checked it — which is a fact about this client's\n"+
				"%s    configuration and not about the person.  /issuer names what IS pinned.\n",
				indent, indent, indent)
		default:
			// The credential WAS checked against a pinned key and did not verify.
			// Saying "not checked here" would be reassurance standing exactly where
			// the failure is.
			fmt.Fprintf(&b, "%s  ◇ checked here against a pinned issuer key and did NOT verify: %s\n",
				indent, d.Reason)
		}
		// Only when the detail adds something the lines above did not. An empty
		// Reason means "nothing was attempted", which they already said, and a
		// mismatch has already had its own paragraph at the top.
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
			return credentialBlock("  ", mem.identity, m.pinned())
		}
	}
	return ""
}

// ownCredentialText is the /whoami half: what THIS operator is carrying, so they
// can see it before they act rather than after somebody reads the record. Empty
// when none is provisioned, which keeps /whoami byte-identical on an
// unprovisioned client.
//
// It renders a decision made elsewhere (useCredential, recheckIdentities) rather
// than making one, because deciding takes an evaluation time and a view is not
// where a clock is read: an operator's own credential expires on the same tick
// a peer's does.
func (m *Model) ownCredentialText() string {
	if m.credential == nil {
		return ""
	}
	return credentialBlock("", m.ownIdentity, m.pinned())
}
