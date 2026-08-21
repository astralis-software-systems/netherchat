package app

import (
	"fmt"
	"strings"
	"time"

	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/record"
)

// The room view's half of D-I: what a sealed-record entry carrying an identity
// attestation looks like where a person is actually looking.
//
// # WHAT IT LOOKED LIKE BEFORE
//
// renderRecordEntry printed "📌 " + kind + author + ": " + Body for every kind it
// did not special-case, and an attestation's Body is
// (*attest.IdentityAttestation).Marshal() — indented JSON. Twenty-two lines of it
// landed in the message pane the moment the designated writer filed an approver's
// credential, captured byte-for-byte in testdata/room_identity_pre3c_json.txt.
//
// # THE DECISION IS NOT TAKEN HERE
//
// Which name goes where a person's name goes, and which mark stands beside it, is
// D-I, and D-I lives in exactly one function: attest.IdentityDisplayFor. This file
// obtains an IdentityResult the only way a live surface may — (*Model).attribute,
// the single reader of the issuer pin — and renders what comes back. It decides
// nothing about names or marks, and it must not start to: a fifth surface that
// took the decision again is how the ✓ collision happened with two.
//
// # THE JOIN ON THIS SURFACE IS A DIFFERENT QUESTION FROM THE ONE ON PRESENCE
//
// On Member/Hello a credential ARRIVES ON A KEY, and the join is "is this
// statement about the key it rode in on" — because an attestation is not a secret
// and anyone who has seen one can attach it to their own frame (Phase 3b §7).
//
// A record entry is not worn by a key. It is FILED by an author about a subject,
// and the two are routinely different people: the designated writer files every
// approver's credential (client.writeApproverCredentials), so author ≠ subject is
// the normal case in the demo and not a finding. Rendering ◇✗ there would call an
// honest, load-bearing operation an attack.
//
// So the key being rendered on this surface is the artifact's own subject, and
// what the surface owes a reader instead is that the subject is VISIBLE and never
// confused with the author:
//
//   - the signed name is never placed in the author slot — the author keeps the
//     name they typed, and the credential's name appears after a verb ("filed a
//     credential for …"), so the grammar itself says who is who;
//   - the subject is named on its own line, as a room handle when somebody here
//     holds that key and as the whole fingerprint when nobody does;
//   - "filed their own credential" is said only when the author's fingerprint IS
//     the subject, which is a comparison this client can make with no issuer key
//     and no clock, exactly like the presence join.
//
// TestARoomLineNeverAttachesASignedNameToTheAuthorWhoFiledIt is that rule.
//
// # WHY A SCROLLBACK LINE IS NOT RE-DECIDED ON THE CLOCK
//
// A participants panel is re-decided on the room tick, because presence is now
// and "now" moves (D-L §3.2). A record line is not, and the asymmetry is
// deliberate: the pane is a log of things that happened, and rewriting the mark on
// a line stamped 14:35 at 15:01 would leave a reader with a mark and no way to
// know which moment it belonged to. So the decision is frozen at the instant the
// entry landed, and that instant is PRINTED on any line where a check was actually
// attempted — a frozen mark whose evaluation time is invisible is a claim with no
// provenance surface, which is the defect /issuer exists to close.
//
// A REPLAYED entry (§2.7) is not checked at all. Its credential belongs to a
// record that carries two signed timestamps to bracket an evaluation against
// (identity-v1-spec §5.6); this room's wall clock is not those, and answering "does it verify
// now" would be answering a question nobody asked about a record nobody is
// reading. The line says so and names the command that does ask the right one.

// recordIdentity is one decided attribution for an identity attestation carried
// by a record entry: what D-I says to render, plus the facts about the ENTRY that
// the display cannot carry because they are not properties of the credential.
type recordIdentity struct {
	// display is attest.IdentityDisplayFor's answer. Everything about names and
	// marks comes out of it and nothing here second-guesses it.
	display attest.IdentityDisplay

	// subject is the fingerprint the credential is about, and handle is the room
	// name of whoever holds that key — empty when nobody in this room does, which
	// is a fact worth showing rather than hiding.
	subject string
	handle  string

	// selfFiled: the entry's author IS the subject. A fingerprint comparison, no
	// issuer key and no clock, and the only thing this surface establishes about
	// the relationship between the author and the credential.
	selfFiled bool

	// checkedAt is the evaluation time this client used, zero when nothing was
	// checked (no pin, or a replayed entry). It is rendered rather than kept
	// because the decision is frozen.
	checkedAt time.Time

	// replayed marks an entry streamed in from a prior sealed record, which is
	// deliberately not evaluated against this room's clock.
	replayed bool

	// malformed: the entry body carries the identity schema tag and is not an
	// identity artifact. record.VerifyWithIdentity reaches the same outcome
	// (ReasonMalformedArtifact) on the same bytes.
	malformed bool
}

// appendRecordLine is the ONLY function that puts a record entry into a room
// buffer, for the reason admitMember is the only one that writes r.members: a
// typed entry that entered by another route would be a line whose attribution was
// never decided, and the view cannot decide it (it would have to read a clock).
//
// at is the evaluation time — supplied by the caller, never read here.
func (m *Model) appendRecordLine(r *room, e client.EvRecordEntry, at time.Time) {
	if r == nil {
		return
	}
	r.appendLine(line{
		at: e.At, kind: lineRecord, from: e.AuthorName, text: e.Body,
		fpr: e.AuthorFpr, signed: true,
		recordKind: e.Kind, actionee: e.Actionee, replayed: e.Replayed,
		schema:   e.Schema,
		identity: m.decideRecordIdentity(r, e, at),
	})
}

// decideRecordIdentity resolves the D-I attribution for an identity attestation
// entry, or nil for any entry that does not carry one.
//
// record.IsIdentityEntry is what decides "does this entry carry an attestation",
// here as everywhere: the schema tag is compared in one place, so a room view and
// an offline verifier walking the same chain agree about which entries they are
// looking at.
func (m *Model) decideRecordIdentity(r *room, e client.EvRecordEntry, at time.Time) *recordIdentity {
	if !record.IsIdentityEntry(record.Entry{Kind: e.Kind, Schema: e.Schema}) {
		return nil
	}
	att, err := attest.ParseIdentity([]byte(e.Body))
	if err != nil {
		// Something arrived under the identity tag and it is not an identity
		// artifact. IdentityDisplayForBytes lands it in the carried state rather
		// than the asserted one, because a surface showing "asserted" would be
		// saying nothing arrived.
		return &recordIdentity{
			display:   attest.IdentityDisplayForBytes("", "", []byte(e.Body), nil),
			malformed: true,
			replayed:  e.Replayed,
		}
	}

	ri := &recordIdentity{
		subject:   att.Subject,
		handle:    m.handleHolding(r, att.Subject),
		selfFiled: e.AuthorFpr != "" && att.Subject == e.AuthorFpr,
		replayed:  e.Replayed,
	}
	// The name this room would use for that key with no issuer in the world: the
	// handle if somebody here holds it, and otherwise the identifier itself, which
	// is the only name a key has before an authority gives it one.
	asserted := ri.handle
	if asserted == "" {
		asserted = shortHashUI(att.Subject)
	}
	if e.Replayed {
		ri.display = attest.IdentityDisplayFor(asserted, att.Subject, att, nil)
		return ri
	}
	ri.display, _ = m.attribute(asserted, att.Subject, att, at)
	// The window boundary that attribute schedules is deliberately dropped: see
	// the file comment. A record line records when it was decided.
	if m.pinned() {
		ri.checkedAt = at
	}
	return ri
}

// handleHolding returns the room name of whoever holds fpr — a member, or this
// operator — and "" when nobody here does. It is a fingerprint comparison and
// nothing more; it does not consult the pin, the [[trust]] table or a SAS.
func (m *Model) handleHolding(r *room, fpr string) string {
	if fpr == "" {
		return ""
	}
	if fpr == m.fingerprint {
		return m.name
	}
	if r == nil {
		return ""
	}
	for _, id := range r.order {
		if mem := r.members[id]; mem.fpr == fpr {
			return mem.name
		}
	}
	return ""
}

// renderIdentityEntry draws a filed credential as four short lines at most:
//
//	14:35 📌 identity alice: filed a credential for Rosa Alvarez ◆
//	        rosa.alvarez@acme.example  ·  roles: incident-commander
//	        about @rosa  ·  SHA256:5ah7…
//	        issuer SHA256:eVkC…
//	        ◆ checked here at 2026-06-01T14:35:00Z against a pinned issuer key
//
// Each line carries one idea, and the last one is the only one that says anything
// about what THIS client did. Everything above it is a quotation of what an issuer
// wrote, which is why the claim never appears without the verdict under it.
//
// A replayed entry keeps the room's existing replay shape ("[REPLAY hh:mm] … [kind]"),
// because a second convention for the same thing is how a reader learns that the
// pane has two vocabularies.
func (m *Model) renderIdentityEntry(l line) string {
	ri := l.identity
	d := ri.display
	ts := l.at.UTC().Format("15:04")

	var head string
	switch {
	case ri.malformed:
		head = ": filed an entry tagged as a credential that does not parse"
	case ri.selfFiled && verifiedHere(d):
		// The name is worth appending only when an ISSUER supplied it. Otherwise it
		// is the author's own handle, which the line already carries, or the key,
		// which the "about" line below carries in full.
		head = ": filed their own credential — " + d.Name
	case ri.selfFiled:
		head = ": filed their own credential"
	default:
		head = ": filed a credential for " + d.Name
	}

	var first string
	if ri.replayed {
		first = m.st(m.theme.Muted).Render("[REPLAY "+ts+"] "+l.from+head) + m.credentialMark(d) +
			m.st(m.theme.Muted).Render("  [identity]")
	} else {
		first = m.st(m.theme.Muted).Render(ts+" ") +
			m.st(m.theme.Accent).Bold(true).Render("📌 identity") + " " +
			m.st(m.theme.Accent2).Bold(true).Render(l.from) +
			m.st(m.theme.Text).Render(head) + m.credentialMark(d)
	}
	return first + "\n" + m.identityDetailLines(l)
}

// verifiedHere reports whether D-I placed this attribution in one of its two
// verified rows. The two are peers (identity_display.go), so nothing here may
// treat verified_unnamed as a degraded verified_named.
func verifiedHere(d attest.IdentityDisplay) bool {
	return d.State == attest.IdentityDisplayVerifiedNamed || d.State == attest.IdentityDisplayVerifiedUnnamed
}

// credentialMark is the styled D-I glyph for a filed credential, with its leading
// space. It is IdentityDisplayMark's answer in the panel's colours, so a reader
// meets the same glyph in the same colour in the pane and in the room.
//
// The ✓ family is deliberately absent. ✓ and ✓✓ say what this client established
// about a PEER's key out of band; this line is about a credential, and a room
// entry that borrowed a SAS mark would be answering a question nobody asked of it.
func (m *Model) credentialMark(d attest.IdentityDisplay) string {
	switch attest.IdentityDisplayMark(d.State) {
	case "◆":
		return m.st(m.theme.Success).Bold(true).Render(" ◆")
	case "◇":
		if d.Reason == attest.ReasonSubjectMismatch {
			return m.st(m.theme.Warn).Render(" ◇✗")
		}
		return m.st(m.theme.Muted).Render(" ◇")
	}
	return ""
}

// identityIndent is the left margin of everything under the first line, and
// identityWrap is the deeper one a sentence continues on, so a wrapped verdict
// cannot be read as a second item.
const (
	identityIndent = "        "
	identityWrap   = "          "
)

// identityDetailLines renders everything under the first line: what the issuer
// wrote, whose key it is about, and what this client did about it.
func (m *Model) identityDetailLines(l line) string {
	ri := l.identity
	d := ri.display
	var lines []string

	if ri.malformed {
		lines = append(lines, fmt.Sprintf("%d byte(s) under the %s tag", len(l.text), attest.IdentitySchema))
	} else {
		claim := d.Principal
		if claim == "" {
			claim = "(the artifact named no principal)"
		}
		// The signed display name is shown in parentheses only when it is NOT
		// already the name on the first line. Repeating it would suggest the two
		// strings came from different places.
		if d.DisplayName != "" && d.DisplayName != d.Name {
			claim += "  (" + d.DisplayName + ")"
		}
		if len(d.Roles) > 0 {
			claim += "  ·  roles: " + strings.Join(d.Roles, ", ")
		}
		lines = append(lines, claim)

		switch {
		case ri.selfFiled:
			// The first line already said whose it is; what is left is the key,
			// because a name is not a key and this is the only place the key appears.
			lines = append(lines, "about their own key  ·  "+ri.subject)
		case ri.handle != "":
			lines = append(lines, "about @"+ri.handle+"  ·  "+ri.subject)
		default:
			// Nobody in this room holds that key, which a reader has to be told
			// rather than left to infer from a fingerprint they cannot place.
			lines = append(lines, "about "+ri.subject+"  ·  nobody in this room holds that key")
		}
		if d.Issuer != "" {
			lines = append(lines, "issuer "+d.Issuer)
		}
	}

	lines = append(lines, m.identityVerdict(ri))
	return m.st(m.theme.Muted).Render(identityIndent + strings.Join(lines, "\n"+identityIndent))
}

// identityVerdict is the one line that speaks for this client rather than for the
// issuer. Everything that is not a verified row routes through carriedWords — the
// same sentences /verify and /roster print — so a reader who learned the
// vocabulary on one surface reads it on this one, and a future outcome code
// cannot acquire a fifth phrasing here.
func (m *Model) identityVerdict(ri *recordIdentity) string {
	d := ri.display
	switch {
	case ri.replayed:
		// Deliberately not evaluated. The credential belongs to a record that
		// carries two signed timestamps to bracket an evaluation against; this
		// room's wall clock is not those.
		return "◇ replayed from a sealed record and not checked here — a record is checked at\n" +
			identityIndent + identityWrap + "its own signed times:  netherchat verify <record.json> --issuer <key>"
	case verifiedHere(d):
		return fmt.Sprintf("◆ checked here at %s against a pinned issuer key, for a\n"+
			identityIndent+identityWrap+"window that contained it.  /issuer names the key.",
			ri.checkedAt.UTC().Format(time.RFC3339))
	}
	words := carriedWords(d, m.pinned())
	if ri.checkedAt.IsZero() {
		return words
	}
	// A check was attempted and did not reach ◆. The instant matters here for the
	// same reason it does above: this line will not be decided again.
	return words + "\n" + identityIndent + identityWrap +
		"(checked at " + ri.checkedAt.UTC().Format(time.RFC3339) + ")"
}
