// Package report turns a sealed record (§1.4) into a standalone, shareable incident
// timeline (§2.6): one self-contained HTML file that a director can read and an
// engineer can cryptographically verify, or GitHub-flavored Markdown for a wiki.
//
// HTML output embeds everything — inline CSS in the Netherchat palette, no
// @font-face, no CDN, no external fetches — plus an inline SVG QR code (no external
// library at runtime) encoding the `netherchat verify` command. It never renders a
// tampered record without saying so: the caller verifies first and the hash-chain
// status is shown prominently.
package report

import (
	"html"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/record"
)

// Options control the rendering.
type Options struct {
	Title     string // report title; defaults to "Incident timeline — #<room>"
	Executive bool   // executive-only output: decisions/actions/timeline, no fingerprints/hashes/notes

	// Roster, when set, renders the signed roster attestation (§1.4) alongside the
	// record: who held the room key at the attested epoch. Optional; nil omits the
	// section. Executive mode shows member names and sign-off status but no
	// fingerprints.
	Roster *attest.RosterAttestation
}

// signOff is one seal co-signer's declared sign-off (item 2): who signed, with
// what meaning, and when. Meaning/Name/SignedAt come from the signed Endorsement
// when present; a bare (v1) co-signature falls back to a generic "signed" and the
// author display name.
type signOff struct {
	Fpr      string
	Name     string // may be "" when unknown (renderers substitute a non-identifying label)
	Meaning  string
	SignedAt string
}

// signOffs returns the seal co-signers in stable fingerprint order, each with the
// declared meaning/name/time when present.
func signOffs(rec *record.SealedRecord) []signOff {
	names := signerNames(rec)
	fprs := make([]string, 0, len(rec.Signatures))
	for fpr := range rec.Signatures {
		fprs = append(fprs, fpr)
	}
	sort.Strings(fprs)
	out := make([]signOff, 0, len(fprs))
	for _, fpr := range fprs {
		so := signOff{Fpr: fpr, Meaning: "signed", Name: names[fpr]}
		if end, ok := rec.Endorsements[fpr]; ok {
			so.Meaning = end.Meaning
			so.SignedAt = end.SignedAt
			if end.Name != "" {
				so.Name = end.Name
			}
		}
		out = append(out, so)
	}
	return out
}

// signerNames maps a fingerprint to a display name drawn from the entry authors
// (names are cosmetic; the fingerprint is the authenticated identity).
func signerNames(rec *record.SealedRecord) map[string]string {
	m := map[string]string{}
	for _, e := range rec.Entries {
		if _, ok := m[e.AuthorID]; !ok && e.AuthorName != "" {
			m[e.AuthorID] = e.AuthorName
		}
	}
	return m
}

// approverDisplay renders an artifact entry's approval attribution from ONLY the
// cryptographically verified approver set (VerifyResult.ArtifactApprovers) — never
// the body's approver_fpr — so a renderer never presents an unverified approver as
// authoritative (GAP-1). withFpr appends the short fingerprint (full report only).
// ok is false when there are no verified approvers (a legacy or unproven record),
// so the caller renders a not-verified caveat instead of a name.
func approverDisplay(rec *record.SealedRecord, res *record.VerifyResult, e record.Entry, withFpr bool) (string, bool) {
	m, ok := record.ArtifactOf(e)
	if !ok || m.ProposalID == "" {
		return "", false
	}
	names := signerNames(rec)
	// Prefer the role-attributed surface (artifact-approval/v2) when present, so the
	// report reads "Dr. Alice — qa" rather than a bare "verified reviewer". Falls back to
	// the role-agnostic verified set for proposals that carry only v1 (roleless) proofs.
	if roleApprovers := record.VerifiedArtifactApproverRoles(res, m.ProposalID); len(roleApprovers) > 0 {
		parts := make([]string, 0, len(roleApprovers))
		for _, ra := range roleApprovers {
			who := names[ra.Fingerprint]
			if who == "" {
				who = "verified reviewer"
			}
			label := who + " — " + ra.Role
			if withFpr {
				label += " (" + shortHash(ra.Fingerprint, 16) + ")"
			}
			parts = append(parts, label)
		}
		return strings.Join(parts, ", "), true
	}
	fprs := record.VerifiedArtifactApprovers(res, m.ProposalID)
	if len(fprs) == 0 {
		return "", false
	}
	parts := make([]string, 0, len(fprs))
	for _, fpr := range fprs {
		who := names[fpr]
		if who == "" {
			who = "verified reviewer"
		}
		if withFpr {
			who += " (" + shortHash(fpr, 16) + ")"
		}
		parts = append(parts, who)
	}
	return strings.Join(parts, ", "), true
}

// Netherchat brand palette (CLAUDE.md → Brand & Design Constraints).
const (
	colBg     = "#0a0a12"
	colPanel  = "#14141f"
	colAccent = "#7c3aed"
	colSoft   = "#a78bfa"
	colText   = "#e2e0f0"
	colMuted  = "#7c6fa0"
	colOK     = "#4ade80"
	colBad    = "#f87171"
)

var entryRe = regexp.MustCompile(`entry (\d+)`)

// title returns the configured or default report title.
func (o Options) title(room string) string {
	if strings.TrimSpace(o.Title) != "" {
		return o.Title
	}
	return "Incident timeline — #" + room
}

// chainStatus renders the hash-chain verdict as (symbol, text, colour): ✓ intact,
// or ✗ broken at entry N (extracted from the verifier's reason).
func chainStatus(res *record.VerifyResult) (sym, text, col string) {
	if res.Valid {
		return "✓", "intact", colOK
	}
	if m := entryRe.FindStringSubmatch(res.Reason); m != nil {
		return "✗", "broken at entry " + m[1] + " — " + res.Reason, colBad
	}
	return "✗", "broken — " + res.Reason, colBad
}

// resolution returns the elapsed time from the first entry to the seal, or "" when
// it cannot be computed.
func resolution(rec *record.SealedRecord) string {
	if len(rec.Entries) == 0 {
		return ""
	}
	sealedAt, err := time.Parse(time.RFC3339, rec.SealedAt)
	if err != nil {
		return ""
	}
	first := time.Unix(rec.Entries[0].TS, 0)
	d := sealedAt.Sub(first)
	if d < 0 {
		return ""
	}
	return d.Round(time.Second).String()
}

// whatHappened is the headline for the executive summary: the first decision, else
// a generic line from the room name.
func whatHappened(rec *record.SealedRecord) string {
	for _, e := range rec.Entries {
		if e.Kind == record.KindDecision {
			return e.Body
		}
	}
	return "Incident in #" + rec.Room
}

func decisions(rec *record.SealedRecord) []record.Entry {
	return entriesOfKind(rec, record.KindDecision)
}
func actions(rec *record.SealedRecord) []record.Entry { return entriesOfKind(rec, record.KindAction) }
func artifacts(rec *record.SealedRecord) []record.Entry {
	return entriesOfKind(rec, record.KindArtifact)
}

func entriesOfKind(rec *record.SealedRecord, kind string) []record.Entry {
	var out []record.Entry
	for _, e := range rec.Entries {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

// kindIcon returns the emoji for an entry kind in the timeline.
func kindIcon(kind string) string {
	switch kind {
	case record.KindDecision:
		return "📋"
	case record.KindAction:
		return "⚡"
	case record.KindArtifact:
		return "📋"
	default:
		return "💬"
	}
}

// shortHash returns the first n characters of a hex hash/fingerprint with an
// ellipsis, for the report's reference display.
func shortHash(h string, n int) string {
	if len(h) <= n {
		return h
	}
	return h[:n] + "..."
}

func entryTime(e record.Entry) string { return time.Unix(e.TS, 0).Format("2006-01-02 15:04:05") }

func esc(s string) string { return html.EscapeString(s) }

// identityTimelineLine renders one identity attestation entry for a timeline, or
// ok=false for any entry that does not carry one.
//
// It is the report's whole identity branch, shared by all three timelines (full
// HTML, executive HTML, Markdown) so the three cannot drift — the drift is what
// Phase 2 §F3 found, with each of them falling through to e.Body independently.
//
// The decision is not made here. record.IdentityDisplayForEntry performs the
// record's join and hands the result to attest.IdentityDisplayFor, which is D-I,
// which is the same function the participants panel, /whois, /whoami, the browser
// roster and the room view call. This function chooses word order and nothing else.
//
// WHAT res DECIDES. `netherchat report` calls record.Verify, which surfaces no
// bindings, so every credential in a report produced by the CLI is a carried claim
// and renders as one. A caller that ran VerifyWithIdentity with a pinned issuer
// gets the verified row, because the result it handed in says so. Neither branch
// verifies anything here; a renderer that could verify would be a renderer holding
// a trust anchor.
//
// executive drops the fingerprints, following the same rule the rest of the
// executive report follows — and the qualifier stays, because a principal printed
// in a leadership summary with nothing beside it is the one place a reader is most
// likely to supply the missing word themselves and supply the wrong one.
func identityTimelineLine(res *record.VerifyResult, e record.Entry, executive bool) (string, bool) {
	d, ok := record.IdentityDisplayForEntry(res, e, "")
	if !ok {
		return "", false
	}
	mark := attest.IdentityDisplayMark(d.State)
	verified := d.State == attest.IdentityDisplayVerifiedNamed || d.State == attest.IdentityDisplayVerifiedUnnamed

	if d.Principal == "" {
		return mark + " identity attestation — the entry body is not an identity artifact", true
	}
	claim := d.Principal
	if d.DisplayName != "" {
		claim = d.DisplayName + " (" + d.Principal + ")"
	}

	var b strings.Builder
	b.WriteString(mark + " identity attestation — " + claim)
	if len(d.Roles) > 0 {
		b.WriteString(", roles " + strings.Join(d.Roles, ", "))
	}
	if !executive {
		// The key the statement is ABOUT. A name without it is a name attached to
		// whoever the reader assumes, which on this surface is the entry's author.
		b.WriteString(", about " + d.Name)
		if d.Issuer != "" {
			b.WriteString(", issuer " + shortHash(d.Issuer, 24))
		}
		b.WriteString(", filed by " + e.AuthorName)
	}
	if verified {
		b.WriteString(" — checked against an issuer key this report's caller supplied")
	} else {
		b.WriteString(" — carried by this record, not checked here")
		if d.Reason != "" && d.Reason != attest.ReasonNoIssuerPinned {
			b.WriteString(" (" + string(d.Reason) + ")")
		}
	}
	return b.String(), true
}
