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
