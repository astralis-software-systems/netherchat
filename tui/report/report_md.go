package report

import (
	"fmt"
	"strings"

	"github.com/salehkreiner/netherchat/tui/record"
)

// RenderMarkdown renders a sealed record as GitHub-flavored Markdown (§2.6): the
// same sections as the HTML report (minus the QR, which Markdown cannot embed
// interactively), suitable for pasting into a post-mortem wiki.
func RenderMarkdown(rec *record.SealedRecord, res *record.VerifyResult, opts Options) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", opts.title(rec.Room))
	fmt.Fprintf(&b, "- **Room:** #%s\n- **Sealed:** %s\n- **Participants:** %d\n", rec.Room, rec.SealedAt, len(rec.Signatures))
	if !opts.Executive {
		fmt.Fprintf(&b, "- **Entries:** %d\n", len(rec.Entries))
		sym, text, _ := chainStatus(res)
		fmt.Fprintf(&b, "- **Hash chain:** %s %s\n", sym, text)
	}
	b.WriteString("\n")

	b.WriteString(executiveMarkdown(rec))

	if opts.Executive {
		b.WriteString(footerMarkdown(rec, true))
		return b.String()
	}

	b.WriteString("## Timeline\n\n")
	for _, e := range rec.Entries {
		body := e.Body
		if e.Kind == record.KindAction && e.Actionee != "" {
			body = "@" + e.Actionee + ": " + body
		}
		status := "✗ unverified"
		if res.Valid {
			status = "✓ signed"
		}
		fmt.Fprintf(&b, "- %s `%s` **%s** — %s _(%s)_\n", kindIcon(e.Kind), entryTime(e), e.AuthorName, body, status)
	}

	b.WriteString("\n## Seal signatures\n\n| fingerprint | status |\n|---|---|\n")
	if len(res.Signers) > 0 {
		for _, fpr := range res.Signers {
			fmt.Fprintf(&b, "| `%s` | ✓ verified |\n", fpr)
		}
	} else {
		for fpr := range rec.Signatures {
			fmt.Fprintf(&b, "| `%s` | ✗ not verified |\n", fpr)
		}
	}
	b.WriteString("\n")
	b.WriteString(footerMarkdown(rec, false))
	return b.String()
}

// executiveMarkdown renders the leadership summary — what happened, decisions,
// actions, resolution time — with no fingerprints, hashes, or notes (§2.6).
func executiveMarkdown(rec *record.SealedRecord) string {
	var b strings.Builder
	b.WriteString("## Executive summary\n\n")
	fmt.Fprintf(&b, "**What happened:** %s\n\n", whatHappened(rec))

	if ds := decisions(rec); len(ds) > 0 {
		b.WriteString("**Decisions**\n\n")
		for _, e := range ds {
			fmt.Fprintf(&b, "- %s\n", e.Body)
		}
		b.WriteString("\n")
	}
	if as := actions(rec); len(as) > 0 {
		b.WriteString("**Actions**\n\n")
		for _, e := range as {
			owner := ""
			if e.Actionee != "" {
				owner = "@" + e.Actionee + ": "
			}
			fmt.Fprintf(&b, "- %s%s\n", owner, e.Body)
		}
		b.WriteString("\n")
	}
	if r := resolution(rec); r != "" {
		fmt.Fprintf(&b, "**Resolution time:** %s (first entry → seal)\n\n", r)
	}
	return b.String()
}

func footerMarkdown(rec *record.SealedRecord, executive bool) string {
	var b strings.Builder
	b.WriteString("---\n\n")
	fmt.Fprintf(&b, "Verify with: `%s`\n", verifyCmd)
	if !executive {
		fmt.Fprintf(&b, "\nhead_hash: `%s`\n", rec.HeadHash)
	}
	return b.String()
}
