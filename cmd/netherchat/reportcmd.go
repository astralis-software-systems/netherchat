package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/salehkreiner/netherchat/tui/record"
	"github.com/salehkreiner/netherchat/tui/report"
)

// reportCmd implements `netherchat report record.json` (§2.6): it turns a sealed
// record into a standalone, shareable incident timeline — self-contained HTML for
// leadership or GitHub-flavored Markdown for a wiki — that stays cryptographically
// verifiable. It always runs the full chain verification so the report shows the
// hash-chain status; --verify additionally REFUSES to render a tampered record
// (exit 1), so a circulated report is never silently based on a broken chain.
func reportCmd(args []string) {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	out := fs.String("out", "", "output path (default: record-<room>-<ts>.<ext>)")
	format := fs.String("format", "html", "output format: html | md")
	title := fs.String("title", "", "custom report title")
	executive := fs.Bool("executive", false, "executive summary only — decisions/actions/timeline, no fingerprints/hashes/notes")
	verifyFlag := fs.Bool("verify", false, "verify the record before rendering; exit 1 if invalid (never render a tampered record)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netherchat report <record.json> [--out file] [--format html|md] [--title \"...\"] [--executive] [--verify]")
		fs.PrintDefaults()
	}

	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fs.Usage()
		os.Exit(2)
	}
	path := args[0]
	_ = fs.Parse(args[1:])

	b, err := os.ReadFile(path)
	if err != nil {
		fatal(err)
	}
	rec, err := record.Parse(b)
	if err != nil {
		fatal(err)
	}
	res, err := record.Verify(rec)
	if err != nil {
		fatal(err)
	}
	// --verify is a gate: refuse to render a tampered record.
	if *verifyFlag && !res.Valid {
		fmt.Fprintf(os.Stderr, "netherchat: record is TAMPERED — %s\n", res.Reason)
		os.Exit(1)
	}

	opts := report.Options{Title: *title, Executive: *executive}
	var content, ext string
	switch strings.ToLower(*format) {
	case "md", "markdown":
		content, ext = report.RenderMarkdown(rec, res, opts), "md"
	case "html", "":
		content, ext = report.RenderHTML(rec, res, opts), "html"
	default:
		fatal(fmt.Errorf("unknown --format %q (use html or md)", *format))
	}

	outPath := *out
	if outPath == "" {
		outPath = fmt.Sprintf("record-%s-%d.%s", safeName(rec.Room), time.Now().Unix(), ext)
	}
	if err := os.WriteFile(outPath, []byte(content), 0o644); err != nil {
		fatal(err)
	}

	status := "VALID"
	if !res.Valid {
		status = "TAMPERED (" + res.Reason + ")"
	}
	fmt.Printf("wrote %s — %s, %d entr%s, chain %s\n", outPath, *format, len(rec.Entries), plural(len(rec.Entries), "y", "ies"), status)
}

// safeName sanitizes a room name for use in a default filename.
func safeName(s string) string {
	if s == "" {
		return "incident"
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, s)
}
