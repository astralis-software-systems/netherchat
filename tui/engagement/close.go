package engagement

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/salehkreiner/netherchat/tui/record"
)

// CloseReport summarizes the sealed records gathered for an engagement.
type CloseReport struct {
	Engagement  string          `json:"engagement"`
	GeneratedAt string          `json:"generated_at"`
	Total       int             `json:"total"`
	Verified    int             `json:"verified"`
	Records     []RecordSummary `json:"records"`
}

// RecordSummary is one record's verification outcome.
type RecordSummary struct {
	File     string   `json:"file"`
	Room     string   `json:"room,omitempty"`
	SealedAt string   `json:"sealed_at,omitempty"`
	Entries  int      `json:"entries"`
	Signers  []string `json:"signers,omitempty"`
	Valid    bool     `json:"valid"`
	Reason   string   `json:"reason,omitempty"`
}

// Close reads every sealed record in <dir>/records/, re-verifies each OFFLINE,
// writes a consolidated Markdown close report, and returns its path plus the
// machine-readable summary. outPath defaults to <dir>/close-report.md.
func Close(dir, outPath string) (string, *CloseReport, error) {
	man := loadManifest(dir) // nil if absent; used only for report context

	files, err := filepath.Glob(filepath.Join(dir, "records", "*.json"))
	if err != nil {
		return "", nil, err
	}
	sort.Strings(files)

	rep := &CloseReport{
		Engagement:  engagementName(man, dir),
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Total:       len(files),
	}
	recs := make([]*record.SealedRecord, len(files))

	for i, path := range files {
		rs := RecordSummary{File: filepath.Base(path)}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			rs.Reason = rerr.Error()
			rep.Records = append(rep.Records, rs)
			continue
		}
		rec, perr := record.Parse(b)
		if perr != nil {
			rs.Reason = perr.Error()
			rep.Records = append(rep.Records, rs)
			continue
		}
		recs[i] = rec
		rs.Room = rec.Room
		rs.SealedAt = rec.SealedAt
		rs.Entries = len(rec.Entries)

		res, verr := record.Verify(rec)
		if verr != nil {
			rs.Reason = verr.Error()
		} else {
			rs.Valid = res.Valid
			rs.Reason = res.Reason
			rs.Signers = res.Signers
		}
		if rs.Valid {
			rep.Verified++
		}
		rep.Records = append(rep.Records, rs)
	}

	if outPath == "" {
		outPath = filepath.Join(dir, "close-report.md")
	}
	content := renderCloseMarkdown(rep, man, recs)
	if err := os.WriteFile(outPath, []byte(content), 0o644); err != nil {
		return "", nil, err
	}
	return outPath, rep, nil
}

func loadManifest(dir string) *Manifest {
	b, err := os.ReadFile(filepath.Join(dir, "engagement.json"))
	if err != nil {
		return nil
	}
	var m Manifest
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	m.Dir = dir
	return &m
}

func engagementName(m *Manifest, dir string) string {
	if m != nil && m.Name != "" {
		return m.Name
	}
	return filepath.Base(filepath.Clean(dir))
}

// renderCloseMarkdown builds the consolidated close report. It re-states the
// per-record verification outcome (recomputed above) and lists the decisions and
// actions that were sealed — never any ephemeral discussion, which was never
// recorded in the first place.
func renderCloseMarkdown(rep *CloseReport, man *Manifest, recs []*record.SealedRecord) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Engagement Close Report — %s\n\n", rep.Engagement)
	fmt.Fprintf(&b, "Generated: %s\n", rep.GeneratedAt)
	if man != nil {
		if man.Client != "" {
			fmt.Fprintf(&b, "Client: %s\n", man.Client)
		}
		fmt.Fprintf(&b, "Relay: `%s` @ `%s`\n", man.Relay.Image, man.Relay.Addr)
		if len(man.Consultants) > 0 {
			parts := make([]string, 0, len(man.Consultants))
			for _, c := range man.Consultants {
				parts = append(parts, c.Handle)
			}
			fmt.Fprintf(&b, "Consultants: %s\n", strings.Join(parts, ", "))
		}
	}

	fmt.Fprintf(&b, "\n## Sealed records: %d of %d verified offline\n\n", rep.Verified, rep.Total)
	if rep.Total == 0 {
		b.WriteString("No sealed records were found in `records/`. Drop each war room's\n")
		b.WriteString("`record.json` there and re-run `netherchat engagement close`.\n")
		return b.String()
	}

	b.WriteString("| # | File | Room | Sealed (UTC) | Entries | Signers | Status |\n")
	b.WriteString("|---|------|------|--------------|---------|---------|--------|\n")
	for i, rs := range rep.Records {
		status := "✅ VERIFIED"
		if !rs.Valid {
			status = "❌ NOT VERIFIED"
		}
		fmt.Fprintf(&b, "| %d | %s | %s | %s | %d | %d | %s |\n",
			i+1, rs.File, dash(rs.Room), dash(rs.SealedAt), rs.Entries, len(rs.Signers), status)
	}

	b.WriteString("\n## Record detail\n")
	for i, rs := range rep.Records {
		fmt.Fprintf(&b, "\n### %d. %s — `%s`\n\n", i+1, dash(rs.Room), rs.File)
		if !rs.Valid {
			fmt.Fprintf(&b, "**NOT VERIFIED:** %s\n", dash(rs.Reason))
			continue
		}
		writeRecordDetail(&b, recs[i], rs)
	}

	b.WriteString("\n---\n")
	b.WriteString("Every record above was re-verified **offline** (the same check as\n")
	b.WriteString("`netherchat verify`). This report contains only the decisions and actions that\n")
	b.WriteString("were explicitly sealed — never the ephemeral discussion.\n")
	return b.String()
}

func writeRecordDetail(b *strings.Builder, rec *record.SealedRecord, rs RecordSummary) {
	fmt.Fprintf(b, "Sealed %s · %d co-signer(s).\n\n", dash(rs.SealedAt), len(rs.Signers))

	var decisions, actions, notes []record.Entry
	for _, e := range rec.Entries {
		switch e.Kind {
		case record.KindDecision:
			decisions = append(decisions, e)
		case record.KindAction:
			actions = append(actions, e)
		case record.KindNote:
			notes = append(notes, e)
		}
	}
	if len(decisions) == 0 && len(actions) == 0 && len(notes) == 0 {
		b.WriteString("_No sealed decisions, actions, or notes._\n")
		return
	}
	if len(decisions) > 0 {
		b.WriteString("**Decisions**\n\n")
		for _, e := range decisions {
			fmt.Fprintf(b, "- %s — %s\n", e.AuthorName, e.Body)
		}
		b.WriteString("\n")
	}
	if len(actions) > 0 {
		b.WriteString("**Actions**\n\n")
		for _, e := range actions {
			fmt.Fprintf(b, "- [ ] %s: %s (by %s)\n", dash(e.Actionee), e.Body, e.AuthorName)
		}
		b.WriteString("\n")
	}
	if len(notes) > 0 {
		b.WriteString("**Notes**\n\n")
		for _, e := range notes {
			fmt.Fprintf(b, "- %s: %s\n", e.AuthorName, e.Body)
		}
		b.WriteString("\n")
	}
}

func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}
