package render

import (
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// streamPreviewLines is how many of the most-recent lines a collapsed live-log
// block shows (§2.2) — the tail, so the live update is always visible. Matches the
// 8-line fold threshold used for stack traces.
const streamPreviewLines = 8

// RenderStream renders a live-log stream as a collapsible panel (§2.2), styled like
// a code block: a labeled box with log-level-colored rows. Collapsed, it shows the
// most recent streamPreviewLines plus a "/expand <expandID>" affordance; expanded,
// the whole ring buffer. expandID is the "stream-N" token the user types.
func (r *Renderer) RenderStream(label string, lines []string, expanded bool, expandID string) string {
	inner := r.contentWidth()

	visible := lines
	hidden := 0
	if !expanded && len(lines) > streamPreviewLines {
		hidden = len(lines) - streamPreviewLines
		visible = lines[len(lines)-streamPreviewLines:]
	}

	rows := make([]string, 0, len(visible)+1)
	for _, ln := range visible {
		styled := r.styleLogLine(truncateToWidth(expandTabs(ln), inner))
		rows = append(rows, r.surfaceRow(styled, inner))
	}
	if len(rows) == 0 {
		waiting := lipgloss.NewStyle().Foreground(r.th.Muted).Italic(true).Background(r.surface).Render("(waiting for output…)")
		rows = append(rows, r.surfaceRow(waiting, inner))
	}
	if hidden > 0 {
		rows = append(rows, r.streamFoldRow(hidden, expandID, inner))
	}
	return r.box(label, rows, inner)
}

// streamFoldRow is foldRow with a string expand id ("stream-N").
func (r *Renderer) streamFoldRow(hidden int, expandID string, width int) string {
	msg := "▼ " + strconv.Itoa(hidden) + " more lines — /expand " + expandID
	styled := lipgloss.NewStyle().Foreground(r.th.Accent).Bold(true).Background(r.surface).Render(msg)
	return r.surfaceRow(styled, width)
}

// styleLogLine colors a log line by its severity level (ERROR/FATAL red, WARN
// amber, DEBUG/TRACE dim), painted on the panel surface so the block reads as one
// raised cell. Lightweight auto-detection — no lexer needed for line-oriented logs.
func (r *Renderer) styleLogLine(line string) string {
	st := lipgloss.NewStyle().Background(r.surface).Foreground(r.th.Text)
	switch logLevel(line) {
	case levelError:
		st = st.Foreground(r.th.Error)
	case levelWarn:
		st = st.Foreground(r.th.Warn)
	case levelDebug:
		st = st.Foreground(r.th.Muted)
	}
	return st.Render(line)
}

type level int

const (
	levelNone level = iota
	levelError
	levelWarn
	levelDebug
)

// logLevel sniffs a line's severity from common level tokens (upper-cased so it
// matches ERROR/Error/error). The first match wins, severest first.
func logLevel(line string) level {
	u := strings.ToUpper(line)
	switch {
	case strings.Contains(u, "ERROR") || strings.Contains(u, "FATAL") || strings.Contains(u, "PANIC") || strings.Contains(u, "CRIT"):
		return levelError
	case strings.Contains(u, "WARN"):
		return levelWarn
	case strings.Contains(u, "DEBUG") || strings.Contains(u, "TRACE"):
		return levelDebug
	default:
		return levelNone
	}
}
