package render

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// renderDiff colors a unified diff from the active theme: additions in the
// success color, deletions in the error color, hunk headers in the accent, file
// metadata and context dimmed. Diff lines are not boxed or truncated — engineers
// copy diffs out, so the exact bytes are preserved and the terminal soft-wraps
// anything wider than the view.
func (r *Renderer) renderDiff(lines []string) string {
	add := lipgloss.NewStyle().Foreground(r.th.Success)
	del := lipgloss.NewStyle().Foreground(r.th.Error)
	hunk := lipgloss.NewStyle().Foreground(r.th.Accent).Bold(true)
	meta := lipgloss.NewStyle().Foreground(r.th.Muted).Bold(true)
	ctx := lipgloss.NewStyle().Foreground(r.th.Muted)

	out := make([]string, len(lines))
	for i, ln := range lines {
		switch {
		case strings.HasPrefix(ln, "@@"):
			out[i] = hunk.Render(ln)
		case strings.HasPrefix(ln, "+++"), strings.HasPrefix(ln, "---"),
			strings.HasPrefix(ln, "diff "), strings.HasPrefix(ln, "index "):
			out[i] = meta.Render(ln)
		case strings.HasPrefix(ln, "+"):
			out[i] = add.Render(ln)
		case strings.HasPrefix(ln, "-"):
			out[i] = del.Render(ln)
		default:
			out[i] = ctx.Render(ln)
		}
	}
	return strings.Join(out, "\n")
}
