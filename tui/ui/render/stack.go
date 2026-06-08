package render

import (
	"regexp"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// renderStack renders an auto-detected stack trace (Go panic, Python traceback,
// or JVM frames) as a themed panel: function names in the accent, file paths
// dimmed, line numbers in a distinct color. Folds like a code block, but sooner
// — the top frames carry the signal.
func (r *Renderer) renderStack(s segment, cs *CollapseState) string {
	lines := s.lines
	shown := lines
	folded := s.collapsible && !cs.Expanded(s.id)
	if folded {
		shown = lines[:collapsedLines]
	}

	inner := r.contentWidth()
	rows := make([]string, 0, len(shown)+1)
	for _, ln := range shown {
		raw := truncateToWidth(expandTabs(ln), inner)
		rows = append(rows, r.surfaceRow(r.styleStackLine(raw), inner))
	}
	if folded {
		rows = append(rows, r.foldRow(len(lines)-collapsedLines, s.id, inner))
	}
	return r.box(stackLabel(s.lang), rows, inner)
}

func stackLabel(lang string) string {
	switch lang {
	case "go":
		return "go panic"
	case "python":
		return "traceback"
	case "java":
		return "stack trace"
	default:
		return "stack trace"
	}
}

var (
	// path/to/file.ext:123 — the file:line at the tail of a Go or JVM frame.
	pathLineRe = regexp.MustCompile(`^(.*?)([^\s():]+\.[A-Za-z0-9]+):(\d+)(.*)$`)
	// Python:   File "path", line N, in func
	pyFrameRe = regexp.MustCompile(`^(\s*File ")(.*?)(", line )(\d+)(.*)$`)
)

// styleStackLine colors a single (already width-truncated) stack line. Each
// span carries the surface background so the panel stays uniform.
func (r *Renderer) styleStackLine(ln string) string {
	fn := lipgloss.NewStyle().Foreground(r.th.Accent2).Bold(true).Background(r.surface)
	head := lipgloss.NewStyle().Foreground(r.th.Accent).Bold(true).Background(r.surface)
	path := lipgloss.NewStyle().Foreground(r.th.Muted).Background(r.surface)
	num := lipgloss.NewStyle().Foreground(r.th.Warn).Background(r.surface)
	errc := lipgloss.NewStyle().Foreground(r.th.Error).Bold(true).Background(r.surface)
	text := lipgloss.NewStyle().Foreground(r.th.Text).Background(r.surface)

	trimmed := strings.TrimSpace(ln)
	switch {
	case strings.HasPrefix(trimmed, "goroutine ") || strings.Contains(trimmed, "[running]"),
		strings.HasPrefix(trimmed, "Traceback (most recent call last):"):
		return head.Render(ln)
	case strings.HasPrefix(trimmed, "panic:"), isExceptionHeader(trimmed):
		return errc.Render(ln)
	}

	// Python frame: File "path", line N, in func
	if m := pyFrameRe.FindStringSubmatch(ln); m != nil {
		return text.Render(m[1]) + path.Render(m[2]) + text.Render(m[3]) +
			num.Render(m[4]) + fn.Render(m[5])
	}
	// Go / JVM frame ending in file.ext:line
	if m := pathLineRe.FindStringSubmatch(ln); m != nil {
		prefix := m[1]
		ps := text
		if strings.ContainsAny(prefix, ".(") { // a qualified function name
			ps = fn
		}
		return ps.Render(prefix) + path.Render(m[2]) + path.Render(":") +
			num.Render(m[3]) + text.Render(m[4])
	}
	// A bare function frame, e.g. "main.main()" or "at com.example.Foo.bar(...)".
	if strings.Contains(trimmed, "(") {
		return fn.Render(ln)
	}
	return path.Render(ln)
}

var exceptionRe = regexp.MustCompile(`^[\w.$]+(Exception|Error|Throwable)\b`)

// isExceptionHeader reports whether a line is a JVM/Python exception header line
// such as "java.lang.NullPointerException: ...".
func isExceptionHeader(line string) bool {
	return exceptionRe.MatchString(line)
}
