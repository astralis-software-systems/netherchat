package render

import (
	"strings"

	"github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/alecthomas/chroma/v2/styles"
	"github.com/charmbracelet/lipgloss"
)

// renderCode renders a fenced code block as a syntax-highlighted panel. The
// language is taken from the fence label or, absent one, sniffed from the
// content; the chroma style is chosen to complement the active theme. A block
// longer than its threshold folds to the first 8 lines plus an /expand row.
func (r *Renderer) renderCode(s segment, cs *CollapseState) string {
	code := s.lines
	shown := code
	folded := s.collapsible && !cs.Expanded(s.id)
	if folded {
		shown = code[:collapsedLines]
	}

	inner := r.contentWidth()
	lexer, label := r.resolveLexer(s.lang, strings.Join(code, "\n"))

	// Truncate raw source to the panel width before highlighting, so each source
	// line maps to exactly one panel row and we never slice across ANSI escapes.
	prepared := make([]string, len(shown))
	for i, ln := range shown {
		prepared[i] = truncateToWidth(expandTabs(ln), inner)
	}
	styled := r.highlight(lexer, prepared)

	rows := make([]string, 0, len(styled)+1)
	for _, line := range styled {
		rows = append(rows, r.surfaceRow(line, inner))
	}
	if folded {
		rows = append(rows, r.foldRow(len(code)-collapsedLines, s.id, inner))
	}
	return r.box(label, rows, inner)
}

// resolveLexer picks a chroma lexer and a display label. A non-empty fence label
// wins; otherwise the content is analysed and the detected lexer's name becomes
// the label (so unlabeled JSON shows "json"). Falls back to plaintext.
func (r *Renderer) resolveLexer(lang, code string) (chroma.Lexer, string) {
	label := lang
	var lx chroma.Lexer
	if lang != "" {
		lx = lexers.Get(lang)
	}
	if lx == nil {
		if a := lexers.Analyse(code); a != nil {
			lx = a
			if label == "" {
				label = strings.ToLower(a.Config().Name)
			}
		}
	}
	if lx == nil {
		lx = lexers.Fallback
		if label == "" {
			label = "text"
		}
	}
	return chroma.Coalesce(lx), label
}

// highlight tokenizes code and returns one styled string per input line. Every
// token is painted on the surface background (overriding the chroma style's own
// background) so the whole panel reads as one uniform raised cell, and the line
// count is forced to match the input so panel rows stay aligned.
func (r *Renderer) highlight(lexer chroma.Lexer, srcLines []string) []string {
	style := styles.Get(r.style)
	it, err := lexer.Tokenise(nil, strings.Join(srcLines, "\n"))
	if err != nil {
		return r.plainLines(srcLines)
	}

	out := make([]string, 0, len(srcLines))
	var cur strings.Builder
	for _, tok := range it.Tokens() {
		st := r.tokenStyle(style, tok.Type)
		segs := strings.Split(tok.Value, "\n")
		for i, part := range segs {
			if i > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
			if part != "" {
				cur.WriteString(st.Render(part))
			}
		}
	}
	out = append(out, cur.String())

	// Reconcile with the source line count: chroma may emit a trailing newline.
	for len(out) < len(srcLines) {
		out = append(out, "")
	}
	return out[:len(srcLines)]
}

// tokenStyle converts a chroma style entry to a Lip Gloss style, forcing the
// panel surface as the background.
func (r *Renderer) tokenStyle(style *chroma.Style, tt chroma.TokenType) lipgloss.Style {
	e := style.Get(tt)
	s := lipgloss.NewStyle().Background(r.surface)
	if e.Colour.IsSet() {
		s = s.Foreground(lipgloss.Color(e.Colour.String()))
	}
	if e.Bold == chroma.Yes {
		s = s.Bold(true)
	}
	if e.Italic == chroma.Yes {
		s = s.Italic(true)
	}
	if e.Underline == chroma.Yes {
		s = s.Underline(true)
	}
	return s
}

// plainLines is the fallback when a lexer fails to tokenize: the text on the
// surface background, in the theme's foreground.
func (r *Renderer) plainLines(srcLines []string) []string {
	st := lipgloss.NewStyle().Foreground(r.th.Text).Background(r.surface)
	out := make([]string, len(srcLines))
	for i, ln := range srcLines {
		out[i] = st.Render(ln)
	}
	return out
}
