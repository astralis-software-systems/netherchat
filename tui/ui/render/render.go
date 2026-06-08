// Package render turns a chat message body into themed, structured terminal
// output: fenced code blocks with chroma syntax highlighting, unified diffs with
// +/- coloring, auto-detected stack traces (Go panics, Python tracebacks, JVM
// frames), and inline `code` spans. Long code blocks and stack traces fold to a
// preview with an /expand affordance (§2.6).
//
// It is pure presentation: it imports only lipgloss, chroma, and the theme
// palette. It knows nothing of the network, crypto, server, or message
// transport — it is handed a string and a theme and returns a string.
package render

import (
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/salehkreiner/netherchat/tui/ui/theme"
)

// Renderer renders message bodies for one TUI session. It caches the (expensive)
// rendered output of structural blocks keyed by content + theme + width +
// fold-state, so re-renders — which happen on every frame, and across every
// message on a /theme switch — only repeat work that actually changed.
//
// A Renderer is not safe for concurrent use; Bubble Tea calls View on a single
// goroutine, which is where rendering happens.
type Renderer struct {
	th      theme.Theme
	width   int
	style   string         // chroma style name for th
	surface lipgloss.Color // code/stack panel background

	cache  map[string]cacheEntry
	hits   int
	misses int
}

type cacheEntry struct {
	out    string
	blocks int
}

// New builds a Renderer for the given theme and render width (the width of the
// message viewport, in cells).
func New(th theme.Theme, width int) *Renderer {
	r := &Renderer{cache: make(map[string]cacheEntry)}
	r.configure(th, width)
	return r
}

func (r *Renderer) configure(th theme.Theme, width int) {
	r.th = th
	r.width = width
	r.style = chromaStyleFor(th.Name)
	r.surface = surfaceColor(th)
}

// SetTheme switches the active theme and invalidates the render cache so every
// block re-highlights with the new palette on the next frame (R2 instant theme
// switch). It is a no-op if the theme is unchanged.
func (r *Renderer) SetTheme(th theme.Theme) {
	if th.Name == r.th.Name {
		return
	}
	r.configure(th, r.width)
	r.cache = make(map[string]cacheEntry)
}

// SetWidth updates the render width and invalidates the cache (box and wrap
// geometry depend on width). No-op if unchanged.
func (r *Renderer) SetWidth(width int) {
	if width == r.width {
		return
	}
	r.width = width
	r.cache = make(map[string]cacheEntry)
}

// Stats reports cache hits and misses. Exposed for tests and introspection; the
// renderer keeps no other instrumentation (this is a no-telemetry product).
func (r *Renderer) Stats() (hits, misses int) { return r.hits, r.misses }

// Inline styles `code` spans within a string with the theme's soft accent. It is
// the single source of inline-code styling, used both for plain messages and for
// the prose between blocks, so inline code looks identical across every theme
// and every message kind (§2.6 item 2).
func (r *Renderer) Inline(s string) string {
	if !strings.Contains(s, "`") {
		return s
	}
	code := lipgloss.NewStyle().Foreground(r.th.Accent2)
	parts := strings.Split(s, "`")
	var b strings.Builder
	for i, p := range parts {
		if i%2 == 1 {
			b.WriteString(code.Render(p))
		} else {
			b.WriteString(p)
		}
	}
	return b.String()
}

// RenderBody renders a message body. Collapsible blocks are numbered with
// sequential ids starting at baseID; cs decides which are expanded.
//
// Returns:
//   - out: the rendered body. When block is false it is inline prose the caller
//     places right after the message header (preserving the one-line look of an
//     ordinary message). When block is true it is fully formatted, width-aware
//     multi-line content the caller places on the lines below the header.
//   - blocks: how many collapsible blocks were numbered, so the caller can
//     advance its id counter for the next message.
//   - block: whether the body contained any structural block at all.
func (r *Renderer) RenderBody(body string, baseID int, cs *CollapseState) (out string, blocks int, block bool) {
	segs := parse(body)

	hasBlock := false
	nextID := baseID
	for i := range segs {
		if segs[i].kind != segProse {
			hasBlock = true
		}
		if segs[i].collapsible {
			segs[i].id = nextID
			nextID++
		}
	}
	blocks = nextID - baseID

	// Fast path: an ordinary message (no fences, diffs, traces, or JSON). This is
	// the overwhelmingly common case and the one the no-regression test pins —
	// it renders identically to the previous inline-only path, uncached because
	// it is already trivial.
	if !hasBlock {
		return r.Inline(body), 0, false
	}

	key := r.cacheKey(body, baseID, segs, cs)
	if e, ok := r.cache[key]; ok {
		r.hits++
		return e.out, e.blocks, true
	}
	r.misses++
	out = r.renderSegments(segs, cs)
	r.cache[key] = cacheEntry{out: out, blocks: blocks}
	return out, blocks, true
}

func (r *Renderer) renderSegments(segs []segment, cs *CollapseState) string {
	parts := make([]string, 0, len(segs))
	for _, s := range segs {
		switch s.kind {
		case segCode:
			parts = append(parts, r.renderCode(s, cs))
		case segDiff:
			parts = append(parts, r.renderDiff(s.lines))
		case segStack:
			parts = append(parts, r.renderStack(s, cs))
		default:
			parts = append(parts, r.renderProse(s.text))
		}
	}
	return strings.Join(parts, "\n")
}

// renderProse styles inline code and wraps to the render width, matching the
// wrapping the app applies to ordinary messages.
func (r *Renderer) renderProse(text string) string {
	return lipgloss.NewStyle().Width(r.width).Render(r.Inline(text))
}

// cacheKey encodes everything that affects a body's rendered output: theme,
// width, the starting id, the fold state of each block, and the content itself.
// Theme and width are also cleared from the cache on change, so including them
// here is belt-and-suspenders correctness.
func (r *Renderer) cacheKey(body string, baseID int, segs []segment, cs *CollapseState) string {
	var b strings.Builder
	b.WriteString(r.th.Name)
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(r.width))
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(baseID))
	b.WriteByte('|')
	for _, s := range segs {
		if !s.collapsible {
			continue
		}
		if cs.Expanded(s.id) {
			b.WriteByte('+')
		} else {
			b.WriteByte('-')
		}
	}
	b.WriteByte('\n')
	b.WriteString(body)
	return b.String()
}

// --- box drawing ------------------------------------------------------------

// contentWidth is the inner text width of a panel: the render width minus the
// two border columns and one column of padding on each side.
func (r *Renderer) contentWidth() int {
	w := r.width - 4
	if w < 8 {
		w = 8
	}
	return w
}

// box wraps content rows (each already padded to contentWidth on the surface
// background) in a rounded-corner panel whose top border carries a language
// label, e.g. ┌─ go ───────────┐.
func (r *Renderer) box(label string, rows []string, contentWidth int) string {
	boxW := contentWidth + 4
	border := lipgloss.NewStyle().Foreground(r.th.Muted)
	labelStyle := lipgloss.NewStyle().Foreground(r.th.Accent).Bold(true)
	pad := lipgloss.NewStyle().Background(r.surface)
	bar := border.Render("│")

	var top string
	switch {
	case label == "" || boxW < 8:
		top = border.Render("┌" + strings.Repeat("─", boxW-2) + "┐")
	default:
		maxLabel := boxW - 6 // ┌─ <label> <one dash> ┐
		if lipgloss.Width(label) > maxLabel {
			label = truncateToWidth(label, maxLabel)
		}
		dashes := boxW - 5 - lipgloss.Width(label)
		if dashes < 0 {
			dashes = 0
		}
		top = border.Render("┌─ ") + labelStyle.Render(label) + border.Render(" "+strings.Repeat("─", dashes)+"┐")
	}

	out := make([]string, 0, len(rows)+2)
	out = append(out, top)
	for _, row := range rows {
		out = append(out, bar+pad.Render(" ")+row+pad.Render(" ")+bar)
	}
	out = append(out, border.Render("└"+strings.Repeat("─", boxW-2)+"┘"))
	return strings.Join(out, "\n")
}

// surfaceRow pads already-styled content out to width with the surface
// background, so a panel row reads as one continuous raised cell.
func (r *Renderer) surfaceRow(content string, width int) string {
	gap := width - lipgloss.Width(content)
	if gap > 0 {
		content += lipgloss.NewStyle().Background(r.surface).Render(strings.Repeat(" ", gap))
	}
	return content
}

// foldRow renders the "▼ N more lines — /expand <id>" affordance shown at the
// bottom of a folded block.
func (r *Renderer) foldRow(hidden, id, width int) string {
	msg := "▼ " + strconv.Itoa(hidden) + " more lines — /expand " + strconv.Itoa(id)
	styled := lipgloss.NewStyle().Foreground(r.th.Accent).Bold(true).Background(r.surface).Render(msg)
	return r.surfaceRow(styled, width)
}

// --- text helpers -----------------------------------------------------------

// truncateToWidth shortens s (assumed plain, no ANSI) to at most w display
// columns, appending an ellipsis when it cuts. Used for raw source lines before
// styling, so we never have to truncate across ANSI escapes.
func truncateToWidth(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= w {
		return s
	}
	if w == 1 {
		return "…"
	}
	rs := []rune(s)
	// Trim by display width, leaving one column for the ellipsis.
	out := make([]rune, 0, len(rs))
	used := 0
	for _, ru := range rs {
		cw := lipgloss.Width(string(ru))
		if used+cw > w-1 {
			break
		}
		out = append(out, ru)
		used += cw
	}
	return string(out) + "…"
}

func expandTabs(s string) string { return strings.ReplaceAll(s, "\t", "    ") }
