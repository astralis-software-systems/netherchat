package render

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Collapse thresholds (§2.6). Code blocks are dense, so they may run longer
// before folding; stack traces fold sooner because the first frames carry the
// signal. When folded, both show the first 8 lines plus an /expand affordance.
const (
	codeCollapseThreshold  = 20 // fold code blocks longer than this
	stackCollapseThreshold = 8  // fold stack traces longer than this
	collapsedLines         = 8  // lines shown while folded
)

// segKind classifies a contiguous span of a message body.
type segKind int

const (
	segProse segKind = iota // free text (with inline `code` spans)
	segCode                 // fenced code block → chroma syntax highlight
	segDiff                 // unified diff → theme +/- coloring
	segStack                // panic / traceback / JVM stack → theme coloring
)

// segment is one classified span of a message body.
type segment struct {
	kind  segKind
	lang  string   // code: fence label (may be ""); stack: "go"|"python"|"java"
	text  string   // segProse: the raw text
	lines []string // segCode/segDiff/segStack: the raw content lines

	collapsible bool // long enough to fold (code/stack only)
	id          int  // /expand id, assigned by the renderer (0 = never folded)
}

// parse splits a message body into classified segments. Fenced ``` blocks are
// carved out first; the prose between fences is then sniffed for diffs, stack
// traces, and bare JSON. The common case — a one-line chat message with no
// fences — yields a single segProse, which the renderer fast-paths.
func parse(body string) []segment {
	lines := strings.Split(body, "\n")
	var segs []segment
	var prose []string

	flush := func() {
		if len(prose) == 0 {
			return
		}
		text := strings.Join(prose, "\n")
		prose = prose[:0]
		if strings.TrimSpace(text) == "" {
			return // a run of blank lines carries nothing to render
		}
		segs = append(segs, classifyProse(text))
	}

	for i := 0; i < len(lines); {
		if isFence(lines[i]) {
			flush()
			lang := fenceLang(lines[i])
			i++
			var code []string
			for i < len(lines) && !isFence(lines[i]) {
				code = append(code, lines[i])
				i++
			}
			if i < len(lines) { // consume the closing fence if present
				i++
			}
			segs = append(segs, classifyCode(lang, code))
			continue
		}
		prose = append(prose, lines[i])
		i++
	}
	flush()
	return segs
}

func isFence(line string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), "```")
}

// fenceLang extracts the info string of a fence opener, e.g. "```go" → "go",
// "``` json " → "json". Only the first word is kept, lowercased.
func fenceLang(line string) string {
	t := strings.TrimSpace(line)
	t = strings.TrimPrefix(t, "```")
	t = strings.TrimSpace(t)
	if i := strings.IndexAny(t, " \t"); i >= 0 {
		t = t[:i]
	}
	return strings.ToLower(t)
}

// classifyCode turns a fenced block into a segment. A block labeled diff/patch
// (or an unlabeled block whose content is clearly a diff) becomes segDiff so it
// gets theme +/- coloring instead of chroma; everything else is segCode.
func classifyCode(lang string, code []string) segment {
	switch lang {
	case "diff", "patch":
		return segment{kind: segDiff, lines: code}
	case "":
		if looksLikeDiff(code) {
			return segment{kind: segDiff, lines: code}
		}
	}
	return segment{
		kind:        segCode,
		lang:        lang,
		lines:       code,
		collapsible: len(code) > codeCollapseThreshold,
	}
}

// classifyProse sniffs a run of non-fenced text. Order matters: diffs and stack
// traces are checked before the JSON heuristic, which is checked before falling
// back to plain prose.
func classifyProse(text string) segment {
	lines := strings.Split(text, "\n")
	if looksLikeDiff(lines) {
		return segment{kind: segDiff, lines: lines}
	}
	if lang, ok := looksLikeStack(text, lines); ok {
		return segment{
			kind:        segStack,
			lang:        lang,
			lines:       lines,
			collapsible: len(lines) > stackCollapseThreshold,
		}
	}
	if looksLikeJSON(text) {
		return segment{
			kind:        segCode,
			lang:        "json",
			lines:       lines,
			collapsible: len(lines) > codeCollapseThreshold,
		}
	}
	return segment{kind: segProse, text: text}
}

var hunkHeaderRe = regexp.MustCompile(`^@@ -\d+(,\d+)? \+\d+(,\d+)? @@`)

// looksLikeDiff reports whether lines form a unified diff. The strong signal is
// an @@ hunk header; absent that, a matching pair of ---/+++ file headers with
// at least one changed line also qualifies. Requiring one of these avoids
// misreading ordinary "- bullet" prose as a diff.
func looksLikeDiff(lines []string) bool {
	var newHeader, oldHeader bool
	var changed int
	for _, ln := range lines {
		switch {
		case hunkHeaderRe.MatchString(ln):
			return true
		case strings.HasPrefix(ln, "+++ "):
			newHeader = true
		case strings.HasPrefix(ln, "--- "):
			oldHeader = true
		case strings.HasPrefix(ln, "+"), strings.HasPrefix(ln, "-"):
			changed++
		}
	}
	return newHeader && oldHeader && changed > 0
}

var (
	goroutineRe = regexp.MustCompile(`(?m)^\s*goroutine \d+ \[[^\]]+\]:`)
	javaFrameRe = regexp.MustCompile(`^\s*at [\w$.<>/]+\(`)
)

// looksLikeStack detects the three stack-trace shapes the spec calls out and
// returns which one ("go", "python", "java"). Each test is a strong, specific
// signal so normal prose is never misclassified.
func looksLikeStack(text string, lines []string) (lang string, ok bool) {
	if goroutineRe.MatchString(text) {
		return "go", true
	}
	if strings.Contains(text, "Traceback (most recent call last):") {
		return "python", true
	}
	frames := 0
	for _, ln := range lines {
		if javaFrameRe.MatchString(ln) {
			frames++
		}
	}
	if frames >= 2 {
		return "java", true
	}
	return "", false
}

// looksLikeJSON reports whether text is a JSON object or array worth rendering
// as a highlighted block. It is intentionally conservative — bracketed, valid,
// and either multi-line or non-trivially long — so a stray "{}" in chat stays
// prose.
func looksLikeJSON(text string) bool {
	t := strings.TrimSpace(text)
	if len(t) < 2 {
		return false
	}
	if (t[0] != '{' && t[0] != '[') || (t[len(t)-1] != '}' && t[len(t)-1] != ']') {
		return false
	}
	if !strings.Contains(t, "\n") && len(t) < 30 {
		return false
	}
	return json.Valid([]byte(t))
}
