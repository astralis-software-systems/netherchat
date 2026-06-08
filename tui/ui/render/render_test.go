package render

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"github.com/salehkreiner/netherchat/tui/ui/theme"
)

// TestMain forces a truecolor profile so lipgloss emits real ANSI in the test
// binary (it otherwise downgrades to plain text when stdout is not a terminal,
// which would make the highlighting assertions meaningless).
func TestMain(m *testing.M) {
	lipgloss.SetColorProfile(termenv.TrueColor)
	os.Exit(m.Run())
}

func th(name string) theme.Theme {
	t, ok := theme.Get(name)
	if !ok {
		panic("unknown theme " + name)
	}
	return t
}

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func stripANSI(s string) string { return ansiRe.ReplaceAllString(s, "") }

func fencedGo(n int) string {
	var b strings.Builder
	b.WriteString("```go\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "v%d := %d\n", i, i)
	}
	b.WriteString("```")
	return b.String()
}

// TestFencedGoBlockHighlighted: a fenced Go block renders as a bordered,
// syntax-highlighted panel with a language label — not plain text. (Demo target.)
func TestFencedGoBlockHighlighted(t *testing.T) {
	r := New(th("nether"), 60)
	body := "```go\npackage main\n\nfunc main() {}\n```"
	out, blocks, isBlock := r.RenderBody(body, 1, NewCollapseState())

	if !isBlock {
		t.Fatal("fenced block should report as a structural block")
	}
	if blocks != 0 {
		t.Fatalf("a 3-line block is not collapsible, got %d blocks", blocks)
	}
	if !strings.Contains(out, "┌") || !strings.Contains(out, "└") {
		t.Errorf("expected a bordered box:\n%s", out)
	}
	if !strings.Contains(stripANSI(out), "go") {
		t.Error("expected the language label in the header")
	}
	if !strings.Contains(out, "\x1b[") {
		t.Error("expected ANSI syntax highlighting, got plain text")
	}
	if !strings.Contains(stripANSI(out), "package main") {
		t.Errorf("expected the code content to survive rendering:\n%s", stripANSI(out))
	}
}

// TestLongCodeBlockCollapses: a code block over 20 lines folds to 8 lines plus
// an /expand affordance, and /expand unfolds it.
func TestLongCodeBlockCollapses(t *testing.T) {
	r := New(th("nether"), 80)
	body := fencedGo(30)
	cs := NewCollapseState()

	out, blocks, _ := r.RenderBody(body, 1, cs)
	if blocks != 1 {
		t.Fatalf("expected 1 collapsible block, got %d", blocks)
	}
	if !strings.Contains(out, "22 more lines") || !strings.Contains(out, "/expand 1") {
		t.Errorf("expected the fold indicator (22 more, /expand 1):\n%s", stripANSI(out))
	}
	if strings.Contains(stripANSI(out), "v20") {
		t.Error("a folded block must not show line v20 (beyond the 8-line preview)")
	}

	cs.Expand(1)
	out2, _, _ := r.RenderBody(body, 1, cs)
	if strings.Contains(out2, "more lines") {
		t.Error("an expanded block should carry no fold indicator")
	}
	if !strings.Contains(stripANSI(out2), "v29") {
		t.Error("an expanded block should show every line (v29 missing)")
	}
}

// TestExpandAll: /expand all unfolds every collapsed block at once.
func TestExpandAll(t *testing.T) {
	r := New(th("nether"), 80)
	body := fencedGo(30)
	cs := NewCollapseState()
	cs.ExpandAll()
	out, _, _ := r.RenderBody(body, 1, cs)
	if strings.Contains(out, "more lines") {
		t.Errorf("/expand all should unfold the block:\n%s", stripANSI(out))
	}
}

// TestDiffColoring: additions and deletions render with distinct theme colors.
func TestDiffColoring(t *testing.T) {
	theme := th("nether")
	r := New(theme, 80)
	body := "```diff\n@@ -1,2 +1,2 @@\n-old line\n+new line\n context\n```"
	out, _, isBlock := r.RenderBody(body, 1, NewCollapseState())

	if !isBlock {
		t.Fatal("a diff should be a structural block")
	}
	add := lipgloss.NewStyle().Foreground(theme.Success).Render("+new line")
	del := lipgloss.NewStyle().Foreground(theme.Error).Render("-old line")
	if add == del {
		t.Fatal("test setup: add and del styling are identical")
	}
	if !strings.Contains(out, add) {
		t.Errorf("addition not colored with the success color:\n%q", out)
	}
	if !strings.Contains(out, del) {
		t.Errorf("deletion not colored with the error color:\n%q", out)
	}
}

// TestBareDiffDetected: a unified diff with no fence is still detected.
func TestBareDiffDetected(t *testing.T) {
	r := New(th("nether"), 80)
	body := "--- a/main.go\n+++ b/main.go\n@@ -1 +1 @@\n-foo\n+bar"
	_, _, isBlock := r.RenderBody(body, 1, NewCollapseState())
	if !isBlock {
		t.Error("an unfenced unified diff should be detected and rendered as a block")
	}
}

// TestGoStackTraceDetected: a Go panic (unfenced) is auto-detected and boxed.
func TestGoStackTraceDetected(t *testing.T) {
	r := New(th("nether"), 80)
	body := "goroutine 1 [running]:\nmain.main()\n\t/home/alice/netherchat/main.go:42 +0x1a4\nexit status 2"
	out, _, isBlock := r.RenderBody(body, 1, NewCollapseState())
	if !isBlock {
		t.Fatal("a Go panic should be detected as a block")
	}
	if !strings.Contains(out, "┌") {
		t.Error("a stack trace should render in a panel")
	}
	if !strings.Contains(stripANSI(out), "go panic") {
		t.Errorf("expected a 'go panic' label:\n%s", stripANSI(out))
	}
}

// TestStackDetectionShapes covers the predicate for all three trace flavors.
func TestStackDetectionShapes(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{"go", "goroutine 17 [running]:\nmain.boom()", "go"},
		{"python", "Traceback (most recent call last):\n  File \"a.py\", line 1, in <module>", "python"},
		{"java", "java.lang.NullPointerException\n\tat com.example.A.b(A.java:10)\n\tat com.example.A.c(A.java:20)", "java"},
		{"prose", "let's meet at noon to look at the logs", ""},
	}
	for _, c := range cases {
		got, ok := looksLikeStack(c.text, strings.Split(c.text, "\n"))
		if (c.want == "") == ok || got != c.want {
			t.Errorf("%s: looksLikeStack = (%q,%v), want %q", c.name, got, ok, c.want)
		}
	}
}

// TestThemeSwitchChangesColors: switching theme invalidates the cache (a forced
// re-render = a miss) and yields different colors (dracula vs nether).
func TestThemeSwitchChangesColors(t *testing.T) {
	r := New(th("nether"), 80)
	body := "```go\nfunc main() { println(\"hi\") }\n```"

	out1, _, _ := r.RenderBody(body, 1, NewCollapseState())
	_, m1 := r.Stats()

	r.SetTheme(th("dracula"))
	out2, _, _ := r.RenderBody(body, 1, NewCollapseState())
	_, m2 := r.Stats()

	if out1 == out2 {
		t.Error("a theme switch must change code colors")
	}
	if m2 != m1+1 {
		t.Errorf("theme switch should invalidate the cache (force a miss): misses %d→%d", m1, m2)
	}
}

// TestInlineCodeAccent: inline `code` spans get the soft-accent color.
func TestInlineCodeAccent(t *testing.T) {
	theme := th("nether")
	r := New(theme, 80)
	out, _, isBlock := r.RenderBody("restart with `systemctl restart nc`", 1, NewCollapseState())
	if isBlock {
		t.Fatal("inline code is not a structural block")
	}
	want := lipgloss.NewStyle().Foreground(theme.Accent2).Render("systemctl restart nc")
	if !strings.Contains(out, want) {
		t.Errorf("inline code not styled in the accent color:\n%q", out)
	}
}

// TestJSONAutoDetected: JSON content with no fence label is detected, labeled,
// and highlighted.
func TestJSONAutoDetected(t *testing.T) {
	r := New(th("nether"), 80)
	body := "{\n  \"name\": \"netherchat\",\n  \"port\": 3000\n}"
	out, _, isBlock := r.RenderBody(body, 1, NewCollapseState())
	if !isBlock {
		t.Fatal("bare JSON should render as a block")
	}
	if !strings.Contains(stripANSI(out), "json") {
		t.Errorf("expected a json label:\n%s", stripANSI(out))
	}
	if !strings.Contains(out, "\x1b[") {
		t.Error("expected JSON syntax highlighting")
	}
}

// TestPlainTextNoRegression: a plain message is returned byte-for-byte unchanged
// and never reported as a block.
func TestPlainTextNoRegression(t *testing.T) {
	r := New(th("nether"), 80)
	body := "the database is on fire"
	out, blocks, isBlock := r.RenderBody(body, 1, NewCollapseState())
	if isBlock || blocks != 0 {
		t.Fatalf("plain text must not be a block (isBlock=%v blocks=%d)", isBlock, blocks)
	}
	if out != body {
		t.Errorf("plain text changed: %q != %q", out, body)
	}
}

// TestRenderCacheHit: re-rendering the same body with the same inputs hits the
// cache instead of re-highlighting.
func TestRenderCacheHit(t *testing.T) {
	r := New(th("nether"), 80)
	body := "```go\nfunc f() {}\n```"
	cs := NewCollapseState()

	r.RenderBody(body, 1, cs)
	if h, m := r.Stats(); h != 0 || m != 1 {
		t.Fatalf("first render: want hit=0 miss=1, got hit=%d miss=%d", h, m)
	}
	r.RenderBody(body, 1, cs)
	if h, m := r.Stats(); h != 1 || m != 1 {
		t.Fatalf("second render: want hit=1 miss=1, got hit=%d miss=%d", h, m)
	}
}

// TestChromaStyleMappingDistinct guards the property the theme-switch test
// depends on: nether and dracula must map to different chroma styles.
func TestChromaStyleMappingDistinct(t *testing.T) {
	if chromaStyleFor("nether") == chromaStyleFor("dracula") {
		t.Error("nether and dracula must map to different chroma styles")
	}
}
