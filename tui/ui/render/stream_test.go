package render

import (
	"strings"
	"testing"

	"github.com/salehkreiner/netherchat/tui/ui/theme"
)

func TestRenderStreamBox(t *testing.T) {
	r := New(theme.Default(), 60)
	out := r.RenderStream("stream: app.log (alice)", []string{"INFO ok", "ERROR boom"}, false, "stream-1")
	if !strings.Contains(out, "stream: app.log") {
		t.Fatalf("stream box missing header:\n%s", out)
	}
	// Box drawing characters present (rendered like a code block).
	if !strings.ContainsAny(out, "┌└│") {
		t.Fatalf("stream box missing border:\n%s", out)
	}
}

func TestRenderStreamFoldAndExpand(t *testing.T) {
	r := New(theme.Default(), 60)
	many := make([]string, 12)
	for i := range many {
		many[i] = "line"
	}
	collapsed := r.RenderStream("s", many, false, "stream-2")
	if !strings.Contains(collapsed, "/expand stream-2") {
		t.Fatalf("collapsed stream should show the fold affordance:\n%s", collapsed)
	}
	expanded := r.RenderStream("s", many, true, "stream-2")
	if strings.Contains(expanded, "more lines") {
		t.Fatalf("expanded stream should not fold:\n%s", expanded)
	}
}

func TestLogLevelDetection(t *testing.T) {
	cases := map[string]level{
		"2026-06-10 ERROR boom": levelError,
		"something FATAL here":  levelError,
		"a WARN message":        levelWarn,
		"DEBUG verbose":         levelDebug,
		"plain info-less line":  levelNone,
		"INFO normal":           levelNone,
	}
	for line, want := range cases {
		if got := logLevel(line); got != want {
			t.Errorf("logLevel(%q) = %d, want %d", line, got, want)
		}
	}
}
