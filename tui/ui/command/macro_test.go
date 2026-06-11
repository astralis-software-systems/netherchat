package command

import (
	"strings"
	"testing"
)

// builtinsFixture is a small built-in set for macro tests.
func builtinsFixture() *Set {
	return New(
		Command{Name: "break-glass"},
		Command{Name: "ack"},
		Command{Name: "decide"},
		Command{Name: "vanish"},
	)
}

func TestMacroExpands(t *testing.T) {
	ms, err := LoadMacros(map[string]string{
		"drain": "/ack drain-complete",
	}, builtinsFixture())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	cmds, ok := ms.Expand("drain")
	if !ok || len(cmds) != 1 || cmds[0] != "/ack drain-complete" {
		t.Fatalf("expand(drain) = %v, ok=%v", cmds, ok)
	}
	if _, ok := ms.Expand("notamacro"); ok {
		t.Fatal("Expand should report a non-macro as not found")
	}
}

func TestMacroMultiCommandSequence(t *testing.T) {
	ms, err := LoadMacros(map[string]string{
		"resolved": "/decide incident resolved · /vanish",
	}, builtinsFixture())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	cmds, _ := ms.Expand("resolved")
	want := []string{"/decide incident resolved", "/vanish"}
	if len(cmds) != 2 || cmds[0] != want[0] || cmds[1] != want[1] {
		t.Fatalf("multi-command expansion = %v, want %v", cmds, want)
	}
}

func TestMacroNestedExpansion(t *testing.T) {
	ms, err := LoadMacros(map[string]string{
		"drain":    "/ack drain-complete",
		"resolved": "/drain · /decide done",
	}, builtinsFixture())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	cmds, _ := ms.Expand("resolved")
	want := []string{"/ack drain-complete", "/decide done"}
	if len(cmds) != 2 || cmds[0] != want[0] || cmds[1] != want[1] {
		t.Fatalf("nested expansion = %v, want %v", cmds, want)
	}
}

func TestMacroConflictRejected(t *testing.T) {
	_, err := LoadMacros(map[string]string{"vanish": "/ack x"}, builtinsFixture())
	if err == nil || !strings.Contains(err.Error(), "conflicts with the built-in") {
		t.Fatalf("expected a built-in conflict error, got %v", err)
	}
}

func TestMacroCircularRejected(t *testing.T) {
	_, err := LoadMacros(map[string]string{
		"a": "/b",
		"b": "/a",
	}, builtinsFixture())
	if err == nil || !strings.Contains(err.Error(), "circ") {
		t.Fatalf("expected a circular-expansion error, got %v", err)
	}
	// A self-referential macro is also circular.
	_, err = LoadMacros(map[string]string{"loop": "/loop"}, builtinsFixture())
	if err == nil || !strings.Contains(err.Error(), "circ") {
		t.Fatalf("expected a self-cycle error, got %v", err)
	}
}

func TestMacroUnknownReferenceRejected(t *testing.T) {
	_, err := LoadMacros(map[string]string{"x": "/nosuchcommand"}, builtinsFixture())
	if err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("expected an unknown-command error, got %v", err)
	}
}

func TestMacroEmptyExpansionRejected(t *testing.T) {
	if _, err := LoadMacros(map[string]string{"x": "  "}, builtinsFixture()); err == nil {
		t.Fatal("expected an error for an empty expansion")
	}
}

func TestMacroAutocomplete(t *testing.T) {
	ms, err := LoadMacros(map[string]string{
		"sev1": "/break-glass --invite oncall,ic --ttl 4h",
	}, builtinsFixture())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	set := New(Command{Name: "seal"})
	set.Add(ms.Commands()...)

	var names []string
	for _, s := range set.Suggest("/se") {
		names = append(names, s.Value)
	}
	if !contains(names, "/sev1") {
		t.Fatalf("autocomplete for /se = %v, want it to include /sev1", names)
	}
	// The hint carries the (truncated) expansion.
	if c, ok := set.Get("sev1"); !ok || !strings.HasPrefix(c.Help, "macro: /break-glass") {
		t.Fatalf("macro command help = %q", c.Help)
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
