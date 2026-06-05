package command

import (
	"reflect"
	"testing"
)

func testSet() *Set {
	return New(
		Command{Name: "help", Help: "show help"},
		Command{Name: "theme", Args: "<name>", Help: "switch theme",
			Complete: func(p string) []string { return FilterPrefix([]string{"nether", "abyss", "ember"}, p) }},
		Command{Name: "ttl", Args: "<dur>", Help: "set ttl",
			Complete: func(p string) []string { return FilterPrefix([]string{"off", "1h", "24h"}, p) }},
		Command{Name: "whoami", Help: "session info"},
	)
}

func TestParse(t *testing.T) {
	s := testSet()
	name, arg, ok := s.Parse("/theme dracula")
	if !ok || name != "theme" || arg != "dracula" {
		t.Fatalf("parse = %q %q %v", name, arg, ok)
	}
	if _, _, ok := s.Parse("hello world"); ok {
		t.Error("non-slash input should not parse as a command")
	}
	name, arg, ok = s.Parse("/whoami")
	if !ok || name != "whoami" || arg != "" {
		t.Fatalf("parse no-arg = %q %q %v", name, arg, ok)
	}
}

func TestSuggestCommandNames(t *testing.T) {
	s := testSet()
	got := s.Suggest("/t")
	var names []string
	for _, sug := range got {
		names = append(names, sug.Value)
	}
	if !reflect.DeepEqual(names, []string{"/theme", "/ttl"}) {
		t.Fatalf("command-name suggestions = %v", names)
	}
}

func TestSuggestArguments(t *testing.T) {
	s := testSet()
	got := s.Suggest("/theme a")
	if len(got) != 1 || got[0].Value != "/theme abyss" {
		t.Fatalf("arg suggestions = %+v", got)
	}

	all := s.Suggest("/ttl ")
	if len(all) != 3 {
		t.Fatalf("expected 3 ttl suggestions, got %d", len(all))
	}
}

func TestSuggestUnknownCommandArg(t *testing.T) {
	s := testSet()
	if got := s.Suggest("/nope foo"); got != nil {
		t.Errorf("unknown command should yield no suggestions, got %v", got)
	}
}
