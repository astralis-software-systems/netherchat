package cliargs

import (
	"flag"
	"io"
	"strings"
	"testing"
)

// newFS builds a flag set shaped like a real subcommand's: a string, a bool, a
// duration-ish string, and a repeatable Var. ContinueOnError so a test can
// drive a bad line without exiting the test binary.
func newFS() (*flag.FlagSet, *string, *bool, *repeatable) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	server := fs.String("server", "ws://localhost:3000", "")
	jsonMode := fs.Bool("json", false, "")
	var files repeatable
	fs.Var(&files, "file", "")
	return fs, server, jsonMode, &files
}

// repeatable is the shape of the real --file/--role/--consultant flags: Set is
// called once per occurrence and appends. Parse is called more than once by
// Parse(), so this is what would double-count if the loop re-fed tokens.
type repeatable []string

func (r *repeatable) String() string     { return strings.Join(*r, ",") }
func (r *repeatable) Set(v string) error { *r = append(*r, v); return nil }

// TestFlagAfterAPositionalIsParsed is the defect this package exists for, at
// its smallest: a flag typed after a positional must reach the code that reads
// it. Before this package, *server here was the default.
func TestFlagAfterAPositionalIsParsed(t *testing.T) {
	fs, server, jsonMode, _ := newFS()

	pos := Parse(fs, []string{"ops", "a message", "--server", "ws://relay:3000", "--json"})

	if *server != "ws://relay:3000" {
		t.Errorf("--server after a positional = %q, want %q", *server, "ws://relay:3000")
	}
	if !*jsonMode {
		t.Error("--json after a positional was not parsed")
	}
	if got := strings.Join(pos, "|"); got != "ops|a message" {
		t.Errorf("positionals = %q, want %q", got, "ops|a message")
	}
}

// TestFlagBeforeAPositionalStillWorks is the control. Every documented
// invocation in this tree puts flags after a leading room or path, and a fix
// that traded that for the reverse would be no fix.
func TestFlagBeforeAPositionalStillWorks(t *testing.T) {
	fs, server, jsonMode, _ := newFS()

	pos := Parse(fs, []string{"--server", "ws://relay:3000", "ops", "--json"})

	if *server != "ws://relay:3000" || !*jsonMode {
		t.Errorf("server=%q json=%v", *server, *jsonMode)
	}
	if len(pos) != 1 || pos[0] != "ops" {
		t.Errorf("positionals = %v, want [ops]", pos)
	}
}

// TestRepeatableFlagIsNotDoubleCounted guards the one thing the repeated-Parse
// loop could plausibly get wrong. A repeatable Var APPENDS on every Set, and
// several real flags are of that kind (--file on attest, --role on issue,
// --consultant on engagement init). If the loop ever re-fed a token it had
// already parsed, a role would be signed into a credential twice.
func TestRepeatableFlagIsNotDoubleCounted(t *testing.T) {
	fs, _, _, files := newFS()

	Parse(fs, []string{"--file", "a.json", "room", "--file", "b.json"})

	if got := strings.Join(*files, ","); got != "a.json,b.json" {
		t.Errorf("repeatable flag = %q, want %q", got, "a.json,b.json")
	}
}

// TestTerminatorStopsParsing proves the escape hatch. Permuting without
// honouring "--" would take a positional that begins with "-" and try to parse
// it as a flag, which is a worse failure than the one being fixed: it turns a
// legitimate argument into an exit-2.
func TestTerminatorStopsParsing(t *testing.T) {
	fs, server, jsonMode, _ := newFS()

	pos := Parse(fs, []string{"ops", "--server", "ws://relay:3000", "--", "--json", "-x"})

	if *server != "ws://relay:3000" {
		t.Errorf("--server before -- = %q", *server)
	}
	if *jsonMode {
		t.Error("--json after -- was parsed as a flag; the terminator did not hold")
	}
	if got := strings.Join(pos, "|"); got != "ops|--json|-x" {
		t.Errorf("positionals = %q, want %q", got, "ops|--json|-x")
	}
}

// TestEmptyArgsParses covers the no-arguments line: fs must still be parsed, so
// a caller reading fs.Args() or fs.Parsed() sees a parsed, empty flag set.
func TestEmptyArgsParses(t *testing.T) {
	fs, server, _, _ := newFS()

	pos := Parse(fs, nil)

	if len(pos) != 0 {
		t.Errorf("positionals = %v, want none", pos)
	}
	if !fs.Parsed() {
		t.Error("an empty command line must still leave the flag set parsed")
	}
	if *server != "ws://localhost:3000" {
		t.Errorf("defaults must survive an empty parse: %q", *server)
	}
}

// TestParseErrorEndsTheLoop proves the loop terminates on a bad flag rather
// than spinning, and that ContinueOnError callers still see the error.
func TestParseErrorEndsTheLoop(t *testing.T) {
	fs, _, _, _ := newFS()

	pos := Parse(fs, []string{"ops", "--nope"})

	if len(pos) == 0 || pos[0] != "ops" {
		t.Errorf("positionals = %v, want the positional seen before the error", pos)
	}
}

// TestUnexpectedRefusesWhatItCannotUse is the guard, driven at every arity a
// command in this tree declares. A guard that has never failed has never been
// verified (roadmap §8), so each branch is made to fail here.
func TestUnexpectedRefusesWhatItCannotUse(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pos     []string
		allowed int
		want    string // substring the message must carry, or "" for no error
	}{
		{"flags-only command, one stray", []string{"netherchat.toml"}, 0, `"netherchat.toml"`},
		{"flags-only command, clean", nil, 0, ""},
		{"one positional, two given", []string{"rec.json", "extra"}, 1, `"extra"`},
		{"one positional, one given", []string{"rec.json"}, 1, ""},
		{"one positional, none given", nil, 1, ""},
		{"free-form, anything goes", []string{"ops", "a", "b"}, -1, ""},
		{"two positionals, three given", []string{"a", "b", "c"}, 2, `"c"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Unexpected("netherchat test", tc.pos, tc.allowed)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("refused a line it can use: %v", err)
			case tc.want == "":
				return
			case err == nil:
				t.Fatalf("accepted %v at allowed=%d — an argument the operator typed would be ignored", tc.pos, tc.allowed)
			case !strings.Contains(err.Error(), tc.want):
				t.Errorf("message must name the argument it refused; got %q, want it to contain %s", err, tc.want)
			case !strings.Contains(err.Error(), "netherchat test"):
				t.Errorf("message must name the command; got %q", err)
			}
		})
	}
}
