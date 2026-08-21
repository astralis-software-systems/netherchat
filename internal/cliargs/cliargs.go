// Package cliargs is the argv layer every Netherchat command line goes through.
//
// It exists for one defect class. Go's flag package stops parsing at the first
// non-flag argument and leaves the rest — flags included — in Args(), so a
// command that does not look at Args() has silently discarded arguments the
// operator typed:
//
//	netherchat send ops "relay is on a LAN, no TLS" --server ws://192.168.0.203:3000
//
// parsed no --server at all. It dialled ws://localhost:3000, and the flags were
// joined into the MESSAGE and encrypted into the room.
//
// # WHY THE EARLIER SWEEP DID NOT FIND THIS
//
// Phase 2 (docs/phase2-cli-dispatch-2026-08-19.md §6) traced 142 flags across
// 22 subcommands by hand and asked of each: is this flag READ? It found two
// that were not and reported the class closed. This shape answers that question
// YES — the flag is read, at a line the sweep cites — and still never arrives,
// because argv ordering means Parse never sees it. The class was not closed; it
// was narrowed by the question asked (roadmap §8: a defect found three times is
// a class; sweep past the directory you were asked about).
//
// # WHAT THIS PACKAGE DOES ABOUT IT
//
// Parse makes a typed flag reach the code that reads it no matter where on the
// line it was typed. Unexpected makes an argument that still cannot be used an
// error rather than a silence. Between them there is no argv a command accepts
// and ignores, which is the property worth having: this project's recurring
// failure is not that arguments are handled wrongly, it is that they are
// handled invisibly.
//
// Nothing here changes what any flag MEANS. A flag keeps its name, its type,
// its default, and the code that consumes it; only the positions at which it
// may appear change.
package cliargs

import (
	"flag"
	"fmt"
	"os"
)

// Parse parses args into fs, allowing flags to appear after positional
// arguments, and returns the positional arguments in the order given.
//
// It calls fs.Parse repeatedly: each call consumes flags until it stops at a
// positional, that positional is collected, and the remainder is parsed again.
// This is the permutation GNU getopt does and Go's flag package deliberately
// does not (flag's doc: "Flag parsing stops just before the first non-flag
// argument"). Go's choice is right for a command whose trailing arguments are
// filenames that may look like flags; it is wrong for this CLI, where the
// trailing argument is a room or a record path and the flags are how an
// operator names the relay, the identity, and the invite token.
//
// Everything after a bare "--" is positional, verbatim, and is never re-parsed.
// That is the escape hatch for a positional beginning with "-", and it has to
// be handled here rather than left to fs.Parse: fs.Parse consumes the "--" and
// reports what follows as ordinary Args(), which this loop would otherwise feed
// straight back in as flags.
//
// With flag.ContinueOnError, a parse error ends the loop and the arguments not
// yet reached are returned as positionals; the caller inspects fs's error the
// way it already does. With flag.ExitOnError — every command in this tree —
// fs.Parse never returns.
func Parse(fs *flag.FlagSet, args []string) []string {
	head, tail := splitTerminator(args)
	var positional []string
	for {
		if err := fs.Parse(head); err != nil {
			break
		}
		rest := fs.Args()
		if len(rest) == 0 {
			break
		}
		positional = append(positional, rest[0])
		head = rest[1:]
	}
	return append(positional, tail...)
}

// splitTerminator splits args at the first bare "--", dropping the terminator
// itself. Without one, everything is head.
func splitTerminator(args []string) (head, tail []string) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

// Unexpected reports the first positional argument a command cannot use, or nil
// when there is none. cmd is the command as an operator types it; allowed is how
// many positionals it takes, and -1 means any number.
//
// A command handed a positional it does not read is not a harmless typo. Before
// Parse above, it was the thing that made every flag after it invisible; after
// Parse, it is an argument the operator typed and the program will act as though
// they did not. Both are the same failure, and refusing is the only answer that
// never guesses which one the operator meant.
func Unexpected(cmd string, positional []string, allowed int) error {
	if allowed < 0 || len(positional) <= allowed {
		return nil
	}
	switch allowed {
	case 0:
		return fmt.Errorf("%s takes no positional arguments and got %q — everything it reads comes from a flag; run it with --help for the list",
			cmd, positional[0])
	case 1:
		return fmt.Errorf("%s takes one positional argument, and got %d: %q then %q — it will not guess which one you meant",
			cmd, len(positional), positional[0], positional[1])
	default:
		return fmt.Errorf("%s takes %d positional arguments, and got %d — the extra one is %q",
			cmd, allowed, len(positional), positional[allowed])
	}
}

// MustParse is Parse plus Unexpected for the ordinary case: a command that
// wants the positionals and cannot carry on without a usable command line. cmd
// is the program or subcommand as an operator types it, and allowed is how many
// positionals it takes (-1 for any number).
//
// It exits 2, matching flag.ExitOnError — which already exits the process on an
// unknown flag from inside this same package. An argument the command cannot
// use is that same class of mistake and gets the same answer; what it must
// never get is silence.
//
// Parse and Unexpected are the parts with the behaviour, and they return rather
// than exit, so the guard is verifiable in a test without a subprocess. This
// wrapper is the plumbing.
func MustParse(cmd string, fs *flag.FlagSet, args []string, allowed int) []string {
	pos := Parse(fs, args)
	if err := Unexpected(cmd, pos, allowed); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		fs.Usage()
		os.Exit(2)
	}
	return pos
}

// First returns the first positional, or "" when there is none — the shape a
// command with one optional positional (a room, a record path) wants back.
func First(pos []string) string {
	if len(pos) == 0 {
		return ""
	}
	return pos[0]
}
