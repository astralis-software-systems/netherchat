package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The flags-after-positionals class.
//
// Phase 2's sweep (docs/phase2-cli-dispatch-2026-08-19.md §6) audited 142 flags
// across 22 subcommands for whether each is READ, and closed the class on two
// drops. This is a different shape: the flag IS read, and never REACHED,
// because Go's flag package stops parsing at the first non-flag argument and
// leaves everything after it — flags included — in Args(). A command that does
// not look at Args() has silently discarded an argument the operator typed.
//
// These tests start at argv, which is the surface a user touches (roadmap §8).

// TestConnectURLAfterAFlagIsNotDropped drives the shape that made `send` a
// finding, on `connect`, where it is worse: the dropped argument is the RELAY.
//
//	netherchat connect --room ops ws://relay.example:3000
//
// parseConnectFlags peels a leading positional URL, so the documented order
// works. In the other order the URL is not leading, nothing peels it, fs.Parse
// stops at it, and fs.Args() is discarded — so the client connects to
// ws://localhost:3000 while the operator watches a room name they did type
// appear on a relay they did not.
func TestConnectURLAfterAFlagIsNotDropped(t *testing.T) {
	f, url := parseConnectFlags([]string{"--room", "ops", "ws://relay.example:3000"})

	if url != "ws://relay.example:3000" {
		t.Errorf("relay URL after a flag was dropped: got %q, want %q\n"+
			"an operator who typed a relay must not be connected to the default one", url, "ws://relay.example:3000")
	}
	if f.room != "ops" {
		t.Errorf("--room = %q, want %q", f.room, "ops")
	}
}

// TestConnectFlagsAfterTheURLStillWork is the control: the documented order has
// to keep working, or the fix above traded one silent wrong answer for another.
func TestConnectFlagsAfterTheURLStillWork(t *testing.T) {
	f, url := parseConnectFlags([]string{"ws://relay.example:3000", "--room", "ops", "--name", "alice"})

	if url != "ws://relay.example:3000" || f.room != "ops" || f.name != "alice" {
		t.Errorf("url=%q room=%q name=%q", url, f.room, f.name)
	}
}

// TestSendFlagsAfterTheMessageReachTheDial is R2, driven at argv exactly as
// docs/self-hosting.md's Mode A section had an operator type it:
//
//	netherchat send airgap "relay is on a LAN address, no TLS anywhere" \
//	  --server ws://192.168.0.203:3000 --name alice --identity ./alice.json
//
// sendCmd peeled the leading room and called fs.Parse on the rest, which stops
// at the message — so every flag after it was left in fs.Args() and joined into
// the MESSAGE. The command dialled ws://localhost:3000 and, had anything been
// listening there, would have encrypted the operator's --identity path into a
// room on the wrong relay. With --invite it would have published a one-time
// token as chat text.
//
// It failed visibly in Phase 5 only because nothing was on localhost.
func TestSendFlagsAfterTheMessageReachTheDial(t *testing.T) {
	a, _ := parseSendArgs([]string{
		"airgap", "relay is on a LAN address, no TLS anywhere",
		"--server", "ws://192.168.0.203:3000",
		"--name", "alice",
		"--identity", "./alice.json",
	})

	if a.url != "ws://192.168.0.203:3000" {
		t.Errorf("--server = %q, want %q — the message must not swallow the relay", a.url, "ws://192.168.0.203:3000")
	}
	if a.name != "alice" {
		t.Errorf("--name = %q, want %q", a.name, "alice")
	}
	if a.identity != "./alice.json" {
		t.Errorf("--identity = %q, want %q", a.identity, "./alice.json")
	}
	if a.room != "airgap" {
		t.Errorf("room = %q, want %q", a.room, "airgap")
	}
	if a.msg != "relay is on a LAN address, no TLS anywhere" {
		t.Errorf("message = %q\nwant   = %q\na flag that was typed as a flag must never be encrypted into the room as text",
			a.msg, "relay is on a LAN address, no TLS anywhere")
	}
}

// TestSendSecretFlagIsNotSentAsTheMessage is the same defect at its sharpest.
// --invite carries a one-time token for an invite-only room; joined into the
// message it is broadcast to everyone in whatever room the command reached.
func TestSendSecretFlagIsNotSentAsTheMessage(t *testing.T) {
	const token = "inv_7f3c9a21e4"

	a, _ := parseSendArgs([]string{"ops", "deploy done", "--invite", token})

	if a.invite != token {
		t.Errorf("--invite = %q, want %q", a.invite, token)
	}
	if strings.Contains(a.msg, token) {
		t.Errorf("the invite token was put in the message body: %q", a.msg)
	}
}

// TestSendDocumentedFormsStillWork is the control: every send line the tree
// documents has to keep meaning what it meant.
func TestSendDocumentedFormsStillWork(t *testing.T) {
	// README/usage: pipe form, flags after the room, no message positional.
	a, _ := parseSendArgs([]string{"ops", "--server", "ws://host:3000"})
	if a.room != "ops" || a.url != "ws://host:3000" || a.msg != "" {
		t.Errorf("pipe form: room=%q url=%q msg=%q", a.room, a.url, a.msg)
	}

	// usage: the file form, where there is no positional room at all.
	a, _ = parseSendArgs([]string{"--file", "heap.prof", "--room", "ops", "--server", "ws://host:3000"})
	if a.room != "ops" || a.file != "heap.prof" || a.url != "ws://host:3000" {
		t.Errorf("file form: room=%q file=%q url=%q", a.room, a.file, a.url)
	}

	// The leading "#room" spelling, and a multi-word unquoted message.
	a, _ = parseSendArgs([]string{"#ops", "build", "failed", "on", "main"})
	if a.room != "ops" || a.msg != "build failed on main" {
		t.Errorf("#room form: room=%q msg=%q", a.room, a.msg)
	}

	// --room with a message. This is the case the room resolution was reordered
	// for: taking pos[0] as the room and letting --room overwrite it would leave
	// "hello" consumed as a room and the message empty, so the command would sit
	// waiting on stdin instead of sending what was typed.
	a, _ = parseSendArgs([]string{"--room", "ops", "hello"})
	if a.room != "ops" || a.msg != "hello" {
		t.Errorf("--room with a message: room=%q msg=%q, want ops/hello", a.room, a.msg)
	}
}

// TestSendTerminatorPassesAMessageThatLooksLikeAFlag is the escape hatch, at the
// surface that needs it. Permuting means a message word beginning with "-" is
// parsed as a flag; "--" is what makes it text again, and a documented escape
// hatch that does not work is worse than none.
func TestSendTerminatorPassesAMessageThatLooksLikeAFlag(t *testing.T) {
	a, _ := parseSendArgs([]string{"ops", "--server", "ws://host:3000", "--", "--not-a-flag"})

	if a.url != "ws://host:3000" {
		t.Errorf("--server before -- = %q", a.url)
	}
	if a.msg != "--not-a-flag" {
		t.Errorf("message = %q, want %q", a.msg, "--not-a-flag")
	}
}

// TestOnePositionalCommandsTakeFlagsInEitherOrder sweeps the commands that
// carry a leading positional. Each was written as "peel args[0], parse the
// rest", which works only while the positional is first — and `verify --json
// rec.json` was REFUSED outright by the HasPrefix(args[0], "-") guard that
// implemented the peel.
//
// Driven through runVerify because it is the one command in this group that
// returns its exit code instead of calling os.Exit; the others share the
// parseFlags1 path this exercises.
func TestOnePositionalCommandsTakeFlagsInEitherOrder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "not-a-record.json")
	if err := os.WriteFile(path, []byte(`{"nope":true}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// Both orders must reach the same file and the same --json. Exit 1 (the
	// artifact does not verify) rather than 2 (the command line was not usable)
	// is the signal that argv was understood.
	for _, args := range [][]string{
		{path, "--json"},
		{"--json", path},
	} {
		if code := runVerify(args); code != 1 {
			t.Errorf("runVerify(%q) = %d, want 1 — the command line was not understood", args, code)
		}
	}
}

// TestAStrayPositionalIsRefusedNotIgnored is the guard for the other half of
// the class. After permutation a flag can no longer hide behind a positional,
// but a positional a command has nothing to do with is still an argument the
// operator typed — and acting as though they had not is the failure mode this
// project keeps finding. `verify a.json b.json` used to verify a.json and say
// nothing about b.json.
func TestAStrayPositionalIsRefusedNotIgnored(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "a.json")
	if err := os.WriteFile(first, []byte(`{"nope":true}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if code := runVerify([]string{first, filepath.Join(dir, "b.json")}); code != 2 {
		t.Errorf("runVerify with two paths = %d, want 2 (refused) — a second artifact must not be silently dropped", code)
	}
}
