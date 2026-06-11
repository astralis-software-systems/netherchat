package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/salehkreiner/netherchat/tui/duress"
)

// duressCmd implements `netherchat duress <subcommand>` (C2): the coercion-resistant
// safe response. See docs/duress.md for the threat model.
//
//	netherchat duress selftest          prove the safe path works (no input, no I/O)
//	netherchat duress beacon            emit a signed, out-of-band duress beacon
//	netherchat duress verify <file>     verify a duress beacon offline
//	netherchat duress check             classify an unlock attempt (real/duress/reject)
func duressCmd(args []string) {
	if len(args) == 0 {
		duressUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "selftest":
		duressSelftest(args[1:])
	case "beacon":
		duressBeacon(args[1:])
	case "verify":
		duressVerify(args[1:])
	case "check":
		duressCheck(args[1:])
	case "-h", "--help", "help":
		duressUsage()
	default:
		fmt.Fprintf(os.Stderr, "netherchat duress: unknown subcommand %q\n\n", args[0])
		duressUsage()
		os.Exit(2)
	}
}

func duressSelftest(args []string) {
	fs := flag.NewFlagSet("duress selftest", flag.ExitOnError)
	mode := fs.String("mode", string(duress.ModeSilentScuttle), "safe response to test: silent_scuttle | decoy_view")
	_ = fs.Parse(args)

	m, err := parseDuressMode(*mode)
	if err != nil {
		fatal(err)
	}
	if err := duress.SelfTest(m); err != nil {
		fatal(err)
	}
	fmt.Printf("duress self-test passed (mode=%s): the duress credential triggers the safe response, "+
		"the real credential does not, an unrelated one is rejected, and the signed beacon verifies offline.\n", m)
}

func duressBeacon(args []string) {
	fs := flag.NewFlagSet("duress beacon", flag.ExitOnError)
	mode := fs.String("mode", string(duress.ModeSilentScuttle), "mode recorded in the beacon: silent_scuttle | decoy_view")
	context := fs.String("context", "", "optional, non-sensitive label (e.g. a site or room); NO secrets")
	identity := fs.String("identity", "", "identity key file (default: ssh-agent → ~/.ssh/id_ed25519 → generated)")
	out := fs.String("out", "", "write the signed beacon JSON here (default: stdout)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netherchat duress beacon [--mode silent_scuttle|decoy_view] [--context label] [--identity path] [--out file]")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	m, err := parseDuressMode(*mode)
	if err != nil {
		fatal(err)
	}
	b, err := duress.EmitBeacon(*identity, m, *context)
	if err != nil {
		fatal(err)
	}
	raw, err := b.Marshal()
	if err != nil {
		fatal(err)
	}
	if *out == "" {
		fmt.Println(string(raw))
		return
	}
	if err := os.WriteFile(*out, append(raw, '\n'), 0o600); err != nil {
		fatal(err)
	}
	fmt.Fprintf(os.Stderr, "wrote signed duress beacon to %s (actor %s)\n", *out, b.Actor)
}

func duressVerify(args []string) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(os.Stderr, "usage: netherchat duress verify <beacon.json>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(args[0])
	if err != nil {
		fatal(err)
	}
	b, err := duress.ParseBeacon(raw)
	if err != nil {
		fatal(err)
	}
	if err := b.Verify(); err != nil {
		fmt.Fprintf(os.Stderr, "netherchat: duress beacon INVALID — %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("VALID duress beacon\n  actor:   %s\n  mode:    %s\n  context: %s\n  issued:  %s\n",
		b.Actor, b.Mode, orDash(b.Context), b.IssuedAt)
}

// duressCheck classifies a single unlock attempt. It reads exactly three lines from
// stdin — the real credential, the duress credential, then the attempt — derives
// the in-memory tokens, evaluates the attempt, and signals the result via exit code
// (0 normal, 10 duress, 3 reject). Nothing is persisted: the credentials exist only
// for this process. With --beacon-out, a duress match also writes a signed beacon.
//
// For genuine coercion resistance the embedding flow must make the duress path
// LOOK IDENTICAL to a normal one; pass --quiet here and branch only on the exit
// code, so a coercer watching the terminal sees nothing distinguishing.
func duressCheck(args []string) {
	fs := flag.NewFlagSet("duress check", flag.ExitOnError)
	mode := fs.String("mode", string(duress.ModeSilentScuttle), "safe response on a duress match: silent_scuttle | decoy_view")
	context := fs.String("context", "", "optional, non-sensitive label for the emitted beacon")
	identity := fs.String("identity", "", "identity key file for the duress beacon")
	beaconOut := fs.String("beacon-out", "", "on a duress match, write a signed beacon here")
	quiet := fs.Bool("quiet", false, "print nothing to stdout; signal only via exit code (0 normal, 10 duress, 3 reject)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netherchat duress check [--mode ...] [--quiet] [--beacon-out file] [--identity path]")
		fmt.Fprintln(os.Stderr, "reads three lines from stdin: <real-credential> <duress-credential> <attempt>")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	m, err := parseDuressMode(*mode)
	if err != nil {
		fatal(err)
	}
	real, duressPhrase, attempt, err := readThreeLines(os.Stdin)
	if err != nil {
		fatal(err)
	}
	g, err := duress.Arm(real, duressPhrase, m)
	if err != nil {
		fatal(err)
	}
	disp := g.Evaluate(attempt)

	if disp == duress.Duress && *beaconOut != "" {
		b, err := duress.EmitBeacon(*identity, m, *context)
		if err != nil {
			fatal(err)
		}
		raw, _ := b.Marshal()
		if err := os.WriteFile(*beaconOut, append(raw, '\n'), 0o600); err != nil {
			fatal(err)
		}
	}
	if !*quiet {
		fmt.Println(disp.String())
	}
	os.Exit(duressExitCode(disp))
}

// duressExitCode maps a disposition to a process exit code for scripting.
func duressExitCode(d duress.Disposition) int {
	switch d {
	case duress.Normal:
		return 0
	case duress.Duress:
		return 10
	default:
		return 3
	}
}

func parseDuressMode(s string) (duress.Mode, error) {
	m := duress.Mode(s)
	if err := m.Valid(); err != nil {
		return "", err
	}
	return m, nil
}

// readThreeLines reads exactly three newline-delimited fields from r, copying each
// (the scanner reuses its buffer). Trailing \r is stripped by ScanLines.
func readThreeLines(r io.Reader) (a, b, c []byte, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	lines := make([][]byte, 0, 3)
	for len(lines) < 3 && sc.Scan() {
		lines = append(lines, append([]byte(nil), sc.Bytes()...))
	}
	if err := sc.Err(); err != nil {
		return nil, nil, nil, err
	}
	if len(lines) < 3 {
		return nil, nil, nil, fmt.Errorf("duress check: expected 3 lines on stdin (real, duress, attempt), got %d", len(lines))
	}
	return lines[0], lines[1], lines[2], nil
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func duressUsage() {
	fmt.Fprintln(os.Stderr, `usage: netherchat duress <subcommand>

  selftest [--mode ...]                     prove the safe path works (no input, no I/O)
  beacon   [--mode ...] [--context l] [--out f]   emit a signed, out-of-band duress beacon
  verify   <beacon.json>                    verify a duress beacon offline
  check    [--mode ...] [--quiet] [--beacon-out f]   classify an unlock attempt from stdin

modes: silent_scuttle (destroy local state + beacon, appear benign) | decoy_view (show a decoy)
see docs/duress.md for the threat model.`)
}
