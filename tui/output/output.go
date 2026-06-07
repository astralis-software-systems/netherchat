// Package output centralizes machine-readable (JSON) and human stdout/stderr
// writing for the netherchat CLI. Every subcommand routes through it so that,
// when --json is set, stdout carries only valid JSON (compact, one object per
// line for streams) and errors go to stderr as {"error":"…"} — never mixed.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Out and Err are the destinations. They are variables so tests can capture
// output by swapping in a buffer.
var (
	Out io.Writer = os.Stdout
	Err io.Writer = os.Stderr
)

// WriteJSON marshals v as a single compact JSON line to Out. Compact + a
// trailing newline makes it ndjson-friendly (pipe straight into jq, Vector,
// Loki); jq pretty-prints on the other end if a human wants it.
func WriteJSON(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(Out, string(b))
	return err
}

// WriteHuman writes a formatted human line to Out.
func WriteHuman(format string, args ...any) {
	fmt.Fprintf(Out, format, args...)
}

// WriteError reports err on stderr (never stdout). In JSON mode it is a single
// {"error":"…"} object so a downstream parser sees structured output on both
// streams; otherwise a plain "netherchat: …" line.
func WriteError(jsonMode bool, err error) {
	if jsonMode {
		b, _ := json.Marshal(map[string]string{"error": err.Error()})
		fmt.Fprintln(Err, string(b))
	} else {
		fmt.Fprintln(Err, "netherchat: "+err.Error())
	}
}

// Fatal reports err and exits non-zero. --json still exits 0 on success; this is
// the error path.
func Fatal(jsonMode bool, err error) {
	WriteError(jsonMode, err)
	os.Exit(1)
}
