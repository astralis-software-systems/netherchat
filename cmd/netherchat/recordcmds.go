package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/salehkreiner/netherchat/tui/output"
	"github.com/salehkreiner/netherchat/tui/record"
)

// verifyCmd implements `netherchat verify record.json [--json]` (§1.4): it
// recomputes the hash chain from scratch, checks every PrevHash link, verifies
// each entry's Ed25519 signature against its author, and verifies each sealer's
// signature over the chain head. It exits 0 for VALID, 1 for TAMPERED or any
// load/parse error — so it composes in scripts and CI.
func verifyCmd(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	jsonMode := fs.Bool("json", false, "output the verification result as JSON")
	// --issuer and --at apply to an identity attestation only. There is no default
	// issuer file and no default key: an issuer is a trust anchor, and this binary
	// holds none of its own. Without --issuer an identity artifact prints its
	// structural facts and exits non-zero, because with no anchor there is no
	// verdict to give.
	issuer := fs.String("issuer", "", "identity artifacts: file of issuer public keys, one per line (base64 or ssh-ed25519)")
	at := fs.String("at", "", "identity artifacts: RFC3339 evaluation time the validity window is asked about (default: now)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netherchat verify <record.json|roster.json|receipt.json|identity.json> [--json] [--issuer <keys>] [--at <RFC3339>]")
		fs.PrintDefaults()
	}
	// The record path is the first positional; flags follow it. Go's flag parser
	// stops at the first non-flag argument, so (like send/tail) we peel the path
	// off first and parse the rest — otherwise `verify record.json --json` would
	// silently ignore --json.
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fs.Usage()
		os.Exit(2)
	}
	path := args[0]
	_ = fs.Parse(args[1:])
	os.Exit(verifyArtifact(path, *jsonMode, identityVerifyOpts{issuerPath: *issuer, at: *at}))
}

// verifyFile loads and verifies a sealed RECORD specifically, returning the
// process exit code. It is used by `replay --verify-only`, which only ever deals
// with records; the `verify` command itself dispatches by artifact type (see
// verifyArtifact).
func verifyFile(path string, jsonMode bool) int {
	b, err := os.ReadFile(path)
	if err != nil {
		output.WriteError(jsonMode, err)
		return 1
	}
	return verifyRecordBytes(b, jsonMode)
}

// verifyRecordBytes parses and verifies a sealed record from bytes, printing the
// verdict and returning the exit code (0 = VALID, 1 = TAMPERED/error).
func verifyRecordBytes(b []byte, jsonMode bool) int {
	res, err := record.VerifyBytes(b)
	if err != nil {
		output.WriteError(jsonMode, err)
		return 1
	}

	if jsonMode {
		_ = output.WriteJSON(res)
		if res.Valid {
			return 0
		}
		return 1
	}

	if !res.Valid {
		output.WriteHuman("TAMPERED — %s\n", res.Reason)
		return 1
	}
	output.WriteHuman("VALID — chain intact, %d entr%s, %d signature(s) verified\n",
		res.Entries, plural(res.Entries, "y", "ies"), len(res.Signers))
	output.WriteHuman("  room: %s\n  head: %s\n", res.Room, res.HeadHash)
	for _, s := range res.Signers {
		output.WriteHuman("  signed: %s\n", s)
	}
	return 0
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
