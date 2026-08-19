package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/output"
	"github.com/salehkreiner/netherchat/tui/record"
)

// verifyCmd implements `netherchat verify record.json [--json]` (§1.4): it
// recomputes the hash chain from scratch, checks every PrevHash link, verifies
// each entry's Ed25519 signature against its author, and verifies each sealer's
// signature over the chain head. It exits 0 for VALID, 1 for TAMPERED or any
// load/parse error — so it composes in scripts and CI.
func verifyCmd(args []string) { os.Exit(runVerify(args)) }

// runVerify is verifyCmd without the os.Exit, so the whole command — argv, flag
// parsing, dispatch, rendering — is reachable from a test. A flag that is parsed
// here and then not passed on is invisible to a test that starts below this
// line, and making that catchable is the entire reason for the split.
func runVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	jsonMode := fs.Bool("json", false, "output the verification result as JSON")
	// --issuer and --at apply to a standalone identity attestation AND to a sealed
	// record carrying attestation entries — the two artifacts that have identity
	// content to check. There is no default issuer file and no default key: an
	// issuer is a trust anchor, and this binary holds none of its own. Without
	// --issuer an identity artifact prints its structural facts and exits
	// non-zero, because with no anchor there is no verdict to give; a record
	// verifies exactly as it always did, and says nothing about identity at all.
	issuer := fs.String("issuer", "", "identity artifacts and records carrying them: file of issuer public keys, one per line (base64 or ssh-ed25519)")
	at := fs.String("at", "", "with --issuer: RFC3339 evaluation time the validity window is asked about (default: now)")
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
		return 2
	}
	path := args[0]
	_ = fs.Parse(args[1:])
	ident := identityVerifyOpts{issuerPath: *issuer, at: *at}
	// --at with no --issuer is an evaluation time with nothing to evaluate. The
	// spec makes the mirror of this an error rather than a Reason — a zero At on
	// the PINNED path is unusable caller input, not a verdict about an artifact —
	// and the same reasoning lands here: nothing downstream will ever read this
	// value, and an operator who supplied a time is asking for a time-evaluated
	// answer. Accepting it and doing nothing is what this session came to remove.
	if ident.at != "" && !ident.pinned() {
		output.WriteError(*jsonMode, errors.New("--at needs --issuer: an evaluation time is only meaningful against a pinned issuer, and with none there is nothing it would change"))
		return 2
	}
	return verifyArtifact(path, *jsonMode, ident)
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
	return verifyRecordBytes(b, jsonMode, identityVerifyOpts{})
}

// verifyRecordBytes parses and verifies a sealed record from bytes, printing the
// verdict and returning the exit code (0 = VALID, 1 = TAMPERED/error).
//
// THE TWO PATHS, AND WHY THEY ARE TWO. With no issuer pinned this calls
// record.VerifyBytes and renders exactly what it always rendered — the
// standalone-inert guarantee, held at the surface an operator actually runs, not
// only at the library. With an issuer pinned it calls VerifyBytesWithIdentity,
// which is where the record's attestation entries are checked against the
// operator's trust anchor and evaluation time.
//
// The pin check comes FIRST, before the issuer file is read and before a clock
// is consulted, mirroring §7.2 step 2's ordering for the same reason: it is what
// keeps the unpinned invocation byte-identical.
//
// The exit code is res.Valid and nothing else, on both paths. An attestation
// that failed never changes it — §7.2 step 5 — because a failing attestation may
// fail only because YOU pinned a different issuer or asked about a different
// time, and letting it move the verdict would make "VALID" mean different things
// on different machines. What a failed attestation changes is what is PRINTED.
func verifyRecordBytes(b []byte, jsonMode bool, ident identityVerifyOpts) int {
	if !ident.pinned() {
		res, err := record.VerifyBytes(b)
		if err != nil {
			output.WriteError(jsonMode, err)
			return 1
		}
		return renderRecord(res, nil, jsonMode)
	}

	opts, err := ident.resolve()
	if err != nil {
		output.WriteError(jsonMode, err)
		return 1
	}
	res, err := record.VerifyBytesWithIdentity(b, opts)
	if err != nil {
		output.WriteError(jsonMode, err)
		return 1
	}
	// Step 1: on a record that is not cryptographically sound the identity walk
	// does not run at all, so the block says "not evaluated" rather than
	// reporting zero attestations — which would read as "checked, found none".
	ev := &identityEvaluation{
		Evaluated:          res.Valid,
		IssuerKeys:         len(opts.IssuerKeys),
		EvaluatedAt:        opts.At.UTC().Format(time.RFC3339),
		AttestationEntries: len(res.IdentityOutcomes),
	}
	return renderRecord(res, ev, jsonMode)
}

// identityEvaluation records that the identity path RAN and what it was given,
// so a pinned issuer that finds nothing produces a sentence instead of an
// absence. Without it, "I pinned an issuer and this record carries no
// attestations" is byte-identical to "I pinned nothing" — which is the shape of
// the defect this file was changed to fix.
//
// It is emitted only when --issuer was supplied, and that is what keeps the
// unpinned JSON byte-identical to plain VerifyBytes.
type identityEvaluation struct {
	Evaluated          bool   `json:"evaluated"` // false ⇒ the record was not sound, so no walk happened
	IssuerKeys         int    `json:"issuer_keys"`
	EvaluatedAt        string `json:"evaluated_at"`
	AttestationEntries int    `json:"attestation_entries"` // one per identity entry found, verified or not
}

// recordVerifyOut is the JSON shape of the pinned path: the ordinary
// VerifyResult, promoted, plus the evaluation block. The unpinned path marshals
// the VerifyResult directly and never reaches this type.
type recordVerifyOut struct {
	*record.VerifyResult
	IdentityEvaluation *identityEvaluation `json:"identity_evaluation,omitempty"`
}

// renderRecord prints the verdict and returns the exit code. ev is nil on the
// unpinned path, and every identity line is behind that nil check — so with no
// issuer pinned this function emits exactly the bytes it emitted before the
// identity layer existed.
func renderRecord(res *record.VerifyResult, ev *identityEvaluation, jsonMode bool) int {
	if jsonMode {
		if ev == nil {
			_ = output.WriteJSON(res)
		} else {
			_ = output.WriteJSON(recordVerifyOut{VerifyResult: res, IdentityEvaluation: ev})
		}
		if res.Valid {
			return 0
		}
		return 1
	}

	if !res.Valid {
		output.WriteHuman("TAMPERED — %s\n", res.Reason)
		if ev != nil {
			output.WriteHuman("  identity: %d issuer key(s) pinned — not evaluated: bindings are not surfaced for a record that is not cryptographically sound\n", ev.IssuerKeys)
		}
		return 1
	}
	output.WriteHuman("VALID — chain intact, %d entr%s, %d signature(s) verified\n",
		res.Entries, plural(res.Entries, "y", "ies"), len(res.Signers))
	output.WriteHuman("  room: %s\n  head: %s\n", res.Room, res.HeadHash)
	for _, s := range res.Signers {
		output.WriteHuman("  signed: %s\n", s)
	}
	if ev != nil {
		writeIdentityBlock(res, ev)
	}
	return 0
}

// writeIdentityBlock prints what the pinned issuer keys did and did not verify.
//
// IT BRANCHES ON ReasonClass, NEVER ON Valid ALONE, and that is normative rather
// than stylistic (§5.2). An unconfigured verifier, an authority nobody pinned, an
// expired credential and a forged one all carry Valid=false, and rendering them
// the same way would say something about a person that the software did not
// check. unconfigured and unanchored are facts about THIS verifier's setup: they
// print as asserted-not-verified, never as a credential failure. forged is the
// one that is never routine, and it is the only line here that shouts.
func writeIdentityBlock(res *record.VerifyResult, ev *identityEvaluation) {
	output.WriteHuman("  identity: %d issuer key(s) pinned, evaluated at %s", ev.IssuerKeys, ev.EvaluatedAt)
	if ev.AttestationEntries == 0 {
		output.WriteHuman(" — this record carries no identity attestations\n")
		return
	}
	output.WriteHuman(" — %d attestation entr%s\n", ev.AttestationEntries, plural(ev.AttestationEntries, "y", "ies"))

	for _, subject := range sortedBindingSubjects(res) {
		for _, v := range res.IdentityBindings[subject] {
			output.WriteHuman("    verified: %s (%s) — subject %s\n", v.Principal, v.PrincipalType, v.Subject)
			output.WriteHuman("      roles: %s\n      window: %s .. %s   serial: %s\n",
				strings.Join(v.Roles, ", "), v.NotBefore, v.NotAfter, v.Serial)
			for _, by := range v.VerifiedBy {
				output.WriteHuman("      verified by pinned issuer: %s\n", by)
			}
		}
	}
	// The ones that did not verify. They are printed from IdentityOutcomes rather
	// than inferred from the absence of a binding, because an attestation that
	// failed must be visible: absent, it is indistinguishable from one that was
	// never carried at all.
	for _, o := range res.IdentityOutcomes {
		if o.Valid {
			continue
		}
		who := o.Subject
		if who == "" {
			who = "(no readable subject)"
		}
		switch o.ReasonClass {
		case attest.ClassUnconfigured, attest.ClassUnanchored:
			output.WriteHuman("    asserted, not verified (entry %d): subject %s\n", o.Seq, who)
			output.WriteHuman("      %s — a statement about this verifier's trust anchors, not about the subject\n", identityNote(o))
		case attest.ClassLifecycle:
			output.WriteHuman("    credential state (entry %d): subject %s — %s\n", o.Seq, who, o.Reason)
			output.WriteHuman("      %s\n", identityNote(o))
		case attest.ClassForged:
			output.WriteHuman("    SECURITY (entry %d): subject %s — %s\n", o.Seq, who, o.Reason)
			output.WriteHuman("      %s\n", identityNote(o))
		default: // malformed, and anything a later version adds
			output.WriteHuman("    broken attestation (entry %d): %s\n", o.Seq, o.Reason)
			output.WriteHuman("      %s\n", identityNote(o))
		}
	}
}

// identityNote is the outcome's own sentence, falling back to the code when the
// verifier supplied no detail.
func identityNote(o record.IdentityOutcome) string {
	if o.Detail != "" {
		return o.Detail
	}
	return string(o.Reason)
}

// sortedBindingSubjects lists the bound subject fingerprints in sorted order, so
// two runs over one record print the same thing.
func sortedBindingSubjects(res *record.VerifyResult) []string {
	out := make([]string, 0, len(res.IdentityBindings))
	for s := range res.IdentityBindings {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
