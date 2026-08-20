package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/output"
)

// verifyArtifact is the dispatcher behind `netherchat verify <file>.json`. It
// reads the file once, sniffs which attestation artifact it is by its
// discriminator key, and verifies accordingly — a sealed record (§1.4), a signed
// roster (§1.4), or a scuttle receipt (§1.5). Each verifier exits 0 for VALID and
// 1 for INVALID/error, so the command composes in scripts and CI.
//
// TWO OF THESE FOUR BRANCHES CAN CONSUME --issuer AND --at, and the other two
// say so instead of swallowing them. A record CARRIES attestations, so it takes
// both flags and routes them to VerifyBytesWithIdentity; the standalone identity
// artifact takes both by definition. A roster and a receipt carry no identity
// content at all, so a pinned issuer could only be ignored there — and a
// security flag that a command accepts and ignores is precisely the defect this
// dispatcher was changed to fix. It is refused, loudly, rather than dropped.
func verifyArtifact(path string, jsonMode bool, ident identityVerifyOpts) int {
	b, err := os.ReadFile(path)
	if err != nil {
		output.WriteError(jsonMode, err)
		return 1
	}
	kind := detectArtifact(b)
	if (kind == "roster" || kind == "receipt") && ident.pinned() {
		output.WriteError(jsonMode, fmt.Errorf(
			"--issuer does not apply to a %s attestation: it carries no identity content, so a pinned issuer would check nothing", kind))
		return 2
	}
	switch kind {
	case "roster":
		return verifyRosterBytes(b, jsonMode)
	case "receipt":
		return verifyReceiptBytes(b, jsonMode)
	case "identity":
		return verifyIdentityBytes(b, jsonMode, ident)
	default:
		// A sealed record carries "netherchat_record"; an unrecognized shape falls
		// through to the record verifier, which reports a clear parse error.
		return verifyRecordBytes(b, jsonMode, ident)
	}
}

// detectArtifact sniffs the artifact type from its top-level discriminator key
// without committing to a full decode.
func detectArtifact(b []byte) string {
	var probe struct {
		Record   string `json:"netherchat_record"`
		Roster   string `json:"netherchat_roster"`
		Receipt  string `json:"netherchat_receipt"`
		Identity string `json:"netherchat_identity"`
	}
	_ = json.Unmarshal(b, &probe)
	switch {
	case probe.Roster != "":
		return "roster"
	case probe.Receipt != "":
		return "receipt"
	case probe.Identity != "":
		return "identity"
	default:
		return "record"
	}
}

// verifyRosterBytes parses and verifies a roster attestation, printing the
// verdict and returning the exit code.
//
// It prints a member COUNT and the signer fingerprints, and deliberately prints
// no member names and no SAS-verified marks. That is not an omission to fix
// later: only the member fingerprints enter set_hash, so the names and the
// `verified` flags in the artifact are carried but unsigned, and printing them
// under a line that begins "VALID roster" would present unchecked fields as
// verified ones. RosterResult carries no names for the same reason.
func verifyRosterBytes(b []byte, jsonMode bool) int {
	r, err := attest.ParseRoster(b)
	if err != nil {
		output.WriteError(jsonMode, err)
		return 1
	}
	res, err := attest.VerifyRoster(r)
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
		output.WriteHuman("INVALID roster — %s\n", res.Reason)
		return 1
	}
	output.WriteHuman("VALID roster — %d member%s, %d signature(s) verified\n",
		res.Members, plural(res.Members, "", "s"), len(res.Signers))
	output.WriteHuman("  room: %s  epoch: %d\n  set_hash: %s\n", res.Room, res.Epoch, res.SetHash)
	for _, s := range res.Signers {
		output.WriteHuman("  signed: %s\n", s)
	}
	return 0
}

// verifyReceiptBytes parses and verifies a scuttle receipt, printing the verdict
// and returning the exit code.
func verifyReceiptBytes(b []byte, jsonMode bool) int {
	r, err := attest.ParseReceipt(b)
	if err != nil {
		output.WriteError(jsonMode, err)
		return 1
	}
	res, err := attest.VerifyReceipt(r)
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
		output.WriteHuman("INVALID receipt — %s\n", res.Error)
		return 1
	}
	output.WriteHuman("VALID receipt — room %s scuttled at %s, %s, %d signature(s) verified\n",
		res.Room, res.ScuttledAt, res.Reason, len(res.Signers))
	output.WriteHuman("  receipt_hash: %s\n", res.ReceiptHash)
	for _, s := range res.Signers {
		output.WriteHuman("  signed: %s\n", s)
	}
	return 0
}
