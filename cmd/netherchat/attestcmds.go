package main

import (
	"encoding/json"
	"os"

	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/output"
)

// verifyArtifact is the dispatcher behind `netherchat verify <file>.json`. It
// reads the file once, sniffs which attestation artifact it is by its
// discriminator key, and verifies accordingly — a sealed record (§1.4), a signed
// roster (§1.4), or a scuttle receipt (§1.5). Each verifier exits 0 for VALID and
// 1 for INVALID/error, so the command composes in scripts and CI.
func verifyArtifact(path string, jsonMode bool) int {
	b, err := os.ReadFile(path)
	if err != nil {
		output.WriteError(jsonMode, err)
		return 1
	}
	switch detectArtifact(b) {
	case "roster":
		return verifyRosterBytes(b, jsonMode)
	default:
		// A sealed record carries "netherchat_record"; an unrecognized shape falls
		// through to the record verifier, which reports a clear parse error.
		return verifyRecordBytes(b, jsonMode)
	}
}

// detectArtifact sniffs the artifact type from its top-level discriminator key
// without committing to a full decode.
func detectArtifact(b []byte) string {
	var probe struct {
		Record  string `json:"netherchat_record"`
		Roster  string `json:"netherchat_roster"`
		Receipt string `json:"netherchat_receipt"`
	}
	_ = json.Unmarshal(b, &probe)
	switch {
	case probe.Roster != "":
		return "roster"
	case probe.Receipt != "":
		return "receipt"
	default:
		return "record"
	}
}

// verifyRosterBytes parses and verifies a roster attestation, printing the
// verdict and returning the exit code.
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
