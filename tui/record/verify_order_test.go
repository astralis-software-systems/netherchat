package record

import (
	"crypto/ed25519"
	"encoding/base64"
	"sort"
	"strings"
	"testing"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// THE CLASS SWEEP DID NOT STOP AT A PACKAGE BOUNDARY.
//
// Phase 3c was asked to fix VerifyReceipt (the third instance of "iterate a Go
// map, return on the first failure, name the one you happened to reach") and to
// check whether anything ELSE in tui/attest had the same shape. Nothing else in
// tui/attest did — attest's own identity and revocation verifiers already collect
// per-key outcomes and sort them, which is the pattern the sweep was measuring
// against.
//
// Two more were one import away, in tui/record, and a sweep that stopped at a
// directory when the same defect was next door would have been a sweep about
// directories:
//
//	Verify's seal-signature loop        ranges r.Signatures (map), returns on the
//	                                    first bad one, names it in Reason
//	verifyArtifactApprovals             ranges r.ArtifactApprovals (map), returns
//	                                    an error on the first bad proposal, names
//	                                    it in the error
//
// The second one is the worse of the two: a record's whole VerifyResult.Reason is
// that error string, and a record with two malformed proposals told two different
// stories to two runs of `netherchat verify`.
//
// The verdict was never in question in any of the five. What moved was the
// sentence an operator is expected to act on.

// TestSealSignatureFailureNamesTheSameSignerEveryRun corrupts every seal
// signature and requires the lowest fingerprint to be the one Reason names.
func TestSealSignatureFailureNamesTheSameSignerEveryRun(t *testing.T) {
	rec, _, _ := buildValid(t)

	fprs := make([]string, 0, len(rec.Signatures))
	for fpr := range rec.Signatures {
		fprs = append(fprs, fpr)
	}
	sort.Strings(fprs)
	if len(fprs) != 2 {
		t.Fatalf("fixture has %d seal signatures, want 2", len(fprs))
	}
	for _, fpr := range fprs {
		raw, err := base64.StdEncoding.DecodeString(rec.Signatures[fpr])
		if err != nil {
			t.Fatal(err)
		}
		raw[0] ^= 0xff
		rec.Signatures[fpr] = base64.StdEncoding.EncodeToString(raw)
	}

	first := ""
	for i := 0; i < 64; i++ {
		res, err := Verify(rec)
		if err != nil {
			t.Fatal(err)
		}
		if res.Valid {
			t.Fatal("two corrupted seal signatures must not verify")
		}
		if i == 0 {
			first = res.Reason
			if !strings.Contains(first, fprs[0]) {
				t.Fatalf("Reason names the wrong signer; reached in sorted order it must name the\n"+
					"lower fingerprint %s, not the higher %s.\n  Reason: %s", fprs[0], fprs[1], first)
			}
			continue
		}
		if res.Reason != first {
			t.Fatalf("Verify reported two different reasons for the same record:\n"+
				"  run 0:  %s\n  run %d:  %s\n"+
				"The verdict is deterministic; the reason must be too.", first, i, res.Reason)
		}
	}
}

// TestArtifactApprovalFailureNamesTheSameProposalEveryRun. Two artifact entries,
// each with a malformed approval proof: which proposal id the record blames must
// not be a coin flip.
func TestArtifactApprovalFailureNamesTheSameProposalEveryRun(t *testing.T) {
	alice, _, _ := fixedAuthor(11, "alice")
	c := NewChain()
	ids := []string{"prop-aaaa", "prop-zzzz"}
	for _, pid := range ids {
		body, err := MarshalArtifactBody(ArtifactMeta{
			Source: "requirements-agent", ArtifactRef: "RFC-" + pid,
			ArtifactHash: "9f2b7c1d", ProposalID: pid, Nonce: "nonce-" + pid,
			ProposerFpr: "SHA256:agent", ProposedAt: "2026-06-01T14:00:00Z", ApprovedAt: "2026-06-01T14:01:00Z",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Append(alice, EntrySpec{Kind: KindArtifact, Body: body}); err != nil {
			t.Fatal(err)
		}
	}
	head := c.Head()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := id.Sign(protocol.SealSigningBytes("ops", head))
	if err != nil {
		t.Fatal(err)
	}
	rec := NewSealedRecord("ops", id.Fingerprint(), c.Entries(), head,
		map[string][]byte{id.Fingerprint(): sig}, map[string][]byte{id.Fingerprint(): id.SignPub})

	// A malformed approver key under BOTH proposals: whichever is reached first is
	// the one named, and both are equally wrong.
	rec.ArtifactApprovals = map[string][]ApprovalProof{}
	for _, pid := range ids {
		rec.ArtifactApprovals[pid] = []ApprovalProof{{
			ApproverFpr: "SHA256:approver-" + pid,
			ApproverKey: base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize-1)),
			Sig:         base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
		}}
	}

	first := ""
	for i := 0; i < 64; i++ {
		res, err := Verify(rec)
		if err != nil {
			t.Fatal(err)
		}
		if res.Valid {
			t.Fatal("two malformed approval proofs must not verify")
		}
		if i == 0 {
			first = res.Reason
			if !strings.Contains(first, ids[0]) {
				t.Fatalf("Reason names the wrong proposal; reached in sorted order it must name %q,\n"+
					"not %q.\n  Reason: %s", ids[0], ids[1], first)
			}
			continue
		}
		if res.Reason != first {
			t.Fatalf("Verify blamed two different proposals for the same record:\n"+
				"  run 0:  %s\n  run %d:  %s", first, i, res.Reason)
		}
	}
}
