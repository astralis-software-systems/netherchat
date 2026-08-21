package attest

import (
	"encoding/base64"
	"sort"
	"strings"
	"testing"
)

// THE SAME DEFECT, THE THIRD TIME — WHICH MAKES IT A CLASS, NOT A COINCIDENCE.
//
// VerifyRoster returned on the first signature that did not verify and reached
// them by ranging over a Go map, so the fingerprint it named was a coin flip. It
// was fixed in Phase 2 (sortedKeys), and the tamper test that was supposed to
// catch it was found not to tamper at all — the second instance, in a different
// form.
//
// VerifyReceipt was noted then as having the same shape and left alone. It is the
// third, and it is verbatim: the same loop, over the same kind of map, returning
// on the same first failure, with the fingerprint interpolated into the same kind
// of sentence. A receipt is the artifact a room's destruction rests on, so "which
// co-signature is bad" is exactly the question an operator brings to it.
//
// These two tests mirror roster_order_test.go deliberately. A defect that recurs
// in three places gets a guard that recurs with it.

// TestVerifyReceiptNamesTheSameSignatureEveryRun corrupts BOTH signatures and
// requires the LOWER fingerprint to be named. One bad signature cannot tell a
// sorted walk from a random one, which is exactly why this went unnoticed.
func TestVerifyReceiptNamesTheSameSignatureEveryRun(t *testing.T) {
	r := makeReceipt(t, "inc-3f9a", "manual", 2, true)

	fprs := make([]string, 0, len(r.Signatures))
	for fpr := range r.Signatures {
		fprs = append(fprs, fpr)
	}
	sort.Strings(fprs)
	if len(fprs) != 2 {
		t.Fatalf("fixture has %d signatures, want 2", len(fprs))
	}
	for _, fpr := range fprs {
		raw, err := base64.StdEncoding.DecodeString(r.Signatures[fpr])
		if err != nil {
			t.Fatal(err)
		}
		raw[0] ^= 0xff
		r.Signatures[fpr] = base64.StdEncoding.EncodeToString(raw)
	}

	res, err := VerifyReceipt(r)
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid {
		t.Fatal("two corrupted signatures must not verify")
	}
	if !strings.Contains(res.Error, fprs[0]) {
		t.Fatalf("Error names the wrong signature; with signatures reached in sorted order it must\n"+
			"name the lower fingerprint %s, not the higher %s. A verifier whose reported reason\n"+
			"depends on Go's map iteration order gives an operator nothing to act on.\n  Error: %s",
			fprs[0], fprs[1], res.Error)
	}
}

// TestVerifyReceiptFailureReasonIsStableAcrossRuns verifies the same input many
// times in one process and requires every answer to be byte-identical. Go
// re-seeds map iteration on every range statement, not once per process, so
// repeating the call inside one test exercises the randomness directly.
func TestVerifyReceiptFailureReasonIsStableAcrossRuns(t *testing.T) {
	r := makeReceipt(t, "inc-3f9a", "manual", 4, true)
	for fpr, sigB64 := range r.Signatures {
		raw, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			t.Fatal(err)
		}
		raw[0] ^= 0xff
		r.Signatures[fpr] = base64.StdEncoding.EncodeToString(raw)
	}

	first := ""
	for i := 0; i < 64; i++ {
		res, err := VerifyReceipt(r)
		if err != nil {
			t.Fatal(err)
		}
		if res.Valid {
			t.Fatal("four corrupted signatures must not verify")
		}
		if i == 0 {
			first = res.Error
			continue
		}
		if res.Error != first {
			t.Fatalf("VerifyReceipt reported two different errors for the same artifact:\n"+
				"  run 0:  %s\n  run %d:  %s\n"+
				"The verdict is deterministic; the reason must be too.", first, i, res.Error)
		}
	}
}
