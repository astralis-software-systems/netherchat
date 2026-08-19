package attest

import (
	"encoding/base64"
	"sort"
	"strings"
	"testing"
)

// TestVerifyRosterNamesTheSameSignatureEveryRun pins the fix for a
// non-reproducible failure reason.
//
// VerifyRoster returns on the FIRST signature that does not verify, and it used
// to reach them by ranging over r.Signatures — a Go map, whose iteration order
// is deliberately randomized. The verdict was never in doubt (every signature
// has to verify, so any failure is fatal whichever one is met first), but the
// fingerprint named in Reason was a coin flip. Two operators looking at the same
// file, or the same operator looking twice, got different answers to "which
// signature is bad".
//
// So: corrupt BOTH signatures, and assert the lower fingerprint is the one
// named. One bad signature could not tell the two orders apart, which is why
// this went unnoticed. Ranging over the map again would fail this roughly half
// the time — see TestVerifyRosterFailureReasonIsStableAcrossRuns below, which
// closes even that gap.
func TestVerifyRosterNamesTheSameSignatureEveryRun(t *testing.T) {
	r := makeRoster(t, "inc-3f9a", 3, 2)

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

	res, err := VerifyRoster(r)
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid {
		t.Fatal("two corrupted signatures must not verify")
	}
	if !strings.Contains(res.Reason, fprs[0]) {
		t.Fatalf("Reason names %q; with signatures reached in sorted order it must name the\n"+
			"lower fingerprint %s, not the higher %s. A verifier whose reported reason depends\n"+
			"on Go's map iteration order gives an operator nothing to act on.\n  Reason: %s",
			"the wrong signature", fprs[0], fprs[1], res.Reason)
	}
}

// TestVerifyRosterFailureReasonIsStableAcrossRuns verifies the same input many
// times in one process and requires every answer to be byte-identical.
//
// The test above asserts the CORRECT signature is named; this one asserts the
// answer does not move, which is the property that was actually broken. Go
// re-seeds map iteration on every range statement, not once per process, so
// repeating the call inside one test exercises the randomness directly: against
// the old map-ranging loop this failed within a handful of iterations.
func TestVerifyRosterFailureReasonIsStableAcrossRuns(t *testing.T) {
	r := makeRoster(t, "inc-3f9a", 3, 4)
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
		res, err := VerifyRoster(r)
		if err != nil {
			t.Fatal(err)
		}
		if res.Valid {
			t.Fatal("four corrupted signatures must not verify")
		}
		if i == 0 {
			first = res.Reason
			continue
		}
		if res.Reason != first {
			t.Fatalf("VerifyRoster reported two different reasons for the same artifact:\n"+
				"  run 0:  %s\n  run %d:  %s\n"+
				"The verdict is deterministic; the reason must be too.", first, i, res.Reason)
		}
	}
}
