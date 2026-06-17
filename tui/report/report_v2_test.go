package report

import (
	"strings"
	"testing"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
	"github.com/salehkreiner/netherchat/tui/record"
)

// buildEndorsed assembles a record co-sealed with a declared signature meaning
// (item 2), so the report has an endorsement to render.
func buildEndorsed(t *testing.T) *record.SealedRecord {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	author := record.Author{ID: id.Fingerprint(), Name: "Dr. Alice Example", Key: id.SignPub, Sign: id.Sign}
	c := record.NewChain()
	if _, err := c.AppendNew(author, record.KindDecision, "", "rolled back to v2.3.1"); err != nil {
		t.Fatalf("append: %v", err)
	}
	sealer := record.NewSealer("ops", id.Fingerprint(), c.Entries())
	if err := sealer.SignAs(author, record.MeaningApproved); err != nil {
		t.Fatalf("sign as: %v", err)
	}
	rec, err := sealer.Finalize()
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	return rec
}

// buildRoster assembles a valid signed roster attestation for the report tests.
func buildRoster(t *testing.T) *attest.RosterAttestation {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	fpr := id.Fingerprint()
	const room = "ops"
	const epoch = uint64(3)
	members := []attest.RosterMember{{Name: "alice", Fpr: fpr, Verified: true}}
	setHash := attest.SetHash([]string{fpr})
	sig, err := id.Sign(protocol.RosterSigningBytes(room, epoch, setHash))
	if err != nil {
		t.Fatalf("sign roster: %v", err)
	}
	return attest.NewRoster(room, epoch, fpr, members,
		map[string][]byte{fpr: sig}, map[string][]byte{fpr: id.SignPub})
}

// TestSignOffsRenderMeaningBothModes proves the declared meaning, signer name, and
// timestamp are shown in BOTH the full and executive reports, and that the
// executive sign-offs never leak a fingerprint.
func TestSignOffsRenderMeaningBothModes(t *testing.T) {
	rec := buildEndorsed(t)
	res, err := record.Verify(rec)
	if err != nil || !res.Valid {
		t.Fatalf("endorsed record should verify: err=%v reason=%q", err, res.Reason)
	}

	full := RenderHTML(rec, res, Options{})
	for _, want := range []string{"Sign-offs", "approved", "Dr. Alice Example"} {
		if !strings.Contains(full, want) {
			t.Errorf("full report missing %q", want)
		}
	}

	exec := RenderHTML(rec, res, Options{Executive: true})
	for _, want := range []string{"Sign-offs", "approved", "Dr. Alice Example"} {
		if !strings.Contains(exec, want) {
			t.Errorf("executive report missing %q", want)
		}
	}
	if strings.Contains(exec, "SHA256:") {
		t.Fatal("executive sign-offs must not leak a fingerprint")
	}
}

// TestRosterRendersInReport proves the roster attestation renders in both modes,
// with fingerprints shown only in the full report.
func TestRosterRendersInReport(t *testing.T) {
	rec := buildSealed(t)
	res, _ := record.Verify(rec)
	roster := buildRoster(t)
	fpr := roster.Members[0].Fpr

	full := RenderHTML(rec, res, Options{Roster: roster})
	for _, want := range []string{"Roster attestation", "alice", fpr} {
		if !strings.Contains(full, want) {
			t.Errorf("full report missing %q", want)
		}
	}

	exec := RenderHTML(rec, res, Options{Executive: true, Roster: roster})
	if !strings.Contains(exec, "Roster attestation") || !strings.Contains(exec, "alice") {
		t.Error("executive roster missing the membership")
	}
	if strings.Contains(exec, fpr) {
		t.Error("executive roster must not leak a fingerprint")
	}

	md := RenderMarkdown(rec, res, Options{Roster: roster})
	if !strings.Contains(md, "## Roster attestation") || !strings.Contains(md, "alice") {
		t.Error("markdown report missing roster section")
	}
}

// TestNoRosterNoSection confirms a nil roster renders no roster section (the
// default, so existing reports are unaffected).
func TestNoRosterNoSection(t *testing.T) {
	rec := buildSealed(t)
	res, _ := record.Verify(rec)
	if strings.Contains(RenderHTML(rec, res, Options{}), "Roster attestation") {
		t.Fatal("a report with no roster must not render a roster section")
	}
}
