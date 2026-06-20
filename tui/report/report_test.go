package report

import (
	"strings"
	"testing"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
	"github.com/salehkreiner/netherchat/tui/record"
)

// buildSealed assembles a small, validly-signed sealed record for the report tests.
func buildSealed(t *testing.T) *record.SealedRecord {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	chain := record.NewChain()
	author := record.Author{ID: id.Fingerprint(), Name: "alice", Key: id.SignPub, Sign: id.Sign}
	for _, e := range []struct{ kind, who, body string }{
		{record.KindDecision, "", "rolled back to v2.3.1"},
		{record.KindAction, "bob", "watch the dashboards"},
		{record.KindNote, "", "db CPU pinned at 100%"},
	} {
		if _, err := chain.AppendNew(author, e.kind, e.who, e.body); err != nil {
			t.Fatalf("append %s: %v", e.kind, err)
		}
	}
	head := chain.Head()
	sig, err := id.Sign(protocol.SealSigningBytes("ops", head))
	if err != nil {
		t.Fatalf("sign seal: %v", err)
	}
	sigs := map[string][]byte{id.Fingerprint(): sig}
	keys := map[string][]byte{id.Fingerprint(): id.SignPub}
	return record.NewSealedRecord("ops", id.Fingerprint(), chain.Entries(), head, sigs, keys)
}

func TestRenderHTMLValidSelfContained(t *testing.T) {
	rec := buildSealed(t)
	res, err := record.Verify(rec)
	if err != nil || !res.Valid {
		t.Fatalf("freshly built record should verify: err=%v reason=%q", err, res.Reason)
	}
	out := RenderHTML(rec, res, Options{})

	if !strings.HasPrefix(out, "<!DOCTYPE html>") || !strings.Contains(out, "</html>") {
		t.Fatal("output is not a complete HTML document")
	}
	if !strings.Contains(out, "rolled back to v2.3.1") {
		t.Fatal("timeline missing the decision")
	}
	if !strings.Contains(out, "hash chain") || !strings.Contains(out, "intact") {
		t.Fatal("missing the ✓-intact hash-chain status")
	}
	if !strings.Contains(out, "<svg") {
		t.Fatal("missing the inline QR svg")
	}
	// Self-contained: no external fetches (the SVG xmlns is not a fetch).
	for _, bad := range []string{`src="http`, `href="http`, "<link", "@import", "cdn."} {
		if strings.Contains(out, bad) {
			t.Fatalf("report is not self-contained: contains %q", bad)
		}
	}
}

func TestRenderHTMLTampered(t *testing.T) {
	rec := buildSealed(t)
	rec.Entries[1].Body = "TAMPERED action item" // invalidates entry 1's signature
	res, _ := record.Verify(rec)
	if res.Valid {
		t.Fatal("a tampered record must not verify")
	}
	out := RenderHTML(rec, res, Options{})
	if !strings.Contains(out, "✗") || !strings.Contains(out, "broken") {
		t.Fatal("a tampered report must show a broken hash chain")
	}
}

func TestExecutiveHidesTechnicalDetail(t *testing.T) {
	rec := buildSealed(t)
	res, _ := record.Verify(rec)
	out := RenderHTML(rec, res, Options{Executive: true})

	if strings.Contains(out, "SHA256:") {
		t.Fatal("executive report must not show fingerprints")
	}
	if strings.Contains(out, "head_hash") {
		t.Fatal("executive report must not show hashes")
	}
	if strings.Contains(out, "db CPU pinned") {
		t.Fatal("executive report must omit note entries")
	}
	if !strings.Contains(out, "rolled back to v2.3.1") {
		t.Fatal("executive report should show decisions")
	}
	if !strings.Contains(out, "watch the dashboards") {
		t.Fatal("executive report should show actions")
	}
}

func TestRenderMarkdownValid(t *testing.T) {
	rec := buildSealed(t)
	res, _ := record.Verify(rec)
	out := RenderMarkdown(rec, res, Options{})
	for _, want := range []string{"# Incident timeline", "## Timeline", "## Seal signatures", "| fingerprint | status |", "rolled back to v2.3.1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("markdown report missing %q", want)
		}
	}
}

func TestChainStatusEntryExtraction(t *testing.T) {
	sym, text, _ := chainStatus(&record.VerifyResult{Valid: false, Reason: "entry 2 prev_hash does not link to the previous entry"})
	if sym != "✗" || !strings.Contains(text, "broken at entry 2") {
		t.Fatalf("chainStatus(broken) = %q / %q", sym, text)
	}
	sym2, text2, _ := chainStatus(&record.VerifyResult{Valid: true})
	if sym2 != "✓" || text2 != "intact" {
		t.Fatalf("chainStatus(valid) = %q / %q", sym2, text2)
	}
}

// buildWithArtifact assembles a sealed record whose chain includes an "artifact"
// entry (an agent-produced artifact a human approved), for the NC-W1 report tests.
func buildWithArtifact(t *testing.T) *record.SealedRecord {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	chain := record.NewChain()
	author := record.Author{ID: id.Fingerprint(), Name: "alice", Key: id.SignPub, Sign: id.Sign}
	body, err := record.MarshalArtifactBody(record.ArtifactMeta{
		Source:       "requirements-agent",
		ArtifactRef:  "Q3-requirements",
		ArtifactHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		ApproverFpr:  id.Fingerprint(),
		ProposedAt:   "2026-06-12T10:00:00Z",
		ApprovedAt:   "2026-06-12T10:03:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.AppendNew(author, record.KindArtifact, "", body); err != nil {
		t.Fatalf("append artifact: %v", err)
	}
	head := chain.Head()
	sig, err := id.Sign(protocol.SealSigningBytes("ops", head))
	if err != nil {
		t.Fatal(err)
	}
	sigs := map[string][]byte{id.Fingerprint(): sig}
	keys := map[string][]byte{id.Fingerprint(): id.SignPub}
	return record.NewSealedRecord("ops", id.Fingerprint(), chain.Entries(), head, sigs, keys)
}

func TestArtifactRendersInFullReport(t *testing.T) {
	rec := buildWithArtifact(t)
	res, err := record.Verify(rec)
	if err != nil || !res.Valid {
		t.Fatalf("artifact record should verify: err=%v reason=%q", err, res.Reason)
	}
	out := RenderHTML(rec, res, Options{})
	for _, want := range []string{
		"AI-drafted artifact approved",
		"requirements-agent",
		"Q3-requirements",
		"0123456789abcdef...", // hash shortened to 16 chars
		"Recorded by: alice",
		// This fixture is a LEGACY artifact (no offline approval proofs), so the report
		// must NOT present an approver as authoritative — it says so plainly (GAP-1).
		"Approver attribution not offline-verified",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("full report missing %q", want)
		}
	}
	if strings.Contains(out, "Approved by (verified)") {
		t.Fatal("a legacy artifact (no proofs) must not claim a verified approver")
	}
	// The full hash must never appear — only the 16-char prefix.
	if strings.Contains(out, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") {
		t.Fatal("full report leaked the entire artifact hash")
	}
}

// buildWithVerifiedArtifact assembles a sealed record whose artifact entry carries a
// real, offline-verifiable approval proof by a DISTINCT approver (bob) — the
// new-format two-person case the report renders authoritatively.
func buildWithVerifiedArtifact(t *testing.T) *record.SealedRecord {
	t.Helper()
	alice, err := crypto.GenerateIdentity() // writer / entry author
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	bob, err := crypto.GenerateIdentity() // distinct approver
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	const pid, nonce = "p1prop", "n1nonce"
	const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	body, err := record.MarshalArtifactBody(record.ArtifactMeta{
		Source: "requirements-agent", ArtifactRef: "Q3-requirements", ArtifactHash: hash,
		ApproverFpr: alice.Fingerprint(), ProposalID: pid, Nonce: nonce, ProposerFpr: "SHA256:agent",
		ProposedAt: "2026-06-12T10:00:00Z", ApprovedAt: "2026-06-12T10:03:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	chain := record.NewChain()
	author := record.Author{ID: alice.Fingerprint(), Name: "alice", Key: alice.SignPub, Sign: alice.Sign}
	if _, err := chain.Append(author, record.EntrySpec{Kind: record.KindArtifact, Body: body}); err != nil {
		t.Fatalf("append artifact: %v", err)
	}
	s := record.NewSealer("ops", author.ID, chain.Entries())
	if err := s.Sign(author); err != nil {
		t.Fatalf("seal: %v", err)
	}
	bobSig, err := bob.Sign(protocol.ArtifactApprovalSigningBytes(pid, hash, bob.Fingerprint(), nonce))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddArtifactApproval(pid, bob.SignPub, bobSig); err != nil {
		t.Fatalf("add approval: %v", err)
	}
	rec, err := s.Finalize()
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	return rec
}

func TestArtifactVerifiedApproverRendersAuthoritatively(t *testing.T) {
	rec := buildWithVerifiedArtifact(t)
	res, err := record.Verify(rec)
	if err != nil || !res.Valid {
		t.Fatalf("verified artifact record should verify: err=%v reason=%q", err, res.Reason)
	}
	out := RenderHTML(rec, res, Options{})
	if !strings.Contains(out, "Approved by (verified):") {
		t.Error("a proofs-bearing artifact must render an authoritative verified approver")
	}
	if strings.Contains(out, "Approver attribution not offline-verified") {
		t.Error("a proofs-bearing artifact must not be marked unverified")
	}
	md := RenderMarkdown(rec, res, Options{})
	if !strings.Contains(md, "approved by") {
		t.Error("markdown report should render the verified approver")
	}
}

func TestArtifactExecutiveHidesHashAndFpr(t *testing.T) {
	rec := buildWithArtifact(t)
	res, _ := record.Verify(rec)
	out := RenderHTML(rec, res, Options{Executive: true})
	// The human-readable facts are present...
	for _, want := range []string{"Q3-requirements", "requirements-agent", "alice"} {
		if !strings.Contains(out, want) {
			t.Errorf("executive report missing %q", want)
		}
	}
	// ...but no hash and no fingerprint.
	if strings.Contains(out, "0123456789abcdef") {
		t.Fatal("executive report must not show the artifact hash")
	}
	if strings.Contains(out, "SHA256:") {
		t.Fatal("executive report must not show a fingerprint")
	}
}

func TestQRSVGInline(t *testing.T) {
	svg := QRSVG("netherchat verify record.json")
	if !strings.Contains(svg, "<svg") || !strings.Contains(svg, "<rect") {
		t.Fatal("QR is not an inline SVG of rects")
	}
	if strings.Contains(svg, "src=") {
		t.Fatal("QR SVG must not reference an external source")
	}
}
