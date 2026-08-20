package client

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/sealedrecord"
	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/tui/record"
)

// hashOf returns the hex SHA-256 of content — exactly what a proposer would compute
// for an artifact, and the ONLY representation of the content that may cross.
func hashOf(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// waitForArtifactEntry blocks until the artifact record entry for proposalID is on
// c's chain. This — not EvArtifactSealed — is the signal that says "this proposal's
// evidence has settled here".
//
// EvArtifactSealed fires when a client counts quorum from the approvals IT has seen.
// On the one designated writer the entry is already appended by then; on every other
// client it says nothing about the entry, which the writer may not have authored yet
// and which still has to cross the wire. The writer files each approver's credential
// first and the artifact entry last over one ordered connection, so the artifact
// entry arriving means the credentials already have: it is the terminal signal for
// the proposal, which is why waiting for it is enough.
func waitForArtifactEntry(t *testing.T, c *Client, proposalID string) EvRecordEntry {
	t.Helper()
	return waitUntil[EvRecordEntry](t, c, 5*time.Second, func(e EvRecordEntry) bool {
		if e.Kind != record.KindArtifact {
			return false
		}
		meta, err := record.ParseArtifactBody(e.Body)
		return err == nil && meta.ProposalID == proposalID
	})
}

// twoClients spins up a test relay and connects two members to one room.
func twoClients(t *testing.T, room string) (relay *httptest.Server, a, b *Client) {
	t.Helper()
	relay = httptest.NewServer(server.Handler(config.Default(), quietLog()))
	t.Cleanup(relay.Close)
	a = dialClient(t, relay.URL, room, "agent")
	waitFor[EvKeyReady](t, a, 5*time.Second)
	b = dialClient(t, relay.URL, room, "alice")
	waitFor[EvKeyReady](t, b, 5*time.Second)
	// Let the agent observe alice joining, so its member set is current.
	waitFor[EvMemberJoined](t, a, 5*time.Second)
	return relay, a, b
}

// TestApproverFirstProposerSecond replicates the demo ordering: the approver joins
// the room FIRST (becoming the key distributor) and the proposer joins SECOND. The
// first member must still receive the proposal the later member sends.
func TestApproverFirstProposerSecond(t *testing.T) {
	relay := httptest.NewServer(server.Handler(config.Default(), quietLog()))
	defer relay.Close()
	alice := dialClient(t, relay.URL, "ops", "alice") // FIRST
	waitFor[EvKeyReady](t, alice, 5*time.Second)
	agent := dialClient(t, relay.URL, "ops", "agent") // SECOND
	waitFor[EvKeyReady](t, agent, 5*time.Second)
	waitFor[EvMemberJoined](t, alice, 5*time.Second) // alice sees agent join

	hash := hashOf("content")
	id, err := agent.Propose("agent", "ref", hash, "", 1)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	prop := waitFor[EvArtifactProposed](t, alice, 5*time.Second)
	if prop.ProposalID != id {
		t.Fatalf("first member did not receive the proposal: %+v", prop)
	}
}

// TestProposeIsPendingNotSealed: a proposal creates a pending item, NOT a record entry.
func TestProposeIsPendingNotSealed(t *testing.T) {
	_, agent, alice := twoClients(t, "ops")
	content := "DRAFT_REQUIREMENTS_v1_SECRET"
	hash := hashOf(content)

	id, err := agent.Propose("requirements-agent", "Q3-requirements", hash, "draft for review", 1)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	prop := waitFor[EvArtifactProposed](t, alice, 5*time.Second)
	if prop.ProposalID != id || prop.Source != "requirements-agent" || prop.ArtifactHash != hash {
		t.Fatalf("proposed event = %+v", prop)
	}
	// No record entry is written until approval reaches quorum.
	if n := len(alice.RecordEntries()); n != 0 {
		t.Fatalf("a proposal must not create a record entry, got %d", n)
	}
	if len(alice.PendingProposals()) != 1 {
		t.Fatalf("proposal should be pending on the approver")
	}
}

// TestApproveQuorum1Seals: a single human approval seals the artifact entry, and the
// artifact CONTENT never appears in the record — only its hash.
func TestApproveQuorum1Seals(t *testing.T) {
	_, agent, alice := twoClients(t, "ops")
	content := "DRAFT_REQUIREMENTS_v1_SECRET"
	hash := hashOf(content)

	id, err := agent.Propose("requirements-agent", "Q3-requirements", hash, "", 1)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	waitFor[EvArtifactProposed](t, alice, 5*time.Second)

	if err := alice.ApproveArtifact(id, ""); err != nil {
		t.Fatalf("approve: %v", err)
	}
	sealed := waitFor[EvArtifactSealed](t, alice, 5*time.Second)
	if sealed.ArtifactHash != hash || sealed.Source != "requirements-agent" {
		t.Fatalf("sealed event = %+v", sealed)
	}

	entries := alice.RecordEntries()
	if len(entries) != 1 || entries[0].Kind != record.KindArtifact {
		t.Fatalf("want one artifact entry, got %+v", entries)
	}
	meta, ok := record.ArtifactOf(entries[0])
	if !ok {
		t.Fatal("artifact entry body did not parse")
	}
	if meta.ArtifactHash != hash {
		t.Fatalf("stored hash %q != %q", meta.ArtifactHash, hash)
	}
	if meta.ApproverFpr != alice.Fingerprint() {
		t.Fatalf("approver_fpr %q != approver %q", meta.ApproverFpr, alice.Fingerprint())
	}

	// Seal and verify offline. The agent leaves so the seal finalizes immediately.
	_ = agent.Close()
	waitFor[EvMemberLeft](t, alice, 5*time.Second)
	if err := alice.Seal(); err != nil {
		t.Fatalf("seal: %v", err)
	}
	complete := waitFor[EvSealComplete](t, alice, 5*time.Second)
	res, err := record.Verify(complete.Record)
	if err != nil {
		t.Fatalf("verify err: %v", err)
	}
	if !res.Valid {
		t.Fatalf("sealed record with an artifact entry must verify: %s", res.Reason)
	}
	// The boundary law: the content never enters the record; the hash does.
	b, _ := complete.Record.Marshal()
	if strings.Contains(string(b), "DRAFT_REQUIREMENTS_v1_SECRET") {
		t.Fatal("BOUNDARY VIOLATED: artifact content is in the record")
	}
	if !strings.Contains(string(b), hash) {
		t.Fatal("the artifact hash should be in the record")
	}
}

// TestSelfApprovalRejected: the proposer (an agent, or whoever proposed) can never
// count toward its own quorum — the second law.
func TestSelfApprovalRejected(t *testing.T) {
	_, agent, alice := twoClients(t, "ops")
	id, err := agent.Propose("requirements-agent", "ref", hashOf("x"), "", 1)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	waitFor[EvArtifactProposed](t, alice, 5*time.Second)

	// The proposer's own /approve-artifact is refused outright.
	if err := agent.ApproveArtifact(id, ""); err == nil {
		t.Fatal("the proposer must not be able to approve its own proposal")
	}
	// And at the counting layer, an approval whose fingerprint equals the proposer's
	// is never counted.
	tp := &trackedProposal{
		prop:      protocol.ArtifactProposalBody{ProposalID: id, ProposerFpr: agent.Fingerprint()},
		approvers: map[string]bool{},
	}
	if tp.addApprover(agent.Fingerprint()) {
		t.Fatal("addApprover must reject the proposer's fingerprint")
	}
	if !tp.addApprover(alice.Fingerprint()) {
		t.Fatal("addApprover must accept a distinct human approver")
	}
}

// TestQuorum2NeedsTwoDistinct: quorum=2 does not seal until two DISTINCT humans
// approve; a second approval from the same human does not count.
func TestQuorum2NeedsTwoDistinct(t *testing.T) {
	relay := httptest.NewServer(server.Handler(config.Default(), quietLog()))
	defer relay.Close()
	agent := dialClient(t, relay.URL, "ops", "agent")
	waitFor[EvKeyReady](t, agent, 5*time.Second)
	alice := dialClient(t, relay.URL, "ops", "alice")
	waitFor[EvKeyReady](t, alice, 5*time.Second)
	bob := dialClient(t, relay.URL, "ops", "bob")
	waitFor[EvKeyReady](t, bob, 5*time.Second)
	waitFor[EvMemberJoined](t, agent, 5*time.Second) // alice
	waitFor[EvMemberJoined](t, agent, 5*time.Second) // bob

	hash := hashOf("the plan")
	id, err := agent.Propose("planner-agent", "plan", hash, "", 2)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	waitFor[EvArtifactProposed](t, alice, 5*time.Second)
	waitFor[EvArtifactProposed](t, bob, 5*time.Second)

	// First human approval: count 1/2, nothing sealed yet.
	if err := alice.ApproveArtifact(id, ""); err != nil {
		t.Fatalf("alice approve: %v", err)
	}
	ev := waitFor[EvArtifactApproved](t, alice, 5*time.Second)
	if ev.Count != 1 || ev.Quorum != 2 {
		t.Fatalf("first approval = %d/%d, want 1/2", ev.Count, ev.Quorum)
	}
	// Alice approving again is refused (already approved).
	if err := alice.ApproveArtifact(id, ""); err == nil {
		t.Fatal("the same human must not approve twice")
	}
	if len(alice.RecordEntries()) != 0 {
		t.Fatal("quorum not reached yet — no entry should exist")
	}

	// Second DISTINCT human: quorum reached, bob (the completer) writes the entry.
	if err := bob.ApproveArtifact(id, ""); err != nil {
		t.Fatalf("bob approve: %v", err)
	}
	waitFor[EvArtifactSealed](t, bob, 5*time.Second)
	// Bob wrote the entry; it propagates to alice over the record-entry path.
	got := waitFor[EvRecordEntry](t, alice, 5*time.Second)
	if got.Kind != record.KindArtifact {
		t.Fatalf("alice should receive the artifact entry, got kind %q", got.Kind)
	}
}

// TestQuorum2OfflineProvableTwoPerson is the client-capture end-to-end test: a
// quorum-2 artifact, once sealed, persists TWO distinct identity-bound approval
// proofs into the record, so the two-person approval is provable OFFLINE through the
// public façade (sealedrecord.VerifyBytes) — the GAP-1/GAP-2 closure.
func TestQuorum2OfflineProvableTwoPerson(t *testing.T) {
	relay := httptest.NewServer(server.Handler(config.Default(), quietLog()))
	defer relay.Close()
	agent := dialClient(t, relay.URL, "ops", "agent")
	waitFor[EvKeyReady](t, agent, 5*time.Second)
	alice := dialClient(t, relay.URL, "ops", "alice")
	waitFor[EvKeyReady](t, alice, 5*time.Second)
	bob := dialClient(t, relay.URL, "ops", "bob")
	waitFor[EvKeyReady](t, bob, 5*time.Second)
	waitFor[EvMemberJoined](t, agent, 5*time.Second) // alice
	waitFor[EvMemberJoined](t, agent, 5*time.Second) // bob

	hash := hashOf("the plan")
	id, err := agent.Propose("planner-agent", "plan", hash, "", 2)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	waitFor[EvArtifactProposed](t, alice, 5*time.Second)
	waitFor[EvArtifactProposed](t, bob, 5*time.Second)

	if err := alice.ApproveArtifact(id, ""); err != nil {
		t.Fatalf("alice approve: %v", err)
	}
	waitFor[EvArtifactApproved](t, alice, 5*time.Second)
	if err := bob.ApproveArtifact(id, ""); err != nil {
		t.Fatalf("bob approve: %v", err)
	}
	waitFor[EvArtifactSealed](t, bob, 5*time.Second)

	// Deterministically make the NON-writer the sealer (§9.6): the writer is minFpr of
	// the approver set — the same rule the production code uses — so the OTHER member
	// seals. This proves a member that did NOT author the artifact entry still holds the
	// full proof set (captured in countArtifactApproval, which every observer runs).
	writerFpr := minFpr([]string{alice.Fingerprint(), bob.Fingerprint()})
	sealer, leaver := alice, bob
	if alice.Fingerprint() == writerFpr {
		sealer, leaver = bob, alice
	}
	// The non-writer sealer must have the artifact entry on its chain before sealing —
	// and specifically that entry, not merely the first EvRecordEntry. Nobody here
	// carries a credential, so the writer files exactly one entry and the two coincide;
	// the moment an approver in this test gained a UseIdentity call the writer would
	// file credentials first and the loose wait would return on one of those, seal a
	// chain without the artifact entry, and fail on the assertions below.
	waitForArtifactEntry(t, sealer, id)

	// The proposer and the WRITER leave so the non-writer sealer finalizes alone, still
	// holding both approval proofs.
	_ = agent.Close()
	_ = leaver.Close()
	waitFor[EvMemberLeft](t, sealer, 5*time.Second)
	waitFor[EvMemberLeft](t, sealer, 5*time.Second)

	if err := sealer.Seal(); err != nil {
		t.Fatalf("seal: %v", err)
	}
	complete := waitFor[EvSealComplete](t, sealer, 5*time.Second)
	rec := complete.Record
	if sealer.Fingerprint() == writerFpr {
		t.Fatal("test setup error: the sealer must be the non-writer")
	}

	// Two distinct approval proofs were persisted under the proposal id.
	if got := len(rec.ArtifactApprovals[id]); got != 2 {
		t.Fatalf("want 2 persisted approval proofs, got %d (%v)", got, rec.ArtifactApprovals[id])
	}

	// Offline-provable two-person through the public façade.
	b, err := rec.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	res, err := sealedrecord.VerifyBytes(b)
	if err != nil || !res.Valid {
		t.Fatalf("sealed record must verify offline: err=%v reason=%q", err, res.Reason)
	}
	approvers := sealedrecord.VerifiedArtifactApprovers(res, id)
	if len(approvers) != 1 {
		t.Fatalf("want exactly one distinct approver beyond the author, got %v", approvers)
	}

	// The surfaced approver is distinct from the entry author: author + approver = two
	// distinct people who signed off, provable from the file alone.
	var artAuthor string
	for _, e := range rec.Entries {
		if e.Kind == record.KindArtifact {
			artAuthor = e.AuthorID
		}
	}
	if approvers[0] == artAuthor {
		t.Fatal("the surfaced approver must be distinct from the entry author")
	}
}

// TestRejectDiscards: /reject-artifact drops the proposal with no record entry.
func TestRejectDiscards(t *testing.T) {
	_, agent, alice := twoClients(t, "ops")
	id, err := agent.Propose("agent", "ref", hashOf("y"), "", 1)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	waitFor[EvArtifactProposed](t, alice, 5*time.Second)

	if err := alice.RejectArtifact(id, "out of scope"); err != nil {
		t.Fatalf("reject: %v", err)
	}
	rej := waitFor[EvArtifactRejected](t, agent, 5*time.Second)
	if rej.Reason != "out of scope" {
		t.Fatalf("reject reason = %q", rej.Reason)
	}
	if len(alice.RecordEntries()) != 0 || len(agent.RecordEntries()) != 0 {
		t.Fatal("a rejected proposal must not produce a record entry")
	}
	// Approving a rejected proposal fails.
	if err := alice.ApproveArtifact(id, ""); err == nil {
		t.Fatal("approving a rejected proposal should fail")
	}
}

// TestProposalExpires: a proposal that never reaches quorum is discarded after its
// window with an EvArtifactExpired and no record entry.
func TestProposalExpires(t *testing.T) {
	old := artifactProposalTTL
	artifactProposalTTL = 200 * time.Millisecond
	defer func() { artifactProposalTTL = old }()

	_, agent, alice := twoClients(t, "ops")
	if _, err := agent.Propose("agent", "ref", hashOf("z"), "", 1); err != nil {
		t.Fatalf("propose: %v", err)
	}
	exp := waitFor[EvArtifactExpired](t, agent, 2*time.Second)
	if exp.ArtifactRef != "ref" {
		t.Fatalf("expired event = %+v", exp)
	}
	if len(agent.PendingProposals()) != 0 {
		t.Fatal("an expired proposal must be dropped from the pending list")
	}
	if len(alice.RecordEntries()) != 0 {
		t.Fatal("an expired proposal must not produce a record entry")
	}
}
