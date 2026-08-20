package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
	"github.com/salehkreiner/netherchat/tui/record"
)

// --- test issuer plumbing ---------------------------------------------------
//
// A test authority, and a credential it signs about one subject fingerprint.
// Nothing here is a trust anchor of the client's: the key is minted by the test
// and handed to the VERIFIER at the end, which is the whole shape of the seam.

type testAuthority struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	fpr  string
}

func newAuthority(t *testing.T) testAuthority {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("issuer key: %v", err)
	}
	return testAuthority{pub: pub, priv: priv, fpr: crypto.Fingerprint(pub)}
}

// credentialFor signs an identity attestation about subject naming roles.
func credentialFor(t *testing.T, is testAuthority, subject string, roles ...string) *attest.IdentityAttestation {
	t.Helper()
	unsigned := attest.NewIdentityAttestation(attest.IdentitySpec{
		Serial:        "acme-" + subject[7:15],
		Subject:       subject,
		Principal:     "rosa.alvarez@acme.example",
		DisplayName:   "Rosa Alvarez",
		PrincipalType: "person",
		Roles:         roles,
		ExpiresAt:     time.Now().UTC().Add(90 * 24 * time.Hour).Format(time.RFC3339),
		Algorithm:     attest.AlgorithmEd25519,
		Issuer:        is.fpr,
	}, nil, nil)
	sig := ed25519.Sign(is.priv, attest.IdentitySigningBytes(unsigned))
	return unsigned.WithSignatures(
		map[string][]byte{is.fpr: sig},
		map[string][]byte{is.fpr: is.pub},
	)
}

// TestApprovalCarriesTheAttestationOnTheWire is W1: the approver's credential
// travels with the approval as the standalone artifact's marshalled bytes,
// verbatim, and reaches the sealed record where a reader that pins the issuer
// binds it to the approver's own fingerprint.
func TestApprovalCarriesTheAttestationOnTheWire(t *testing.T) {
	_, agent, alice := twoClients(t, "ops")
	is := newAuthority(t)
	cred := credentialFor(t, is, alice.Fingerprint(), "qa")
	if err := alice.UseIdentity(cred); err != nil {
		t.Fatalf("use identity: %v", err)
	}

	hash := hashOf("DRAFT_REQUIREMENTS_v1")
	id, err := agent.Propose("requirements-agent", "Q3-requirements", hash, "", 1)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	waitFor[EvArtifactProposed](t, alice, 5*time.Second)
	if err := alice.ApproveArtifact(id, ""); err != nil {
		t.Fatalf("approve: %v", err)
	}

	// The RECEIVER — the other end of the wire — got the credential verbatim.
	got := waitFor[EvArtifactApproved](t, agent, 5*time.Second)
	want, err := cred.Marshal()
	if err != nil {
		t.Fatalf("marshal credential: %v", err)
	}
	if !bytes.Equal(got.Attestation, want) {
		t.Fatalf("the receiver's attestation bytes differ from the standalone artifact:\n got %q\nwant %q",
			got.Attestation, want)
	}

	// And it reached the record: seal, then verify with the issuer pinned.
	waitFor[EvArtifactSealed](t, alice, 5*time.Second)
	_ = agent.Close()
	waitFor[EvMemberLeft](t, alice, 5*time.Second)
	if err := alice.Seal(); err != nil {
		t.Fatalf("seal: %v", err)
	}
	rec := waitFor[EvSealComplete](t, alice, 20*time.Second).Record
	b, err := rec.Marshal()
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	res, err := record.VerifyBytesWithIdentity(b, attest.IdentityOptions{
		IssuerKeys: []ed25519.PublicKey{is.pub},
		At:         time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("verify with identity: %v", err)
	}
	if !res.Valid {
		t.Fatalf("the sealed record must verify: %s", res.Reason)
	}
	bindings := record.VerifiedIdentitiesOf(res, alice.Fingerprint())
	if len(bindings) != 1 {
		t.Fatalf("want one verified binding for the approver, got %d (outcomes: %+v)", len(bindings), res.IdentityOutcomes)
	}
	if bindings[0].Principal != "rosa.alvarez@acme.example" || bindings[0].DisplayName != "Rosa Alvarez" {
		t.Fatalf("binding = %+v", bindings[0])
	}
}

// --- W2: the role, and where it may come from -------------------------------

// TestSingleRoleApproverIsAskedNothing: a credential naming exactly one role
// resolves it without the operator naming anything. There is no choice to make,
// so there is no question to ask.
func TestSingleRoleApproverIsAskedNothing(t *testing.T) {
	_, agent, alice := twoClients(t, "ops")
	is := newAuthority(t)
	if err := alice.UseIdentity(credentialFor(t, is, alice.Fingerprint(), "qa")); err != nil {
		t.Fatalf("use identity: %v", err)
	}
	id, err := agent.Propose("requirements-agent", "Q3", hashOf("x"), "", 1)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	waitFor[EvArtifactProposed](t, alice, 5*time.Second)
	if err := alice.ApproveArtifact(id, ""); err != nil {
		t.Fatalf("a single-role approver must not be asked: %v", err)
	}
	got := waitFor[EvArtifactApproved](t, agent, 5*time.Second)
	if got.Role != "qa" {
		t.Fatalf("role on the wire = %q, want the one role the credential names", got.Role)
	}
	if got.RoleUnbacked {
		t.Fatal("a role the carried credential names must not be flagged unbacked")
	}
}

// TestMultiRoleApproverMustNameOne: two roles is a choice, and the client will
// not make it. The error names the choices, which is what the command surface
// turns into a prompt.
func TestMultiRoleApproverMustNameOne(t *testing.T) {
	_, agent, alice := twoClients(t, "ops")
	is := newAuthority(t)
	if err := alice.UseIdentity(credentialFor(t, is, alice.Fingerprint(), "qa", "system-owner")); err != nil {
		t.Fatalf("use identity: %v", err)
	}
	id, err := agent.Propose("requirements-agent", "Q3", hashOf("x"), "", 1)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	waitFor[EvArtifactProposed](t, alice, 5*time.Second)
	err = alice.ApproveArtifact(id, "")
	if err == nil {
		t.Fatal("a credential naming two roles must not resolve one silently")
	}
	if !strings.Contains(err.Error(), "qa") || !strings.Contains(err.Error(), "system-owner") {
		t.Fatalf("the error must name the choices, got %q", err)
	}
	// Nothing was sent: the proposal is still pending and unapproved.
	if len(alice.PendingProposals()) != 1 {
		t.Fatal("a refused approval must not resolve the proposal")
	}
}

// TestRoleOutsideTheSignedSetIsRefused: the sender never produces a role its own
// credential does not name. That is what makes Role a selection from a signed
// set rather than a free-text string an approver asserts about themselves.
func TestRoleOutsideTheSignedSetIsRefused(t *testing.T) {
	_, agent, alice := twoClients(t, "ops")
	is := newAuthority(t)
	if err := alice.UseIdentity(credentialFor(t, is, alice.Fingerprint(), "qa")); err != nil {
		t.Fatalf("use identity: %v", err)
	}
	id, err := agent.Propose("requirements-agent", "Q3", hashOf("x"), "", 1)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	waitFor[EvArtifactProposed](t, alice, 5*time.Second)
	if err := alice.ApproveArtifact(id, "release-manager"); err == nil {
		t.Fatal("a role the credential does not name must be refused at the sender")
	}
	// And with no credential at all there is no signed set to select from.
	_, agent2, bob := twoClients(t, "ops2")
	id2, err := agent2.Propose("requirements-agent", "Q3", hashOf("y"), "", 1)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	waitFor[EvArtifactProposed](t, bob, 5*time.Second)
	if err := bob.ApproveArtifact(id2, "qa"); err == nil {
		t.Fatal("a role with no carried credential must be refused")
	}
}

// TestRoleReachesTheSealedRecord is the other half of the wire round trip: the
// role signed on the wire is the role the sealed record carries, verified from
// the file alone. Quorum is 2 because the role-typed surface excludes the entry
// author, so a single approver who is also the writer would surface nothing.
func TestRoleReachesTheSealedRecord(t *testing.T) {
	relay := httptest.NewServer(server.Handler(config.Default(), quietLog()))
	defer relay.Close()
	agent := dialClient(t, relay.URL, "ops", "agent")
	waitFor[EvKeyReady](t, agent, 5*time.Second)
	alice := dialClient(t, relay.URL, "ops", "alice")
	waitFor[EvKeyReady](t, alice, 5*time.Second)
	bob := dialClient(t, relay.URL, "ops", "bob")
	waitFor[EvKeyReady](t, bob, 5*time.Second)
	waitFor[EvMemberJoined](t, agent, 5*time.Second)
	waitFor[EvMemberJoined](t, agent, 5*time.Second)

	is := newAuthority(t)
	if err := alice.UseIdentity(credentialFor(t, is, alice.Fingerprint(), "qa")); err != nil {
		t.Fatalf("alice identity: %v", err)
	}
	if err := bob.UseIdentity(credentialFor(t, is, bob.Fingerprint(), "system-owner")); err != nil {
		t.Fatalf("bob identity: %v", err)
	}

	id, err := agent.Propose("planner-agent", "plan", hashOf("the plan"), "", 2)
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

	writer := minFpr([]string{alice.Fingerprint(), bob.Fingerprint()})
	sealer, leaver := alice, bob
	if alice.Fingerprint() == writer {
		sealer, leaver = bob, alice
	}
	waitFor[EvRecordEntry](t, sealer, 5*time.Second)
	_ = agent.Close()
	_ = leaver.Close()
	waitFor[EvMemberLeft](t, sealer, 5*time.Second)
	waitFor[EvMemberLeft](t, sealer, 5*time.Second)
	if err := sealer.Seal(); err != nil {
		t.Fatalf("seal: %v", err)
	}
	rec := waitFor[EvSealComplete](t, sealer, 25*time.Second).Record
	b, err := rec.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	res, err := record.VerifyBytes(b)
	if err != nil || !res.Valid {
		t.Fatalf("the record must verify offline: err=%v reason=%q", err, res.Reason)
	}
	roles := record.VerifiedArtifactApproverRoles(res, id)
	if len(roles) != 1 {
		t.Fatalf("want the one non-authoring role-typed approval, got %+v", roles)
	}
	// The surfaced approver is the one who did NOT author the artifact entry —
	// which is the non-writer, i.e. the sealer.
	wantRole := "system-owner"
	if sealer.Fingerprint() == alice.Fingerprint() {
		wantRole = "qa"
	}
	if roles[0].Fingerprint != sealer.Fingerprint() || roles[0].Role != wantRole {
		t.Fatalf("surfaced role = %+v, want %s as %q", roles[0], sealer.Fingerprint(), wantRole)
	}
}

// --- W3: a role the carried credential does not name ------------------------

// TestRoleNotNamedByTheCredentialIsVisibleNotRejected constructs the mismatch
// this client refuses to produce and a peer on another build could: a v2
// approval signed as "system-owner" carrying a credential that names only "qa".
//
// The decision it pins: the approval COUNTS — the signature verifies and the
// proposal seals — and the mismatch is stated on the event. Netherchat surfaces
// what arrived; whether a role claim is worth anything needs an issuer key and
// an evaluation time this process does not hold.
func TestRoleNotNamedByTheCredentialIsVisibleNotRejected(t *testing.T) {
	_, agent, alice := twoClients(t, "ops")
	is := newAuthority(t)
	cred := credentialFor(t, is, alice.Fingerprint(), "qa")
	credBytes, err := cred.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	id, err := agent.Propose("planner-agent", "plan", hashOf("the plan"), "", 1)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	waitFor[EvArtifactProposed](t, alice, 5*time.Second)

	alice.mu.Lock()
	prop := alice.proposals[id].prop
	alice.mu.Unlock()

	fpr := alice.Fingerprint()
	sig, err := alice.id.Sign(protocol.ArtifactApprovalSigningBytesV2(
		prop.ProposalID, prop.ArtifactHash, fpr, prop.Nonce, "system-owner"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	body, err := json.Marshal(protocol.ArtifactApprovalBody{
		ProposalID: prop.ProposalID, ArtifactHash: prop.ArtifactHash, ApproverFpr: fpr, Sig: sig,
		Attestation: credBytes, Role: "system-owner",
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	if err := alice.sealAndSend(protocol.OpArtifactApproval, body); err != nil {
		t.Fatalf("send: %v", err)
	}

	got := waitFor[EvArtifactApproved](t, agent, 5*time.Second)
	if got.Role != "system-owner" {
		t.Fatalf("the role must be surfaced as signed, got %q", got.Role)
	}
	if !got.RoleUnbacked {
		t.Fatal("a role the carried credential does not name must be visible as unbacked")
	}
	if got.Count != 1 {
		t.Fatalf("the approval must still count, got %d", got.Count)
	}
	// And it still seals: nothing here adjudicates.
	waitFor[EvArtifactSealed](t, agent, 5*time.Second)
}

// TestRoleWithNoCredentialIsVisibleNotRejected is the same decision for the
// other shape of the same gap: a role arriving with no attestation at all.
func TestRoleWithNoCredentialIsVisibleNotRejected(t *testing.T) {
	_, agent, alice := twoClients(t, "ops")
	id, err := agent.Propose("planner-agent", "plan", hashOf("the plan"), "", 1)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	waitFor[EvArtifactProposed](t, alice, 5*time.Second)

	alice.mu.Lock()
	prop := alice.proposals[id].prop
	alice.mu.Unlock()

	fpr := alice.Fingerprint()
	sig, err := alice.id.Sign(protocol.ArtifactApprovalSigningBytesV2(
		prop.ProposalID, prop.ArtifactHash, fpr, prop.Nonce, "release-manager"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	body, _ := json.Marshal(protocol.ArtifactApprovalBody{
		ProposalID: prop.ProposalID, ArtifactHash: prop.ArtifactHash, ApproverFpr: fpr, Sig: sig,
		Role: "release-manager",
	})
	if err := alice.sealAndSend(protocol.OpArtifactApproval, body); err != nil {
		t.Fatalf("send: %v", err)
	}
	got := waitFor[EvArtifactApproved](t, agent, 5*time.Second)
	if got.Role != "release-manager" || !got.RoleUnbacked || got.Count != 1 {
		t.Fatalf("event = %+v; want the role surfaced, flagged unbacked, and counted", got)
	}
}

// TestAlteredRoleIsRejectedAsForged is the boundary of the decision above: a
// role that was CHANGED after signing is not a surfacing question, it is a bad
// signature, and the approval never counts. The two preimages differ by their
// domain tag and by field(role), so every tamper direction fails closed.
func TestAlteredRoleIsRejectedAsForged(t *testing.T) {
	_, agent, alice := twoClients(t, "ops")
	id, err := agent.Propose("planner-agent", "plan", hashOf("the plan"), "", 1)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	waitFor[EvArtifactProposed](t, alice, 5*time.Second)

	alice.mu.Lock()
	prop := alice.proposals[id].prop
	alice.mu.Unlock()

	fpr := alice.Fingerprint()
	sig, err := alice.id.Sign(protocol.ArtifactApprovalSigningBytesV2(
		prop.ProposalID, prop.ArtifactHash, fpr, prop.Nonce, "qa"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	body, _ := json.Marshal(protocol.ArtifactApprovalBody{
		ProposalID: prop.ProposalID, ArtifactHash: prop.ArtifactHash, ApproverFpr: fpr, Sig: sig,
		Role: "system-owner", // relabelled in flight
	})
	if err := alice.sealAndSend(protocol.OpArtifactApproval, body); err != nil {
		t.Fatalf("send: %v", err)
	}
	ev := waitFor[EvError](t, agent, 5*time.Second)
	if !strings.Contains(ev.Err.Error(), "invalid signature") {
		t.Fatalf("a relabelled role must fail the signature check, got %v", ev.Err)
	}
	if len(agent.PendingProposals()) != 1 {
		t.Fatal("a forged approval must not resolve the proposal")
	}
}

// TestCredentialIsFiledOncePerRoom: a second approval in the same room must not
// re-file a credential the chain already holds. Verification deduplicates
// bindings regardless; this is about the evidence reading like evidence.
func TestCredentialIsFiledOncePerRoom(t *testing.T) {
	_, agent, alice := twoClients(t, "ops")
	is := newAuthority(t)
	if err := alice.UseIdentity(credentialFor(t, is, alice.Fingerprint(), "qa")); err != nil {
		t.Fatalf("use identity: %v", err)
	}
	for i, content := range []string{"first artifact", "second artifact"} {
		id, err := agent.Propose("requirements-agent", "ref", hashOf(content), "", 1)
		if err != nil {
			t.Fatalf("propose %d: %v", i, err)
		}
		waitFor[EvArtifactProposed](t, alice, 5*time.Second)
		if err := alice.ApproveArtifact(id, ""); err != nil {
			t.Fatalf("approve %d: %v", i, err)
		}
		waitFor[EvArtifactSealed](t, alice, 5*time.Second)
	}
	var identityEntries, artifactEntries int
	for _, e := range alice.RecordEntries() {
		switch {
		case record.IsIdentityEntry(e):
			identityEntries++
		case e.Kind == record.KindArtifact:
			artifactEntries++
		}
	}
	if artifactEntries != 2 {
		t.Fatalf("want two artifact entries, got %d", artifactEntries)
	}
	if identityEntries != 1 {
		t.Fatalf("want the credential filed once, got %d identity entries", identityEntries)
	}
}
