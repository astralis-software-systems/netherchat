package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// These tests start at the surface a user touches: the /approve-artifact command
// handler, driven through a real Model against a real relay, exactly as the TUI
// dispatch calls it. Nothing here reaches into the client's approval internals.

// credential signs an attestation about subject naming roles.
func credential(t *testing.T, subject string, roles ...string) *attest.IdentityAttestation {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("issuer key: %v", err)
	}
	unsigned := attest.NewIdentityAttestation(attest.IdentitySpec{
		Serial:        "acme-0001",
		Subject:       subject,
		Principal:     "rosa.alvarez@acme.example",
		PrincipalType: "person",
		Roles:         roles,
		ExpiresAt:     time.Now().UTC().Add(90 * 24 * time.Hour).Format(time.RFC3339),
		Algorithm:     attest.AlgorithmEd25519,
		Issuer:        crypto.Fingerprint(pub),
	}, nil, nil)
	sig := ed25519.Sign(priv, attest.IdentitySigningBytes(unsigned))
	return unsigned.WithSignatures(
		map[string][]byte{crypto.Fingerprint(pub): sig},
		map[string][]byte{crypto.Fingerprint(pub): pub},
	)
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// approvalStage stands up a proposer and an approver driven through a Model, and
// returns the model, its room, the approver client, and the pending proposal id.
func approvalStage(t *testing.T, roles ...string) (*Model, *room, *client.Client, string) {
	t.Helper()
	ts := httptest.NewServer(server.Handler(config.Default(), discardLogger()))
	t.Cleanup(ts.Close)

	agent := connectCore(t, ts.URL, "ops", "agent")
	waitKeyReady(t, agent)
	approver := connectCore(t, ts.URL, "ops", "alice")
	waitKeyReady(t, approver)
	if len(roles) > 0 {
		if err := approver.UseIdentity(credential(t, approver.Fingerprint(), roles...)); err != nil {
			t.Fatalf("use identity: %v", err)
		}
	}

	id, err := agent.Propose("requirements-agent", "Q3-requirements", sha256hex("draft"), "", 1)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}

	m := newModel(ts.URL, "alice", "", "ops", "")
	r := m.activeRoom()
	r.client = approver
	r.connected = true

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(approver.PendingProposals()) > 0 {
			return m, r, approver, id
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timed out waiting for the proposal to reach the approver")
	return nil, nil, nil, ""
}

// errorLines returns the error lines the model has shown in this room.
func errorLines(r *room) []string {
	var out []string
	for _, l := range r.lines {
		if l.kind == lineError {
			out = append(out, l.text)
		}
	}
	return out
}

func waitApproved(t *testing.T, c *client.Client, id string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(c.PendingProposals()) == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("proposal %s was never approved", id)
}

// TestApproveArtifactSingleRoleAsksNothing: one signed role means no choice, so
// /approve-artifact takes the proposal id and nothing else — as it always has.
func TestApproveArtifactSingleRoleAsksNothing(t *testing.T) {
	m, r, c, id := approvalStage(t, "qa")
	m.runApproveArtifact(r, id)
	if errs := errorLines(r); len(errs) != 0 {
		t.Fatalf("a single-role approver must not be asked anything, got %v", errs)
	}
	waitApproved(t, c, id)
}

// TestApproveArtifactMultiRolePrompts: two signed roles is a choice the command
// will not make for you, and the prompt names both.
func TestApproveArtifactMultiRolePrompts(t *testing.T) {
	m, r, c, id := approvalStage(t, "qa", "system-owner")
	m.runApproveArtifact(r, id)
	errs := errorLines(r)
	if len(errs) != 1 {
		t.Fatalf("want one prompt line, got %v", errs)
	}
	if !strings.Contains(errs[0], "qa") || !strings.Contains(errs[0], "system-owner") {
		t.Fatalf("the prompt must name both roles, got %q", errs[0])
	}
	if len(c.PendingProposals()) != 1 {
		t.Fatal("the proposal must still be pending after a prompt")
	}

	// Naming one approves.
	m.runApproveArtifact(r, id+" system-owner")
	if errs := errorLines(r); len(errs) != 1 {
		t.Fatalf("naming a signed role must not error, got %v", errs)
	}
	waitApproved(t, c, id)
}

// TestApproveArtifactRejectsARoleTheCredentialDoesNotName: the command surface
// offers a selection from a signed set, and refuses anything outside it.
func TestApproveArtifactRejectsARoleTheCredentialDoesNotName(t *testing.T) {
	m, r, c, id := approvalStage(t, "qa")
	m.runApproveArtifact(r, id+" release-manager")
	errs := errorLines(r)
	if len(errs) != 1 || !strings.Contains(errs[0], "release-manager") {
		t.Fatalf("want a refusal naming the role, got %v", errs)
	}
	if len(c.PendingProposals()) != 1 {
		t.Fatal("a refused approval must leave the proposal pending")
	}
}

// TestApproveArtifactUnattestedIsUnchanged: with no credential the command is
// exactly what it was — one positional id, no role, no prompt.
func TestApproveArtifactUnattestedIsUnchanged(t *testing.T) {
	m, r, c, id := approvalStage(t)
	m.runApproveArtifact(r, id)
	if errs := errorLines(r); len(errs) != 0 {
		t.Fatalf("the unattested path must not gain a prompt, got %v", errs)
	}
	waitApproved(t, c, id)
}

// TestApproveArtifactCompletionOffersTheSignedSet: autocomplete draws from the
// credential, so an operator picks a role rather than typing one.
func TestApproveArtifactCompletionOffersTheSignedSet(t *testing.T) {
	m, _, _, _ := approvalStage(t, "qa", "system-owner")
	cmd, ok := m.cmds.Get("approve-artifact")
	if !ok || cmd.Complete == nil {
		t.Fatal("/approve-artifact must offer completions for the role")
	}
	got := cmd.Complete("")
	if len(got) != 2 || got[0] != "qa" || got[1] != "system-owner" {
		t.Fatalf("completions = %v, want the two roles the credential names", got)
	}
	if only := cmd.Complete("sys"); len(only) != 1 || only[0] != "system-owner" {
		t.Fatalf("prefix completion = %v", only)
	}
}

// TestApproveArtifactCompletionEmptyWithoutACredential: no credential, nothing
// to offer — and no invented vocabulary.
func TestApproveArtifactCompletionEmptyWithoutACredential(t *testing.T) {
	m, _, _, _ := approvalStage(t)
	cmd, _ := m.cmds.Get("approve-artifact")
	if got := cmd.Complete(""); len(got) != 0 {
		t.Fatalf("want no completions without a credential, got %v", got)
	}
}
