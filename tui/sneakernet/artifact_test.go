package sneakernet

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
	"github.com/salehkreiner/netherchat/tui/record"
)

// THE PAIR-MODE DECISION, PINNED (roadmap §5 3a, §9 risk register).
//
// The coordinator routes the three artifact ops. It did not: they fell through
// to its default arm and were dropped, so relay-less pair mode carried no
// artifact approvals at all — a whole feature missing by omission, in the one
// mode interop-live structurally cannot exercise because it runs a relay.
//
// The alternative was to document pair mode as approval-free. It was rejected
// because the ops are the same shape as the frames the coordinator already fans
// out: opaque, sealed, Ed25519-signed Message envelopes it never decodes. The
// relay's own arm lists them beside the Two-Person Rule frames; routing them
// here is that list, matched. Documenting the gap would have made two answers
// to "can two people approve an artifact" depending on transport, which is the
// distinction this test exists to prevent from reappearing.

func hashOfContent(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// pairCredential signs an attestation about subject naming one role.
func pairCredential(t *testing.T, subject, role string) *attest.IdentityAttestation {
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
		Roles:         []string{role},
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

// TestDirectArtifactApprovalRoundTrip: a proposal and an attested, role-typed
// approval cross a relay-LESS pair and reach the record. No relay is started.
func TestDirectArtifactApprovalRoundTrip(t *testing.T) {
	host, joiner, _ := directPair(t)
	if err := joiner.UseIdentity(pairCredential(t, joiner.Fingerprint(), "qa")); err != nil {
		t.Fatalf("use identity: %v", err)
	}

	hash := hashOfContent("DRAFT_REQUIREMENTS_v1")
	id, err := host.Propose("requirements-agent", "Q3-requirements", hash, "", 1)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	prop := waitEvent[client.EvArtifactProposed](t, joiner, 5*time.Second)
	if prop.ProposalID != id {
		t.Fatalf("the joiner received %+v, want proposal %s", prop, id)
	}

	if err := joiner.ApproveArtifact(id, ""); err != nil {
		t.Fatalf("approve: %v", err)
	}
	// The PROPOSER, at the other end of the direct connection, sees the approval
	// with the credential and the role that were signed into it.
	got := waitEvent[client.EvArtifactApproved](t, host, 5*time.Second)
	if got.Role != "qa" {
		t.Fatalf("role over the direct transport = %q, want %q", got.Role, "qa")
	}
	if len(got.Attestation) == 0 {
		t.Fatal("the attestation did not cross the relay-less pair")
	}
	if got.RoleUnbacked {
		t.Fatal("the carried credential names this role")
	}
	waitEvent[client.EvArtifactSealed](t, host, 5*time.Second)

	// And the artifact entry is on the proposer's chain — the approval reached
	// the record with no relay in the process table.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, e := range host.RecordEntries() {
			if e.Kind == record.KindArtifact {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the artifact entry never reached the proposer's chain over the direct transport")
}

// TestDirectArtifactRejectionRoundTrip: the third op of the family crosses too.
// Routing two of three would be the same silent half-feature in a smaller size.
func TestDirectArtifactRejectionRoundTrip(t *testing.T) {
	host, joiner, _ := directPair(t)
	id, err := host.Propose("requirements-agent", "Q3-requirements", hashOfContent("x"), "", 1)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	waitEvent[client.EvArtifactProposed](t, joiner, 5*time.Second)
	if err := joiner.RejectArtifact(id, "not this quarter"); err != nil {
		t.Fatalf("reject: %v", err)
	}
	got := waitEvent[client.EvArtifactRejected](t, host, 5*time.Second)
	if got.ProposalID != id || got.Reason != "not this quarter" {
		t.Fatalf("rejection over the direct transport = %+v", got)
	}
}
