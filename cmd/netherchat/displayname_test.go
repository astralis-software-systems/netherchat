package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/sealedrecord"
	"github.com/salehkreiner/netherchat/tui/attest"
)

// These tests drive `netherchat verify` from ARGV, for the reason the file next
// door states: a surface can carry a field in its library type and never print
// it, and no test that starts below the flag parse can tell. A signed display
// name that reaches IdentityResult and stops there is the same defect as a flag
// that is parsed and dropped.
//
// They assert the field is AVAILABLE and PRINTED. They deliberately do not
// assert it is primary, or that the principal moves to a detail line: that is a
// rendering decision for three surfaces at once and it belongs to the phase that
// makes it, not to the phase that adds the field.

// namedAttestation is signedAttestation (recordcmds_test.go) with a display name.
func namedAttestation(t *testing.T, is testIssuer, subject, principal, display, serial string, expires time.Time) *attest.IdentityAttestation {
	t.Helper()
	unsigned := sealedrecord.NewIdentityAttestation(sealedrecord.IdentitySpec{
		Serial:        serial,
		Subject:       subject,
		Principal:     principal,
		DisplayName:   display,
		PrincipalType: "person",
		Roles:         []string{"operations", "security"},
		ExpiresAt:     expires.UTC().Format(time.RFC3339),
		Algorithm:     sealedrecord.AlgorithmEd25519,
		Issuer:        is.fpr,
	}, nil, nil)
	sig := ed25519.Sign(is.priv, sealedrecord.IdentitySigningBytes(unsigned))
	return unsigned.WithSignatures(
		map[string][]byte{is.fpr: sig},
		map[string][]byte{is.fpr: is.pub},
	)
}

// writeIdentityFile marshals an attestation to a file, the way an issuer hands
// one over.
func writeIdentityFile(t *testing.T, a *attest.IdentityAttestation) string {
	t.Helper()
	b, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "identity.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestVerifyIdentityArtifactSurfacesDisplayName covers the standalone artifact on
// both paths and in both modes. The UNPINNED path matters as much as the pinned
// one: it prints what the file says, checked by nobody, and a display name is
// part of what the file says. Leaving it out there would mean an operator reading
// an identity.json they were handed could not see the name it carries.
func TestVerifyIdentityArtifactSurfacesDisplayName(t *testing.T) {
	is := mkTestIssuer(t)
	const display = "Jonathan Doe"
	att := namedAttestation(t, is, is.fpr, "jonathan.doe@acme.example", display, "acme-0003", time.Now().Add(24*time.Hour))
	path := writeIdentityFile(t, att)
	issuerFile := writeIssuerFile(t, is.pub)

	// Pinned, --json: the verdict object carries the signed name.
	m, code := verifyJSON(t, path, "--issuer", issuerFile, "--json")
	if code != 0 || m["valid"] != true {
		t.Fatalf("the fixture must verify: exit %d %v", code, m)
	}
	if m["display_name"] != display {
		t.Errorf("display_name = %v, want %q — the field reached the result and stopped there", m["display_name"], display)
	}
	if m["principal"] != "jonathan.doe@acme.example" {
		t.Errorf("the principal must still be in the verdict: %v", m["principal"])
	}

	// Pinned, human.
	human := captureOut(t, func() { runVerify([]string{path, "--issuer", issuerFile}) })
	if !strings.Contains(human, display) {
		t.Errorf("a verified display name must be printed:\n%s", human)
	}
	if !strings.Contains(human, "jonathan.doe@acme.example") {
		t.Errorf("the principal must still be printed — it is the identifier:\n%s", human)
	}

	// Unpinned, --json and human: the fields the FILE says, name included.
	mu, codeu := verifyJSON(t, path, "--json")
	if codeu != 1 {
		t.Errorf("no issuer pinned must still exit 1, got %d", codeu)
	}
	if mu["display_name"] != display {
		t.Errorf("unpinned --json display_name = %v, want %q", mu["display_name"], display)
	}
	humanu := captureOut(t, func() { runVerify([]string{path}) })
	if !strings.Contains(humanu, display) {
		t.Errorf("unpinned human mode must show the name the file carries:\n%s", humanu)
	}
	if strings.Contains(humanu, "VALID") {
		t.Errorf("unpinned output must never say VALID:\n%s", humanu)
	}
}

// TestVerifyIdentityArtifactWithNoDisplayNamePrintsNoEmptyLine is the optional
// half at the command line. An artifact that carries no name must not produce a
// dangling label, and must not produce a JSON key either — an empty string in a
// verdict reads as "the issuer signed an empty name", which is not what happened.
func TestVerifyIdentityArtifactWithNoDisplayNamePrintsNoEmptyLine(t *testing.T) {
	is := mkTestIssuer(t)
	att := signedAttestation(t, is, is.fpr, "svc-deploy@acme.example", "acme-0004", time.Now().Add(24*time.Hour))
	path := writeIdentityFile(t, att)
	issuerFile := writeIssuerFile(t, is.pub)

	m, code := verifyJSON(t, path, "--issuer", issuerFile, "--json")
	if code != 0 {
		t.Fatalf("exit %d %v", code, m)
	}
	if _, present := m["display_name"]; present {
		t.Errorf("an attestation with no display name must emit no display_name key: %v", m)
	}
	human := captureOut(t, func() { runVerify([]string{path, "--issuer", issuerFile}) })
	if strings.Contains(human, "display name:") {
		t.Errorf("no name means no label:\n%s", human)
	}
}

// TestVerifyRecordSurfacesDisplayName is the record carrier, at argv. A record is
// the form the demo actually verifies — `netherchat verify record.json --issuer
// acme-ca.pub` on a laptop that was never in the room — so the name has to reach
// this output, not only the standalone artifact's.
func TestVerifyRecordSurfacesDisplayName(t *testing.T) {
	is := mkTestIssuer(t)
	author := testAuthor(t)
	const display = "Jonathan Doe"
	att := namedAttestation(t, is, author.ID, "jonathan.doe@acme.example", display, "acme-0005", time.Now().Add(24*time.Hour))
	path := sealRecordFile(t, author, att)
	issuerFile := writeIssuerFile(t, is.pub)

	m, code := verifyJSON(t, path, "--issuer", issuerFile, "--json")
	if code != 0 || m["valid"] != true {
		t.Fatalf("exit %d %v", code, m)
	}
	bindings, _ := m["identity_bindings"].(map[string]any)
	got, _ := bindings[author.ID].([]any)
	if len(got) != 1 {
		t.Fatalf("no binding for subject %s: %v", author.ID, bindings)
	}
	b := got[0].(map[string]any)
	if b["display_name"] != display {
		t.Errorf("binding display_name = %v, want %q", b["display_name"], display)
	}
	if b["principal"] != "jonathan.doe@acme.example" {
		t.Errorf("binding principal = %v", b["principal"])
	}

	human := captureOut(t, func() { runVerify([]string{path, "--issuer", issuerFile}) })
	if !strings.Contains(human, display) {
		t.Errorf("the record's identity block must print the signed name:\n%s", human)
	}
	if !strings.Contains(human, "jonathan.doe@acme.example") {
		t.Errorf("and must still print the principal:\n%s", human)
	}
}
