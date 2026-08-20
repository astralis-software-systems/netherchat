package main

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/sealedrecord"
)

// TestIssueCarriesADisplayName drives the issuer tool at the level an operator
// does — a flag on a command line — and follows the artifact all the way to a
// verdict. The library test proves the field is signed; this one proves the tool
// can actually put a name into it, which is a different failure and the one that
// would leave the format correct and the product unable to use it.
func TestIssueCarriesADisplayName(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "issuer.json")
	outPath := filepath.Join(dir, "identity.json")

	keygenCmd([]string{"--out", keyPath})
	pub := readPubFile(t, filepath.Join(dir, "issuer.pub"))

	const display = "Jonathan Doe"
	issueCmd([]string{
		"--key", keyPath, "--out", outPath,
		"--subject", "SHA256:" + strings.Repeat("A", 43),
		"--principal", "jonathan.doe@acme.example",
		"--display-name", display,
		"--type", "person",
		"--role", "operations",
		"--valid", "30d",
	})

	b, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	att, err := sealedrecord.ParseIdentity(b)
	if err != nil {
		t.Fatal(err)
	}
	if att.DisplayName != display {
		t.Fatalf("display_name = %q, want %q", att.DisplayName, display)
	}
	res, err := sealedrecord.VerifyIdentity(att, sealedrecord.IdentityOptions{
		IssuerKeys: []ed25519.PublicKey{pub},
		At:         time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("an attestation this tool issued must verify: %s / %s", res.Reason, res.Detail)
	}
	if res.DisplayName != display {
		t.Errorf("the verdict must carry the signed name: %q", res.DisplayName)
	}
	if res.Principal != "jonathan.doe@acme.example" {
		t.Errorf("the principal must still be there: %q", res.Principal)
	}
}

// TestIssueWithoutADisplayNameOmitsTheField is the other half of "optional". The
// flag is not mandatory, an artifact minted without it carries no display_name
// key at all, and it verifies exactly as it did before the field existed — which
// is what makes the field additive for an issuer who has no directory name to
// assert.
func TestIssueWithoutADisplayNameOmitsTheField(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "issuer.json")
	outPath := filepath.Join(dir, "identity.json")

	keygenCmd([]string{"--out", keyPath})
	pub := readPubFile(t, filepath.Join(dir, "issuer.pub"))

	issueCmd([]string{
		"--key", keyPath, "--out", outPath,
		"--subject", "SHA256:" + strings.Repeat("B", 43),
		"--principal", "svc-deploy@acme.example",
		"--type", "service",
		"--role", "deploy",
	})

	b, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	if _, present := raw["display_name"]; present {
		t.Errorf("an issuer who named no display name must not ship an empty key:\n%s", b)
	}

	att, err := sealedrecord.ParseIdentity(b)
	if err != nil {
		t.Fatal(err)
	}
	res, err := sealedrecord.VerifyIdentity(att, sealedrecord.IdentityOptions{
		IssuerKeys: []ed25519.PublicKey{pub},
		At:         time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("an attestation with no display name must still verify: %s / %s", res.Reason, res.Detail)
	}
	if res.DisplayName != "" {
		t.Errorf("DisplayName = %q, want empty", res.DisplayName)
	}
}
