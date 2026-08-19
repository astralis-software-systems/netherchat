package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/sealedrecord"
	"github.com/salehkreiner/netherchat/tui/attest"
	"golang.org/x/crypto/ssh"
)

// mkAttestation builds a signed attestation and returns it with its issuer's key.
func mkAttestation(t *testing.T) (*attest.IdentityAttestation, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	subPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fpr := sealedrecord.Fingerprint(pub)
	unsigned := attest.NewIdentityAttestation(attest.IdentitySpec{
		Serial:        "acme-0001",
		Subject:       sealedrecord.Fingerprint(subPub),
		Principal:     "rosa.alvarez@acme.example",
		PrincipalType: "person",
		Roles:         []string{"qa"},
		ExpiresAt:     time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
		Algorithm:     attest.AlgorithmEd25519,
		Issuer:        fpr,
	}, nil, nil)
	sig := ed25519.Sign(priv, attest.IdentitySigningBytes(unsigned))
	return unsigned.WithSignatures(
		map[string][]byte{fpr: sig},
		map[string][]byte{fpr: pub},
	), pub
}

// TestDetectArtifactSniffsIdentity proves the dispatcher recognises the new
// artifact by its discriminator key, and that the three existing families are
// unmoved.
func TestDetectArtifactSniffsIdentity(t *testing.T) {
	cases := map[string]string{
		`{"netherchat_identity":"v1"}`: "identity",
		`{"netherchat_roster":"v1"}`:   "roster",
		`{"netherchat_receipt":"v1"}`:  "receipt",
		`{"netherchat_record":"v1"}`:   "record",
		`{"something_else":true}`:      "record",
	}
	for in, want := range cases {
		if got := detectArtifact([]byte(in)); got != want {
			t.Errorf("detectArtifact(%s) = %q, want %q", in, got, want)
		}
	}
}

// TestVerifyIdentityBytesWithoutIssuerIsNotAVerdict is the inert-breaking
// accident this path exists to prevent. With no issuer key there is nothing to
// check against, so the command prints structural facts and exits NON-ZERO: a
// script must never read "I could not check this" as success.
func TestVerifyIdentityBytesWithoutIssuerIsNotAVerdict(t *testing.T) {
	att, _ := mkAttestation(t)
	b, err := att.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	for _, jsonMode := range []bool{false, true} {
		if code := verifyIdentityBytes(b, jsonMode, identityVerifyOpts{}); code != 1 {
			t.Errorf("jsonMode=%v: exit %d, want 1 — no anchor means no verdict", jsonMode, code)
		}
	}
}

// TestVerifyIdentityBytesWithIssuer covers the pinned path in both directions,
// and the --at flag that makes a verdict reproducible: an expired credential
// still verifies when evaluated at a time its window covered.
func TestVerifyIdentityBytesWithIssuer(t *testing.T) {
	att, pub := mkAttestation(t)
	b, err := att.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "issuers.txt")
	if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if code := verifyIdentityBytes(b, false, identityVerifyOpts{issuerPath: keyFile}); code != 0 {
		t.Errorf("a pinned issuer must verify its own attestation, exit %d", code)
	}
	// Evaluated long after the window closed: a lifecycle outcome, exit 1.
	late := time.Now().UTC().Add(10 * 365 * 24 * time.Hour).Format(time.RFC3339)
	if code := verifyIdentityBytes(b, false, identityVerifyOpts{issuerPath: keyFile, at: late}); code != 1 {
		t.Errorf("an expired window must exit 1, got %d", code)
	}
	// Evaluated inside the window: still valid, which is what makes an old record
	// re-verifiable forever.
	inside := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	if code := verifyIdentityBytes(b, false, identityVerifyOpts{issuerPath: keyFile, at: inside}); code != 0 {
		t.Errorf("a time inside the window must verify, got %d", code)
	}
	// A malformed --at is a bad call, not a verdict about the artifact.
	if code := verifyIdentityBytes(b, false, identityVerifyOpts{issuerPath: keyFile, at: "yesterday"}); code != 1 {
		t.Errorf("an unparseable --at must exit 1, got %d", code)
	}
	// A stranger's key: unanchored, exit 1, and never a claim about the subject.
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	strangerFile := filepath.Join(dir, "stranger.txt")
	if err := os.WriteFile(strangerFile, []byte(base64.StdEncoding.EncodeToString(other)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := verifyIdentityBytes(b, false, identityVerifyOpts{issuerPath: strangerFile}); code != 1 {
		t.Errorf("an unpinned authority must exit 1, got %d", code)
	}
}

// TestLoadIssuerKeys covers both accepted forms and the failure modes, because
// this is the one function in the binary that turns an operator's file into a
// trust anchor.
func TestLoadIssuerKeys(t *testing.T) {
	dir := t.TempDir()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	line := string(ssh.MarshalAuthorizedKey(sshPub))

	both := filepath.Join(dir, "both.txt")
	content := "# the acme certificate authority\n\n" +
		base64.StdEncoding.EncodeToString(pub) + "\n" +
		line
	if err := os.WriteFile(both, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	keys, err := loadIssuerKeys(both)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("want 2 keys (base64 and ssh-ed25519), got %d", len(keys))
	}
	for i, k := range keys {
		if !k.Equal(pub) {
			t.Errorf("key %d does not match", i)
		}
	}

	empty := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(empty, []byte("# nothing here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadIssuerKeys(empty); err == nil {
		t.Error("a file with no keys must be an error, not an empty pin set")
	}

	junk := filepath.Join(dir, "junk.txt")
	if err := os.WriteFile(junk, []byte("this is not a key\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadIssuerKeys(junk); err == nil {
		t.Error("an unreadable key must be an error")
	}

	short := filepath.Join(dir, "short.txt")
	if err := os.WriteFile(short, []byte(base64.StdEncoding.EncodeToString([]byte("tooshort"))+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadIssuerKeys(short); err == nil {
		t.Error("a key of the wrong size must be an error")
	}

	if _, err := loadIssuerKeys(filepath.Join(dir, "absent.txt")); err == nil {
		t.Error("a missing file must be an error")
	}
}

// TestVerifyIdentityBytesRejectsAnUnparseableArtifact proves a broken file is a
// parse failure and not a verdict.
func TestVerifyIdentityBytesRejectsAnUnparseableArtifact(t *testing.T) {
	if code := verifyIdentityBytes([]byte(`{"netherchat_identity":"v1","nope":1}`), false, identityVerifyOpts{}); code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
}
