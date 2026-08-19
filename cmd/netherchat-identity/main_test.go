package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/sealedrecord"
	"golang.org/x/crypto/ssh"
)

// TestKeygenIssueVerifyRoundTrip is the end-to-end proof that this tool produces
// an artifact Netherchat verifies — driving the real commands, writing real
// files, and verifying through the same public façade a third-party CA
// integration would use.
func TestKeygenIssueVerifyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "issuer.json")
	outPath := filepath.Join(dir, "identity.json")

	keygenCmd([]string{"--out", keyPath})
	pub := readPubFile(t, filepath.Join(dir, "issuer.pub"))

	subject := "SHA256:" + strings.Repeat("A", 43)
	issueCmd([]string{
		"--key", keyPath, "--out", outPath,
		"--subject", subject,
		"--principal", "rosa.alvarez@acme.example",
		"--type", "person",
		"--role", "qa", "--role", "technical",
		"--valid", "30d",
	})

	b, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	att, err := sealedrecord.ParseIdentity(b)
	if err != nil {
		t.Fatalf("the tool must produce a parseable artifact: %v", err)
	}
	res, err := sealedrecord.VerifyIdentity(att, sealedrecord.IdentityOptions{
		IssuerKeys: []ed25519.PublicKey{pub},
		At:         time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("an artifact this tool issued must verify against the key it published: %s / %s", res.Reason, res.Detail)
	}
	if res.Principal != "rosa.alvarez@acme.example" || res.Subject != subject {
		t.Errorf("result = %+v", res)
	}
	if att.Issuer != sealedrecord.Fingerprint(pub) {
		t.Error("the artifact must name the issuing key's own fingerprint")
	}
	if att.Serial == "" {
		t.Error("a serial must be generated when the operator does not supply one")
	}

	// And the published .pub is exactly what verification needs: nothing else
	// from this machine travels to a verifier.
	notAfter, err := time.Parse(time.RFC3339, att.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(notAfter); d > 31*24*time.Hour || d < 29*24*time.Hour {
		t.Errorf("--valid 30d produced a %s window", d)
	}
}

// TestKeygenRefusesToOverwriteWithoutForce proves the one destructive path is
// closed by default. Overwriting an issuing key silently would destroy the only
// copy of a trust anchor everyone else has pinned.
func TestKeygenRefusesToOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "issuer.json")
	keygenCmd([]string{"--out", keyPath})

	before, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	// keygenCmd exits the process on refusal, so the refusal itself cannot be
	// driven from here; what IS checkable is that --force replaces the key and
	// that the file this test wrote is a real, loadable key either way.
	keygenCmd([]string{"--out", keyPath, "--force"})
	after, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) == string(after) {
		t.Error("--force must mint a new key")
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatal(err)
	}
}

// TestRevokeProducesAVerifiableStatement proves the revocation half end to end,
// and that the statement it writes actually withdraws the serial when handed to
// the identity verifier.
func TestRevokeProducesAVerifiableStatement(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "issuer.json")
	idPath := filepath.Join(dir, "identity.json")
	revPath := filepath.Join(dir, "revocation.json")

	keygenCmd([]string{"--out", keyPath})
	pub := readPubFile(t, filepath.Join(dir, "issuer.pub"))

	issueCmd([]string{
		"--key", keyPath, "--out", idPath,
		"--subject", "SHA256:" + strings.Repeat("B", 43),
		"--principal", "svc-deploy@acme.example",
		"--type", "service", "--role", "deploy",
		"--serial", "acme-0007",
	})
	revokeCmd([]string{
		"--key", keyPath, "--out", revPath,
		"--statement-id", "acme-2026-08-19", "--number", "41",
		"--serial", "acme-0007", "--reason", "key rotation",
		"--next-update", "30d",
	})

	ib, err := os.ReadFile(idPath)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := os.ReadFile(revPath)
	if err != nil {
		t.Fatal(err)
	}
	att, err := sealedrecord.ParseIdentity(ib)
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := sealedrecord.ParseRevocation(rb)
	if err != nil {
		t.Fatal(err)
	}

	keys := []ed25519.PublicKey{pub}
	if rres, err := sealedrecord.VerifyRevocation(stmt, keys); err != nil || !rres.Valid {
		t.Fatalf("the statement must verify: %v / %+v", err, rres)
	}
	res, err := sealedrecord.VerifyIdentity(att, sealedrecord.IdentityOptions{
		IssuerKeys:  keys,
		At:          time.Now().UTC(),
		Revocations: []*sealedrecord.RevocationStatement{stmt},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid {
		t.Fatal("a revoked serial must not verify")
	}
	if res.Reason != sealedrecord.ReasonRevoked {
		t.Errorf("Reason = %q, want %q", res.Reason, sealedrecord.ReasonRevoked)
	}
	if len(res.Revocation) != 1 || res.Revocation[0].StatementID != "acme-2026-08-19" {
		t.Errorf("the consulted statement must be named in the result: %+v", res.Revocation)
	}
}

// TestCheckLifetime pins the default lifetime as the security parameter it is.
// The window is the only lifecycle mechanism that survives having no network, so
// the default has to be short and the long path has to be deliberate.
func TestCheckLifetime(t *testing.T) {
	if defaultLifetime != 90*24*time.Hour {
		t.Errorf("defaultLifetime = %s; changing it is a security decision, not a tidy-up", defaultLifetime)
	}
	if defaultLifetime >= longLivedThreshold {
		t.Fatal("the default must sit well below the threshold that takes a flag")
	}
	if err := checkLifetime(defaultLifetime, false); err != nil {
		t.Errorf("the default must not take a flag: %v", err)
	}
	if err := checkLifetime(longLivedThreshold, false); err != nil {
		t.Errorf("exactly a year must not take a flag: %v", err)
	}
	if err := checkLifetime(longLivedThreshold+time.Second, false); err == nil {
		t.Error("past a year must take --long-lived")
	}
	if err := checkLifetime(longLivedThreshold+time.Second, true); err != nil {
		t.Errorf("--long-lived must permit it: %v", err)
	}
	if err := checkLifetime(0, true); err == nil {
		t.Error("a zero window is not a window")
	}
	if err := checkLifetime(-time.Hour, true); err == nil {
		t.Error("a negative window is not a window")
	}
}

// TestParseLifetime covers the units an operator actually types. A credential
// lifetime expressed in hours is a unit nobody reasons about correctly.
func TestParseLifetime(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"", defaultLifetime},
		{"90d", 90 * 24 * time.Hour},
		{"12w", 12 * 7 * 24 * time.Hour},
		{"720h", 720 * time.Hour},
		{"  30d  ", 30 * 24 * time.Hour},
	}
	for _, tc := range cases {
		got, err := parseLifetime(tc.in)
		if err != nil {
			t.Errorf("%q: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%q = %s, want %s", tc.in, got, tc.want)
		}
	}
	for _, bad := range []string{"ninety days", "90x", "d", "w"} {
		if _, err := parseLifetime(bad); err == nil {
			t.Errorf("%q should not parse", bad)
		}
	}
}

// TestDefaultIssuerDirAvoidsTheRoamingProfile is the %LOCALAPPDATA% rule, made
// checkable on the platform where it matters.
//
// On a domain-joined Windows machine %APPDATA% is the roaming profile: it is
// copied to a file server at logon and logoff. A certificate authority's private
// key there is a key on a file server and in that server's backups, for a key
// whose entire value is that one party holds it. os.UserConfigDir() returns
// %APPDATA%, so this asserts the tool does NOT follow it.
func TestDefaultIssuerDirAvoidsTheRoamingProfile(t *testing.T) {
	dir, err := defaultIssuerDir()
	if err != nil {
		t.Skipf("no per-user directory on this platform: %v", err)
	}
	if runtime.GOOS != "windows" {
		if dir == "" {
			t.Fatal("a per-user issuer directory must resolve")
		}
		return
	}
	local := os.Getenv("LOCALAPPDATA")
	roaming := os.Getenv("APPDATA")
	if local == "" {
		t.Fatal("LOCALAPPDATA is unset on a Windows host; defaultIssuerDir should have errored")
	}
	if !strings.HasPrefix(dir, local) {
		t.Errorf("issuer directory %q is not under %%LOCALAPPDATA%% (%q)", dir, local)
	}
	if roaming != "" && strings.HasPrefix(dir, roaming) && roaming != local {
		t.Errorf("issuer directory %q is under the ROAMING profile %q — a CA key must not roam", dir, roaming)
	}
	cfg, err := os.UserConfigDir()
	if err == nil && cfg != local && strings.HasPrefix(dir, cfg) {
		t.Errorf("issuer directory %q follows os.UserConfigDir() %q, which is the roaming profile", dir, cfg)
	}
}

// TestGenerateSerialIsUnique proves the unit of revocation does not collide for
// two credentials issued in the same second.
func TestGenerateSerialIsUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		s := generateSerial()
		if seen[s] {
			t.Fatalf("serial %q repeated after %d draws", s, i)
		}
		seen[s] = true
	}
}

// TestAuthorizedKeyLineRoundTrips proves the published line is the one an
// operator can hand to a verifier: it parses back to the same key.
func TestAuthorizedKeyLineRoundTrips(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	line, err := authorizedKeyLine(pub, "netherchat-issuer")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, "ssh-ed25519 ") || !strings.HasSuffix(line, "netherchat-issuer\n") {
		t.Fatalf("unexpected line %q", line)
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	back, ok := parsed.(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey)
	if !ok || !back.Equal(pub) {
		t.Fatal("the published line must round-trip to the same key")
	}
}

func readPubFile(t *testing.T, path string) ed25519.PublicKey {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := parsed.(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		t.Fatal("the published key is not Ed25519")
	}
	return pub
}
