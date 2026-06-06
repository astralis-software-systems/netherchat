package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestSSHKeyFileFingerprintMatchesSSH is the acceptance anchor: an identity
// loaded from an OpenSSH Ed25519 key file produces exactly the fingerprint
// ssh-keygen / ssh.FingerprintSHA256 produces for the same key.
func TestSSHKeyFileFingerprintMatchesSSH(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	block, err := ssh.MarshalPrivateKey(priv, "byo@netherchat")
	if err != nil {
		t.Fatalf("marshal openssh key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	id, err := identityFromSSHKeyFile(path, "~/.ssh/id_ed25519", false)
	if err != nil {
		t.Fatalf("load ssh key: %v", err)
	}

	sshPub, _ := ssh.NewPublicKey(pub)
	want := ssh.FingerprintSHA256(sshPub)
	if id.Fingerprint() != want {
		t.Fatalf("fingerprint mismatch:\n got %s\nwant %s", id.Fingerprint(), want)
	}
	if !strings.HasPrefix(id.Fingerprint(), "SHA256:") {
		t.Errorf("fingerprint not in ssh-keygen format: %s", id.Fingerprint())
	}

	// The loaded identity must sign verifiably and have a working derived KX key.
	sig, err := id.Sign([]byte("hi"))
	if err != nil || !ed25519.Verify(id.SignPub, []byte("hi"), sig) {
		t.Fatalf("signing broken: err=%v", err)
	}
	rk, _ := NewRoomKey(0)
	if _, _, err := id.WrapRoomKey(rk, id.KXPub); err != nil {
		t.Fatalf("derived KX key unusable: %v", err)
	}
}

// TestAgeIdentityRoundTrip checks the Bech32 decoder and the age load path: a
// 32-byte secret encoded as an AGE-SECRET-KEY decodes back to the same bytes and
// yields a working identity.
func TestAgeIdentityRoundTrip(t *testing.T) {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}

	encoded, err := bech32Encode(ageSecretHRP, secret[:])
	if err != nil {
		t.Fatalf("bech32 encode: %v", err)
	}
	// Round-trip the codec.
	decoded, err := decodeBech32(encoded, ageSecretHRP)
	if err != nil {
		t.Fatalf("bech32 decode: %v", err)
	}
	if [32]byte(decoded) != secret {
		t.Fatal("bech32 round-trip changed the secret")
	}

	// age files store the key uppercase; our loader lowercases internally.
	ageFile := "# created: 2026-06-06\n# public key: age1example\n" + strings.ToUpper(encoded) + "\n"
	if !isAgeIdentity([]byte(ageFile)) {
		t.Fatal("isAgeIdentity did not recognize an age file")
	}
	id, err := identityFromAgeFile([]byte(ageFile), "age:test")
	if err != nil {
		t.Fatalf("load age identity: %v", err)
	}
	if id.Source != "age:test" {
		t.Errorf("source = %q", id.Source)
	}
	// Deterministic: the same age secret always yields the same identity.
	id2, _ := identityFromAgeFile([]byte(ageFile), "age:test")
	if id.Fingerprint() != id2.Fingerprint() {
		t.Error("age identity is not deterministic")
	}
}

// TestBech32RejectsCorruption ensures the checksum actually guards against typos.
func TestBech32RejectsCorruption(t *testing.T) {
	good, _ := bech32Encode(ageSecretHRP, make([]byte, 32))
	bad := []byte(good)
	// Flip a character in the data section (after the '1' separator).
	i := strings.LastIndexByte(good, '1') + 3
	if bad[i] == 'q' {
		bad[i] = 'p'
	} else {
		bad[i] = 'q'
	}
	if _, err := decodeBech32(string(bad), ageSecretHRP); err == nil {
		t.Fatal("expected a checksum failure on corrupted bech32")
	}
}

// TestFingerprintAgainstSSHKeygen loads the key at NETHERCHAT_TEST_KEY and prints
// its Netherchat fingerprint, so it can be compared against `ssh-keygen -lf`. It
// is skipped unless that env var is set.
func TestFingerprintAgainstSSHKeygen(t *testing.T) {
	path := os.Getenv("NETHERCHAT_TEST_KEY")
	if path == "" {
		t.Skip("set NETHERCHAT_TEST_KEY=<path to id_ed25519> to compare against ssh-keygen")
	}
	id, err := ResolveIdentity(path)
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	t.Logf("NETHERCHAT_FINGERPRINT=%s source=%s", id.Fingerprint(), id.Source)
}

// bech32Encode is a test helper that mirrors the production decoder (BIP-173).
func bech32Encode(hrp string, data []byte) (string, error) {
	ints := make([]int, len(data))
	for i, b := range data {
		ints[i] = int(b)
	}
	grouped, err := convertBits(ints, 8, 5, true)
	if err != nil {
		return "", err
	}
	five := make([]int, len(grouped))
	for i, b := range grouped {
		five[i] = int(b)
	}
	checksum := bech32CreateChecksum(hrp, five)
	var sb strings.Builder
	sb.WriteString(hrp)
	sb.WriteByte('1')
	for _, v := range append(five, checksum...) {
		sb.WriteByte(bech32Charset[v])
	}
	return sb.String(), nil
}

func bech32CreateChecksum(hrp string, data []int) []int {
	values := append(bech32HRPExpand(hrp), data...)
	polymod := bech32Polymod(append(values, 0, 0, 0, 0, 0, 0)) ^ 1
	out := make([]int, 6)
	for i := 0; i < 6; i++ {
		out[i] = (polymod >> uint(5*(5-i))) & 31
	}
	return out
}
