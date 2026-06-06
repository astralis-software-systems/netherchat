package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestPinStatus(t *testing.T) {
	fpr := "SHA256:Hk3realfingerprint"

	if got := pinStatus(TrustEntry{}, false, fpr); got != "unpinned ✗" {
		t.Errorf("no entry: %q", got)
	}
	if got := pinStatus(TrustEntry{KeysURL: "https://github.com/x.keys"}, true, fpr); got != "unpinned ✗" {
		t.Errorf("keys_url only (no fpr) should be unpinned: %q", got)
	}
	if got := pinStatus(TrustEntry{Fpr: fpr}, true, fpr); got != "pinned ✓" {
		t.Errorf("matching fpr: %q", got)
	}
	if got := pinStatus(TrustEntry{Fpr: "SHA256:somethingelse"}, true, fpr); !strings.Contains(got, "MISMATCH") {
		t.Errorf("mismatched fpr should warn: %q", got)
	}
}

func TestFetchKeysClientSide(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	target := ssh.FingerprintSHA256(sshPub)

	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	otherSSH, _ := ssh.NewPublicKey(otherPub)

	// A github.com/<user>.keys-style authorized_keys list (one match, one not).
	body := "# a comment line\n" +
		string(ssh.MarshalAuthorizedKey(otherSSH)) +
		string(ssh.MarshalAuthorizedKey(sshPub))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	msg := fetchKeys("bob", srv.URL, target)().(whoisFetchMsg)
	if msg.err != nil {
		t.Fatalf("fetch error: %v", msg.err)
	}
	if msg.count != 2 {
		t.Errorf("parsed %d keys, want 2", msg.count)
	}
	if !msg.found {
		t.Error("published fingerprint should have been found")
	}

	// A fingerprint that isn't published is reported as not found.
	miss := fetchKeys("bob", srv.URL, "SHA256:notpublishedanywhere")().(whoisFetchMsg)
	if miss.found {
		t.Error("unexpected match for an unpublished fingerprint")
	}
}
