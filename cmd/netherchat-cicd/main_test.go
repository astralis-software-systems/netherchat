package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/salehkreiner/netherchat/connector"
)

func TestTranslateFailedPassed(t *testing.T) {
	failed, ok := translate(ciFields{Status: "failed", Job: "build", Repo: "acme/api", Commit: "0123456789abcdef", RunID: "42"}, "ci")
	if !ok {
		t.Fatal("failed should translate")
	}
	if failed.Kind != "ci-failure" || failed.Severity != "high" {
		t.Fatalf("failed schema: %+v", failed)
	}
	if failed.Summary != "build failed on acme/api@0123456" || failed.Ref != "42" {
		t.Fatalf("failed summary/ref = %q / %q", failed.Summary, failed.Ref)
	}
	passed, ok := translate(ciFields{Status: "passed", Job: "build", Repo: "acme/api", Commit: "0123456789abcdef", RunID: "43"}, "ci")
	if !ok {
		t.Fatal("passed should translate")
	}
	if passed.Kind != "ci-resolved" || passed.Severity != "info" {
		t.Fatalf("passed schema: %+v", passed)
	}
	if passed.Summary != "build passed on acme/api@0123456" {
		t.Fatalf("passed summary = %q", passed.Summary)
	}
	if _, ok := translate(ciFields{Status: "running"}, "ci"); ok {
		t.Error("a non-terminal status must not translate")
	}
}

func TestParseGitHub(t *testing.T) {
	failBody := `{"action":"completed","workflow_run":{"name":"CI","conclusion":"failure","id":99,"head_sha":"abcdef1234567890"},"repository":{"full_name":"acme/api"}}`
	f, forward, err := parseGitHub([]byte(failBody))
	if err != nil || !forward {
		t.Fatalf("github fail: forward=%v err=%v", forward, err)
	}
	if f.Status != "failed" || f.Job != "CI" || f.Repo != "acme/api" || f.RunID != "99" {
		t.Fatalf("github fields = %+v", f)
	}
	// success → passed
	okBody := `{"action":"completed","workflow_run":{"name":"CI","conclusion":"success","id":100,"head_sha":"abcdef1"},"repository":{"full_name":"acme/api"}}`
	if f, forward, _ := parseGitHub([]byte(okBody)); !forward || f.Status != "passed" {
		t.Errorf("github success should be passed, got forward=%v status=%q", forward, f.Status)
	}
	// in_progress / cancelled → not forwarded
	if _, forward, _ := parseGitHub([]byte(`{"action":"in_progress","workflow_run":{"conclusion":""}}`)); forward {
		t.Error("in_progress must not forward")
	}
	if _, forward, _ := parseGitHub([]byte(`{"action":"completed","workflow_run":{"conclusion":"cancelled"}}`)); forward {
		t.Error("cancelled must not forward")
	}
}

func TestParseGitLab(t *testing.T) {
	body := `{"object_kind":"pipeline","object_attributes":{"id":7,"status":"failed","sha":"deadbeefcafef00d","ref":"main"},"project":{"path_with_namespace":"grp/proj"}}`
	f, forward, err := parseGitLab([]byte(body))
	if err != nil || !forward {
		t.Fatalf("gitlab fail: forward=%v err=%v", forward, err)
	}
	if f.Status != "failed" || f.Job != "pipeline" || f.Repo != "grp/proj" || f.RunID != "7" {
		t.Fatalf("gitlab fields = %+v", f)
	}
	if _, forward, _ := parseGitLab([]byte(`{"object_kind":"pipeline","object_attributes":{"status":"running"}}`)); forward {
		t.Error("running pipeline must not forward")
	}
}

func githubSig(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// runHandle drives the handler against a capture relay, with provider auth headers.
func runHandle(t *testing.T, ad *adapter, payload string, headers map[string]string) (forwarded []byte, status int) {
	t.Helper()
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded, _ = io.ReadAll(r.Body)
		_, _ = io.WriteString(w, `{"accepted":true,"spawned":true,"room":"inc-x"}`)
	}))
	defer relay.Close()
	ad.client = &connector.Client{Server: relay.URL, Token: "t"}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(payload))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	ad.handle(rec, req)
	return forwarded, rec.Code
}

func TestGitHubHMACValidation(t *testing.T) {
	secret := []byte("gh-webhook-secret")
	ad := &adapter{ci: "github", source: "ci", githubSecret: secret}
	body := `{"action":"completed","workflow_run":{"name":"CI","conclusion":"failure","id":1,"head_sha":"abc1234def"},"repository":{"full_name":"acme/api"}}`

	// Valid signature → forwarded.
	fwd, code := runHandle(t, ad, body, map[string]string{"X-Hub-Signature-256": githubSig(secret, []byte(body))})
	if code != http.StatusOK || fwd == nil {
		t.Fatalf("valid sig should forward: code=%d", code)
	}
	if !bytes.Contains(fwd, []byte(`"ci-failure"`)) {
		t.Errorf("expected ci-failure kind: %s", fwd)
	}
	// Wrong signature → 401, nothing forwarded.
	fwd2, code2 := runHandle(t, ad, body, map[string]string{"X-Hub-Signature-256": githubSig([]byte("attacker"), []byte(body))})
	if code2 != http.StatusUnauthorized {
		t.Fatalf("bad sig status = %d, want 401", code2)
	}
	if fwd2 != nil {
		t.Fatal("bad signature must forward nothing")
	}
	// Missing signature → 401.
	if _, code3 := runHandle(t, ad, body, nil); code3 != http.StatusUnauthorized {
		t.Errorf("missing sig status = %d, want 401", code3)
	}
}

func TestGitLabTokenValidation(t *testing.T) {
	ad := &adapter{ci: "gitlab", source: "ci", gitlabToken: "gl-secret-token"}
	body := `{"object_kind":"pipeline","object_attributes":{"id":7,"status":"success","sha":"deadbeef","ref":"main"},"project":{"path_with_namespace":"grp/proj"}}`

	fwd, code := runHandle(t, ad, body, map[string]string{"X-Gitlab-Token": "gl-secret-token"})
	if code != http.StatusOK || fwd == nil {
		t.Fatalf("valid token should forward: code=%d", code)
	}
	if !bytes.Contains(fwd, []byte(`"ci-resolved"`)) {
		t.Errorf("expected ci-resolved kind: %s", fwd)
	}
	fwd2, code2 := runHandle(t, ad, body, map[string]string{"X-Gitlab-Token": "wrong"})
	if code2 != http.StatusUnauthorized || fwd2 != nil {
		t.Fatalf("bad token: code=%d forwarded=%s", code2, fwd2)
	}
}

// TestBoundaryLawGitHub is mandatory: commit messages, logs, and any field beyond
// the seven allowed alert fields must never reach the forwarded body.
func TestBoundaryLawGitHub(t *testing.T) {
	secret := []byte("s")
	ad := &adapter{ci: "github", source: "ci", githubSecret: secret}
	body := `{"action":"completed","workflow_run":{"name":"CI","conclusion":"failure","id":1,"head_sha":"abc1234def","head_commit":{"message":"SECRET_COMMIT_MSG"},"logs_url":"https://SECRET_LOGS"},"repository":{"full_name":"acme/api"},"sender":{"login":"SECRET_USER"}}`
	fwd, code := runHandle(t, ad, body, map[string]string{"X-Hub-Signature-256": githubSig(secret, []byte(body))})
	if code != http.StatusOK || fwd == nil {
		t.Fatalf("expected forward, code=%d", code)
	}
	extra, err := connector.UnexpectedFields(fwd)
	if err != nil {
		t.Fatalf("decode forwarded body: %v", err)
	}
	if len(extra) != 0 {
		t.Fatalf("boundary violated: unexpected fields %v in %s", extra, fwd)
	}
	for _, leak := range []string{"SECRET_COMMIT_MSG", "SECRET_LOGS", "SECRET_USER", "head_commit", "logs_url", "sender", "workflow_run"} {
		if bytes.Contains(fwd, []byte(leak)) {
			t.Fatalf("boundary violated: %q present in forwarded body %s", leak, fwd)
		}
	}
}

func TestNormalizeStatus(t *testing.T) {
	for _, in := range []string{"failed", "failure", "error"} {
		if normalizeStatus(in) != "failed" {
			t.Errorf("%q should normalize to failed", in)
		}
	}
	for _, in := range []string{"passed", "success", "ok"} {
		if normalizeStatus(in) != "passed" {
			t.Errorf("%q should normalize to passed", in)
		}
	}
	if normalizeStatus("running") != "" {
		t.Error("running should normalize to empty")
	}
}
