package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/server/internal/alert"
)

// doAlert posts a raw alert body and returns the status code plus the response body
// text, so a rejection reason (e.g. "stale timestamp") can be asserted.
func doAlert(t *testing.T, base, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+"/api/v1/alert", strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post alert: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func signedSiem(ts int64) string {
	a := alert.AlertV1{Source: "siem", Severity: "high", Kind: "correlation", Summary: "lateral movement", TS: ts}
	a.Signature = hmacSig("s3cr3t", a)
	b, _ := json.Marshal(a)
	return string(b)
}

// TestAlertFreshSpawns is the end-to-end happy path: a legitimately fresh, signed,
// route-matching alert still spawns its war room.
func TestAlertFreshSpawns(t *testing.T) {
	ts, _ := ingressFixture(t)
	code, out := postAlert(t, ts.URL, signedSiem(time.Now().Unix()), "")
	if code != http.StatusOK || !out.Spawned {
		t.Fatalf("fresh signed alert should spawn: code=%d out=%+v", code, out)
	}
}

// TestAlertStaleRejected: a signed alert with an old ts is rejected with HTTP 400
// and the distinct, greppable "stale timestamp" reason — visible, not silently
// dropped, and distinguishable from 401 (auth) and 429 (rate/spawn).
func TestAlertStaleRejected(t *testing.T) {
	ts, _ := ingressFixture(t)
	stale := time.Now().Add(-time.Hour).Unix()
	code, text := doAlert(t, ts.URL, signedSiem(stale))
	if code != http.StatusBadRequest {
		t.Fatalf("stale alert: code = %d, want 400; body = %q", code, text)
	}
	if !strings.Contains(text, "stale timestamp") {
		t.Errorf("stale alert body = %q, want it to name %q", text, "stale timestamp")
	}
}

// TestAlertFutureRejected: a signed alert dated well into the future is rejected
// 400 with the "future timestamp" reason.
func TestAlertFutureRejected(t *testing.T) {
	ts, _ := ingressFixture(t)
	future := time.Now().Add(time.Hour).Unix()
	code, text := doAlert(t, ts.URL, signedSiem(future))
	if code != http.StatusBadRequest {
		t.Fatalf("future alert: code = %d, want 400; body = %q", code, text)
	}
	if !strings.Contains(text, "future timestamp") {
		t.Errorf("future alert body = %q, want it to name %q", text, "future timestamp")
	}
}

// TestAlertTSZeroBaselineStillSpawns: under the enforce-if-present baseline an HMAC
// source that sends no timestamp (ts==0) is NOT broken — it still spawns. (This is
// also the back-compat guarantee for existing adapters that omit ts.)
func TestAlertTSZeroBaselineStillSpawns(t *testing.T) {
	ts, _ := ingressFixture(t)
	code, out := postAlert(t, ts.URL, signedSiem(0), "")
	if code != http.StatusOK || !out.Spawned {
		t.Fatalf("ts==0 baseline should still spawn: code=%d out=%+v", code, out)
	}
}

// TestConfigValidateRejectsRequireFreshWithoutHMAC: the fail-closed config check
// surfaces through POST /api/v1/config/validate as valid:false.
func TestConfigValidateRejectsRequireFreshWithoutHMAC(t *testing.T) {
	ts, _ := ingressFixture(t)
	body := "[[source]]\nname = \"tok\"\ntoken = \"t\"\nrequire_fresh = true\n"
	resp, err := http.Post(ts.URL+"/api/v1/config/validate", "application/toml", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post config/validate: %v", err)
	}
	defer resp.Body.Close()
	var out struct {
		Valid bool   `json:"valid"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Valid {
		t.Fatalf("require_fresh without hmac_secret should validate as false; got %+v", out)
	}
}
