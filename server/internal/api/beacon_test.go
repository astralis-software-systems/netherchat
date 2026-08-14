package api

import (
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/salehkreiner/netherchat/server/config"
)

// beaconWrite issues a token-gated beacon request and returns the status code. An
// empty token sends no header at all — the missing-token case, which must never
// be mistaken for a match. room may carry a query string so the ?token= form can
// be exercised alongside the header.
func beaconWrite(t *testing.T, base, method, room, token, body string) int {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, base+"/beacon/"+room, r)
	if err != nil {
		t.Fatalf("build %s /beacon/%s: %v", method, room, err)
	}
	if token != "" {
		req.Header.Set("X-Netherchat-Token", token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s /beacon/%s: %v", method, room, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// TestBeaconAuthBehavior: the constant-time compare still authenticates correctly
// on BOTH write endpoints — the right token passes, a wrong/missing/prefix token
// 401s, the room's webhook_token is honoured as the documented fallback (the same
// secret the webhook receiver compares, now compared the same way), and a room
// with neither token is 404 because beacons are opt-in rather than unauthorized.
func TestBeaconAuthBehavior(t *testing.T) {
	cfg := config.Default()
	cfg.Rooms = map[string]config.RoomConfig{
		"ops":    {BeaconToken: "beaconA"},
		"alerts": {Webhook: true, WebhookToken: "secretA"}, // no beacon_token → webhook fallback
	}
	ts, _ := webhookServer(t, cfg)

	body := `{"ciphertext":"` + base64.StdEncoding.EncodeToString([]byte("opaque")) + `","ttl_seconds":3600}`

	if code := beaconWrite(t, ts.URL, http.MethodPut, "ops", "beaconA", body); code != http.StatusOK {
		t.Errorf("correct token should pass, got %d", code)
	}
	if code := beaconWrite(t, ts.URL, http.MethodPut, "ops", "nope", body); code != http.StatusUnauthorized {
		t.Errorf("wrong token should be 401, got %d", code)
	}
	if code := beaconWrite(t, ts.URL, http.MethodPut, "ops", "", body); code != http.StatusUnauthorized {
		t.Errorf("missing token should be 401, got %d", code)
	}
	// A prefix of the real token must fail exactly like an unrelated one.
	if code := beaconWrite(t, ts.URL, http.MethodPut, "ops", "beacon", body); code != http.StatusUnauthorized {
		t.Errorf("token prefix should be 401, got %d", code)
	}
	// The ?token= form is the other half of beaconToken and is gated identically.
	if code := beaconWrite(t, ts.URL, http.MethodPut, "ops?token=beaconA", "", body); code != http.StatusOK {
		t.Errorf("correct ?token= should pass, got %d", code)
	}
	if code := beaconWrite(t, ts.URL, http.MethodPut, "ops?token=nope", "", body); code != http.StatusUnauthorized {
		t.Errorf("wrong ?token= should be 401, got %d", code)
	}

	// DELETE is the second, easily-forgotten call site: it gates on the same token.
	if code := beaconWrite(t, ts.URL, http.MethodDelete, "ops", "nope", ""); code != http.StatusUnauthorized {
		t.Errorf("DELETE with a wrong token should be 401, got %d", code)
	}
	if code := beaconWrite(t, ts.URL, http.MethodDelete, "ops", "", ""); code != http.StatusUnauthorized {
		t.Errorf("DELETE with no token should be 401, got %d", code)
	}
	if code := beaconWrite(t, ts.URL, http.MethodDelete, "ops", "beaconA", ""); code != http.StatusOK {
		t.Errorf("DELETE with the correct token should pass, got %d", code)
	}

	// webhook_token fallback: the room has no beacon_token, so BeaconAuth reuses the
	// webhook secret — and a different room's beacon token is still no good here.
	if code := beaconWrite(t, ts.URL, http.MethodPut, "alerts", "secretA", body); code != http.StatusOK {
		t.Errorf("webhook_token fallback should pass, got %d", code)
	}
	if code := beaconWrite(t, ts.URL, http.MethodPut, "alerts", "beaconA", body); code != http.StatusUnauthorized {
		t.Errorf("another room's token should be 401, got %d", code)
	}

	// Neither token configured: the beacon is not enabled at all.
	if code := beaconWrite(t, ts.URL, http.MethodPut, "general", "anything", body); code != http.StatusNotFound {
		t.Errorf("PUT to a room with no beacon should be 404, got %d", code)
	}
	if code := beaconWrite(t, ts.URL, http.MethodDelete, "general", "anything", ""); code != http.StatusNotFound {
		t.Errorf("DELETE on a room with no beacon should be 404, got %d", code)
	}
}

// TestBeaconRejectionLogsMetadataOnly: a refused beacon write is recorded, so a
// run of guesses against a room's token is at least visible to the operator
// reading the logs — and the record carries metadata only. Neither the guess nor
// the real token may appear: a log file has none of the protections the token
// itself gets, and echoing a near miss back would leak most of a live secret.
func TestBeaconRejectionLogsMetadataOnly(t *testing.T) {
	cfg := config.Default()
	cfg.Rooms = map[string]config.RoomConfig{"ops": {BeaconToken: "beaconA"}}
	ts, logs := webhookServer(t, cfg)

	body := `{"ciphertext":"` + base64.StdEncoding.EncodeToString([]byte("opaque")) + `","ttl_seconds":3600}`
	if code := beaconWrite(t, ts.URL, http.MethodPut, "ops", "beaconB", body); code != http.StatusUnauthorized {
		t.Fatalf("PUT with a wrong token should be 401, got %d", code)
	}
	if code := beaconWrite(t, ts.URL, http.MethodDelete, "ops", "beaconB", ""); code != http.StatusUnauthorized {
		t.Fatalf("DELETE with a wrong token should be 401, got %d", code)
	}

	got := logs.String()
	// Both call sites log, and the method distinguishes them.
	for _, want := range []string{"beacon rejected: invalid or missing token", "room=ops", "method=PUT", "method=DELETE"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in the logs; got:\n%s", want, got)
		}
	}
	// The guess and the configured token are both secrets. (The prefix probe from
	// the test above is not checkable this way — "beacon" is a substring of the
	// handler's own message — which is the other reason the reason string is fixed
	// text: nothing the caller sends can reach the log to be confused for it.)
	for _, secret := range []string{"beaconB", "beaconA"} {
		if strings.Contains(got, secret) {
			t.Errorf("the logs echoed %q; a beacon rejection must record metadata only:\n%s", secret, got)
		}
	}
}

// TestBeaconAuthorizedRejectsEmptyWant covers the one case no request can reach:
// BeaconAuth reports enabled=false for a room with no token, so the handlers 404
// before ever calling beaconAuthorized with an empty want — which is exactly why
// the guard has to be asserted here instead. An unset token must not be something
// an absent header can match.
func TestBeaconAuthorizedRejectsEmptyWant(t *testing.T) {
	req, err := http.NewRequest(http.MethodPut, "http://relay.invalid/beacon/ops", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if beaconAuthorized(req, "") {
		t.Error("an empty want must never authorize, not even a request carrying no token")
	}
	req.Header.Set("X-Netherchat-Token", "")
	if beaconAuthorized(req, "") {
		t.Error("an empty header must never satisfy an empty want")
	}

	// Positive control, so the two rejections above are the empty want doing its
	// job rather than a request this helper cannot read a token out of at all.
	req.Header.Set("X-Netherchat-Token", "beaconA")
	if !beaconAuthorized(req, "beaconA") {
		t.Error("a correct token should authorize")
	}
}
