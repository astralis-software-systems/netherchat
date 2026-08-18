package e2e

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/eventlog"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

const beaconToken = "beacon-secret"

// notEnabled is the relay's own sentence for "this room has no beacon", written
// verbatim by server/internal/api/beacon.go. It is the only thing that
// distinguishes that 404 from a proxy that never forwarded /beacon/ at all.
const notEnabled = "beacon is not enabled for this room"

func beaconConfig() config.Config {
	c := config.Default()
	c.Rooms = map[string]config.RoomConfig{"ops": {BeaconToken: beaconToken}}
	return c
}

func httpGet(t *testing.T, url string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, body
}

// beaconReq returns the status code AND the response body. The body is returned
// because it is where the relay says what went wrong: every failure path in
// server/internal/api/beacon.go writes a specific sentence, and the status code
// alone cannot distinguish "this room has no beacon" from a reverse proxy that
// never forwarded /beacon/ at all — both are 404.
func beaconReq(t *testing.T, method, url, token, body string) (int, string) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, url, r)
	if token != "" {
		req.Header.Set("X-Netherchat-Token", token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, strings.TrimSpace(string(respBody))
}

// TestBeaconRESTEndpoints proves the PUT/GET/DELETE contract (§1.2): writes need
// the beacon token, reads need no auth, a non-beacon room rejects writes, and
// delete makes the beacon 404.
func TestBeaconRESTEndpoints(t *testing.T) {
	ts := httptest.NewServer(server.Handler(beaconConfig(), quietLogger()))
	defer ts.Close()
	base := ts.URL + "/beacon/ops"

	cipherB64 := base64.StdEncoding.EncodeToString([]byte("opaque-ciphertext-blob"))
	body := `{"ciphertext":"` + cipherB64 + `","ttl_seconds":3600}`

	if code, _ := beaconReq(t, "PUT", base, "", body); code != http.StatusUnauthorized {
		t.Fatalf("PUT no token = %d, want 401", code)
	}
	if code, _ := beaconReq(t, "PUT", base, "wrong", body); code != http.StatusUnauthorized {
		t.Fatalf("PUT wrong token = %d, want 401", code)
	}
	if code, _ := beaconReq(t, "PUT", base, beaconToken, body); code != http.StatusOK {
		t.Fatalf("PUT valid token = %d, want 200", code)
	}

	// GET requires NO auth and returns the stored ciphertext + a timestamp.
	resp, raw := httpGet(t, base)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET = %d, want 200", resp.StatusCode)
	}
	var got struct {
		Ciphertext string `json:"ciphertext"`
		UpdatedAt  string `json:"updated_at"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("GET body: %v", err)
	}
	if got.Ciphertext != cipherB64 {
		t.Fatalf("GET ciphertext = %q, want %q", got.Ciphertext, cipherB64)
	}
	if got.UpdatedAt == "" {
		t.Error("GET is missing updated_at")
	}

	// DELETE needs the token; afterwards GET is 404.
	if code, _ := beaconReq(t, "DELETE", base, beaconToken, ""); code != http.StatusOK {
		t.Fatalf("DELETE = %d, want 200", code)
	}
	if resp, _ := httpGet(t, base); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET after delete = %d, want 404", resp.StatusCode)
	}

	// A room with no beacon_token cannot have a beacon set (opt-in only), and the
	// relay says which of the several 404s this is.
	code, why := beaconReq(t, "PUT", ts.URL+"/beacon/general", "anything", body)
	if code != http.StatusNotFound {
		t.Fatalf("PUT to a non-beacon room = %d, want 404", code)
	}
	if !strings.Contains(why, notEnabled) {
		t.Fatalf("404 body = %q, want it to contain %q", why, notEnabled)
	}

	// And the sentence has to survive into what the operator is shown. This half is
	// the one that matters: asserting the status code alone was the reason B4 stayed
	// invisible for as long as it did — the check reproduced exactly the information
	// the client kept, so the information the client threw away could not be missed.
	// `404 Not Found` is also what a reverse proxy that never forwarded /beacon/
	// returns, and the two have completely different remedies.
	alice := connect(t, ts.URL, "general", "alice", "")
	waitMatch[client.EvKeyReady](t, alice, nil, 5*time.Second)
	alice.UseBeaconToken("anything")
	alice.SetBeacon("SEV1 declared", 3600)
	res := waitMatch[client.EvBeaconResult](t, alice, func(e client.EvBeaconResult) bool {
		return e.Action == "set"
	}, 5*time.Second)
	if res.OK {
		t.Fatal("/beacon set succeeded against a room with no beacon_token")
	}
	if !strings.Contains(res.Err, notEnabled) {
		t.Fatalf("client reported %q; the relay's reason did not survive the round trip", res.Err)
	}
}

// TestBeaconClientRoundTrip is the demo path through the client: /beacon set
// encrypts to the beacon key (the relay stores only ciphertext it cannot read),
// /beacon status decrypts locally, the beacon-link key decrypts the SAME status,
// and /beacon clear removes it.
func TestBeaconClientRoundTrip(t *testing.T) {
	ts := httptest.NewServer(server.Handler(beaconConfig(), quietLogger()))
	defer ts.Close()

	alice := connect(t, ts.URL, "ops", "alice", "")
	waitMatch[client.EvKeyReady](t, alice, nil, 5*time.Second)
	alice.UseBeaconToken(beaconToken)

	const status = "SEV1 declared, cause under investigation"
	alice.SetBeacon(status, 3600)
	if res := waitMatch[client.EvBeaconResult](t, alice, func(e client.EvBeaconResult) bool { return e.Action == "set" }, 5*time.Second); !res.OK {
		t.Fatalf("set beacon failed: %s", res.Err)
	}

	// The relay holds only ciphertext: the plaintext status is NOT in the response.
	_, raw := httpGet(t, ts.URL+"/beacon/ops")
	if bytes.Contains(raw, []byte(status)) {
		t.Fatalf("the relay leaked the beacon plaintext:\n%s", raw)
	}

	// /beacon status decrypts locally.
	alice.FetchBeaconStatus()
	st := waitMatch[client.EvBeaconStatus](t, alice, nil, 5*time.Second)
	if !st.Set || st.Text != status {
		t.Fatalf("status = %+v, want %q", st, status)
	}

	// A reader holding ONLY the beacon key from the link decrypts the same status —
	// and that key cannot decrypt room messages (different key entirely).
	keyB64, ok := alice.BeaconKeyB64()
	if !ok {
		t.Fatal("no beacon key")
	}
	key, _ := base64.StdEncoding.DecodeString(keyB64)
	var bk [32]byte
	copy(bk[:], key)
	_, raw = httpGet(t, ts.URL+"/beacon/ops")
	var body struct {
		Ciphertext string `json:"ciphertext"`
	}
	_ = json.Unmarshal(raw, &body)
	blob, _ := base64.StdEncoding.DecodeString(body.Ciphertext)
	if got, err := crypto.OpenBeacon(bk, blob); err != nil || got != status {
		t.Fatalf("URL-key decrypt = %q err %v, want %q", got, err, status)
	}

	// /beacon clear removes it.
	alice.ClearBeacon()
	if res := waitMatch[client.EvBeaconResult](t, alice, func(e client.EvBeaconResult) bool { return e.Action == "clear" }, 5*time.Second); !res.OK {
		t.Fatalf("clear failed: %s", res.Err)
	}
	if resp, _ := httpGet(t, ts.URL+"/beacon/ops"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET after clear = %d, want 404", resp.StatusCode)
	}
}

// TestBeaconScuttlePurge proves a room's beacon is purged when the room scuttles.
func TestBeaconScuttlePurge(t *testing.T) {
	ts := httptest.NewServer(server.Handler(beaconConfig(), quietLogger()))
	defer ts.Close()

	alice := connect(t, ts.URL, "ops", "alice", "")
	waitMatch[client.EvKeyReady](t, alice, nil, 5*time.Second)
	alice.UseBeaconToken(beaconToken)
	alice.SetBeacon("Cause isolated, fix deploying", 3600)
	waitMatch[client.EvBeaconResult](t, alice, func(e client.EvBeaconResult) bool { return e.Action == "set" && e.OK }, 5*time.Second)
	if resp, _ := httpGet(t, ts.URL+"/beacon/ops"); resp.StatusCode != http.StatusOK {
		t.Fatal("beacon should be set before scuttle")
	}

	alice.ScuttleNow()
	// After the scuttle grace, ExpireRoom fires onClose → the beacon is purged.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if resp, _ := httpGet(t, ts.URL+"/beacon/ops"); resp.StatusCode == http.StatusNotFound {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("beacon was not purged when the room scuttled")
}

// TestBeaconTailEvents proves a `tail --json` observer records beacon_set and
// beacon_cleared (metadata only — never the status content).
func TestBeaconTailEvents(t *testing.T) {
	ts := httptest.NewServer(server.Handler(beaconConfig(), quietLogger()))
	defer ts.Close()

	observer := connect(t, ts.URL, "ops", "observer", "")
	waitMatch[client.EvKeyReady](t, observer, nil, 5*time.Second)
	alice := connect(t, ts.URL, "ops", "alice", "")
	waitMatch[client.EvKeyReady](t, alice, nil, 5*time.Second)
	alice.UseBeaconToken(beaconToken)

	mapper := eventlog.NewMapper("ops", false)

	alice.SetBeacon("SEV1 declared", 1800)
	waitMatch[client.EvBeaconResult](t, alice, func(e client.EvBeaconResult) bool { return e.Action == "set" && e.OK }, 5*time.Second)
	set := waitMappedEvent(t, observer, mapper, "beacon_set", 5*time.Second)
	if set.Actor != "alice" || set.TTLSeconds != 1800 {
		t.Fatalf("beacon_set event = %+v", set)
	}

	alice.ClearBeacon()
	waitMatch[client.EvBeaconResult](t, alice, func(e client.EvBeaconResult) bool { return e.Action == "clear" && e.OK }, 5*time.Second)
	cleared := waitMappedEvent(t, observer, mapper, "beacon_cleared", 5*time.Second)
	if cleared.Actor != "alice" {
		t.Fatalf("beacon_cleared event = %+v", cleared)
	}
}

// waitMappedEvent consumes a client's events through a mapper until one of type typ
// is produced (so intermediate join/key_ready events populate the directory).
func waitMappedEvent(t *testing.T, c *client.Client, m *eventlog.Mapper, typ string, timeout time.Duration) eventlog.Event {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case ev := <-c.Events():
			for _, e := range m.Map(ev) {
				if e.Type == typ {
					return e
				}
			}
		case <-c.Done():
			t.Fatalf("disconnected while waiting for a %s event", typ)
		case <-deadline:
			t.Fatalf("timed out waiting for a %s event", typ)
		}
	}
}
