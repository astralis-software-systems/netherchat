package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/salehkreiner/netherchat/server/config"
)

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// postValidate POSTs a candidate TOML to the config-validate endpoint and returns
// the decoded {valid,error} response.
func postValidate(t *testing.T, base, toml string) (bool, string) {
	t.Helper()
	resp, err := http.Post(base+"/api/v1/config/validate", "application/toml", strings.NewReader(toml))
	if err != nil {
		t.Fatalf("POST validate: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("validate status = %d, want 200", resp.StatusCode)
	}
	var out struct {
		Valid bool   `json:"valid"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out.Valid, out.Error
}

// TestConfigValidateEndpoint covers B1's server-side check: a well-formed proposed
// config validates, a malformed one is reported invalid with an error — and neither
// is applied to the running server.
func TestConfigValidateEndpoint(t *testing.T) {
	ts := httptest.NewServer(Handler(config.Default(), discardLog()))
	defer ts.Close()

	good := `
[rooms.ops]
invite_only = true
webhook = true

[[trust]]
handle = "alice"

[action.scuttle]
quorum = 2
`
	if valid, errMsg := postValidate(t, ts.URL, good); !valid {
		t.Fatalf("valid config rejected: %s", errMsg)
	}

	bad := "[rooms.ops\nwebhook = true" // unterminated table header
	valid, errMsg := postValidate(t, ts.URL, bad)
	if valid {
		t.Fatal("malformed config reported as valid")
	}
	if errMsg == "" {
		t.Fatal("invalid config should carry an error message")
	}
}

// TestConfigValidateRejectsTLSKeys: the fail-closed tls_cert/tls_key check surfaces
// through POST /api/v1/config/validate as valid:false, so a `terraform plan` that
// would have deployed a relay serving plaintext ws:// under a TLS-shaped config
// fails at plan time rather than at a restart nobody watches.
func TestConfigValidateRejectsTLSKeys(t *testing.T) {
	ts := httptest.NewServer(Handler(config.Default(), discardLog()))
	defer ts.Close()

	for _, toml := range []string{
		"[server]\ntls_cert = \"/etc/nc/cert.pem\"\ntls_key = \"/etc/nc/key.pem\"\n",
		"[server]\ntls_cert = \"/etc/nc/cert.pem\"\n",
		"[server]\ntls_key = \"/etc/nc/key.pem\"\n",
	} {
		valid, errMsg := postValidate(t, ts.URL, toml)
		if valid {
			t.Fatalf("TLS-configured relay should validate as false:\n%s", toml)
		}
		if !strings.Contains(errMsg, "does not terminate TLS") {
			t.Errorf("error should explain the relay terminates no TLS, got: %q", errMsg)
		}
	}

	// The documented deployment — TLS upstream, relay on plain HTTP — stays valid.
	if valid, errMsg := postValidate(t, ts.URL, "[server]\naddr = \":3000\"\n"); !valid {
		t.Fatalf("a config without TLS keys must validate: %s", errMsg)
	}
}
