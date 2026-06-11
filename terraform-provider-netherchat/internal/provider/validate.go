package provider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/salehkreiner/terraform-provider-netherchat/internal/tfconfig"
)

// validateTimeout bounds the optional server-side config check.
const validateTimeout = 10 * time.Second

// validate optionally checks a rendered config against a running relay's
// POST /api/v1/config/validate endpoint before it is written to disk (B1). When no
// validate_url is configured this is a no-op: the provider edits netherchat.toml
// purely offline, which is the common config-as-code case. When set, an invalid
// topology fails `terraform apply` here — at the source of truth — rather than
// later, at a server restart.
//
// It sends ONLY the rendered netherchat.toml (config-as-code; never message
// content) and reads back {"valid":bool,"error":string}. A transport failure is a
// real error, because the operator opted in by setting validate_url.
func validate(meta any, cfg *tfconfig.Config) error {
	url := validateURLOf(meta)
	if url == "" {
		return nil
	}
	body, err := cfg.Bytes()
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: validateTimeout}
	resp, err := client.Post(url, "application/toml", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("validate config against %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("validate config against %s: relay returned %s", url, resp.Status)
	}
	var out struct {
		Valid bool   `json:"valid"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("validate config: decode relay response: %w", err)
	}
	if !out.Valid {
		return fmt.Errorf("relay rejected the proposed netherchat.toml: %s", out.Error)
	}
	return nil
}
