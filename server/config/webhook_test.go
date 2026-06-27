package config

import "testing"

// TestWebhookDefaults: an unset [ingest.webhook] is filled with the built-in caps.
func TestWebhookDefaults(t *testing.T) {
	cfg, err := Parse([]byte(""))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Ingest.Webhook.RatePerMinute != DefaultWebhookRatePerMinute {
		t.Errorf("rate default = %d, want %d", cfg.Ingest.Webhook.RatePerMinute, DefaultWebhookRatePerMinute)
	}
	if cfg.Ingest.Webhook.SpawnPerHour != DefaultWebhookSpawnPerHour {
		t.Errorf("spawn default = %d, want %d", cfg.Ingest.Webhook.SpawnPerHour, DefaultWebhookSpawnPerHour)
	}
	if cfg.Ingest.Webhook.UnauthRatePerMinute != DefaultWebhookUnauthRatePerMinute {
		t.Errorf("unauth default = %d, want %d", cfg.Ingest.Webhook.UnauthRatePerMinute, DefaultWebhookUnauthRatePerMinute)
	}
}

// TestWebhookNonPositiveRepaired: nonsensical (zero/negative) globals revert to the
// built-in defaults, mirroring the limits/freshness repair precedent.
func TestWebhookNonPositiveRepaired(t *testing.T) {
	cfg, err := Parse([]byte("[ingest.webhook]\nrate_per_minute = 0\nspawn_per_hour = -1\nunauth_rate_per_minute = 0\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Ingest.Webhook.RatePerMinute != DefaultWebhookRatePerMinute {
		t.Errorf("zero rate should be repaired to %d", DefaultWebhookRatePerMinute)
	}
	if cfg.Ingest.Webhook.SpawnPerHour != DefaultWebhookSpawnPerHour {
		t.Errorf("negative spawn should be repaired to %d", DefaultWebhookSpawnPerHour)
	}
	if cfg.Ingest.Webhook.UnauthRatePerMinute != DefaultWebhookUnauthRatePerMinute {
		t.Errorf("zero unauth should be repaired to %d", DefaultWebhookUnauthRatePerMinute)
	}
}

// TestWebhookOverridesParse: the global table and per-room overrides parse and survive.
func TestWebhookOverridesParse(t *testing.T) {
	toml := `
[ingest.webhook]
rate_per_minute = 240
spawn_per_hour = 120
unauth_rate_per_minute = 1000

[rooms.alerts]
webhook = true
webhook_token = "x"
webhook_rate_per_minute = 30
webhook_spawn_per_hour = 15
`
	cfg, err := Parse([]byte(toml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Ingest.Webhook.RatePerMinute != 240 || cfg.Ingest.Webhook.UnauthRatePerMinute != 1000 {
		t.Errorf("global webhook caps not parsed: %+v", cfg.Ingest.Webhook)
	}
	r := cfg.Room("alerts")
	if r.WebhookRatePerMinute != 30 || r.WebhookSpawnPerHour != 15 {
		t.Errorf("per-room override not parsed: rate=%d spawn=%d", r.WebhookRatePerMinute, r.WebhookSpawnPerHour)
	}
}

// TestWebhookResolution: override > global > built-in for per-token caps; the
// pre-auth ceiling resolves global-else-built-in.
func TestWebhookResolution(t *testing.T) {
	cfg := Default()
	cfg.Ingest.Webhook = WebhookConfig{RatePerMinute: 100, SpawnPerHour: 50, UnauthRatePerMinute: 500}

	// Per-room override wins.
	over := RoomConfig{WebhookRatePerMinute: 7, WebhookSpawnPerHour: 9}
	if cfg.WebhookRate(over) != 7 {
		t.Errorf("rate override = %d, want 7", cfg.WebhookRate(over))
	}
	if cfg.WebhookSpawn(over) != 9 {
		t.Errorf("spawn override = %d, want 9", cfg.WebhookSpawn(over))
	}

	// Unset (0) → global default.
	none := RoomConfig{}
	if cfg.WebhookRate(none) != 100 {
		t.Errorf("rate global = %d, want 100", cfg.WebhookRate(none))
	}
	if cfg.WebhookSpawn(none) != 50 {
		t.Errorf("spawn global = %d, want 50", cfg.WebhookSpawn(none))
	}
	if cfg.WebhookUnauthRate() != 500 {
		t.Errorf("unauth global = %d, want 500", cfg.WebhookUnauthRate())
	}

	// Both unset (a zero Config) → built-in fallback (gate never silently disabled).
	var zero Config
	if zero.WebhookRate(RoomConfig{}) != DefaultWebhookRatePerMinute {
		t.Errorf("rate builtin = %d, want %d", zero.WebhookRate(RoomConfig{}), DefaultWebhookRatePerMinute)
	}
	if zero.WebhookUnauthRate() != DefaultWebhookUnauthRatePerMinute {
		t.Errorf("unauth builtin = %d, want %d", zero.WebhookUnauthRate(), DefaultWebhookUnauthRatePerMinute)
	}
}
