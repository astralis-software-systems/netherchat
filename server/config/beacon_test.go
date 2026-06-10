package config

import (
	"testing"
	"time"
)

// TestBeaconAuth proves beacon write auth: a dedicated beacon_token wins, the
// room's webhook_token is the fallback, and a room with neither is disabled.
func TestBeaconAuth(t *testing.T) {
	if tok, ok := (RoomConfig{BeaconToken: "b", WebhookToken: "w"}).BeaconAuth(); !ok || tok != "b" {
		t.Fatalf("dedicated beacon_token: got %q %v, want b true", tok, ok)
	}
	if tok, ok := (RoomConfig{WebhookToken: "w"}).BeaconAuth(); !ok || tok != "w" {
		t.Fatalf("webhook fallback: got %q %v, want w true", tok, ok)
	}
	if _, ok := (RoomConfig{}).BeaconAuth(); ok {
		t.Fatal("a room with no token must have beacons disabled (opt-in only)")
	}
}

// TestBeaconLifetime proves the TTL clamp: a 1h default, a 1m floor, the 24h hard
// ceiling, and the per-room beacon_ttl cap.
func TestBeaconLifetime(t *testing.T) {
	def := RoomConfig{}
	if d := def.BeaconLifetime(0); d != time.Hour {
		t.Errorf("non-positive request = %s, want 1h default", d)
	}
	if d := def.BeaconLifetime(100000); d != BeaconMaxTTL {
		t.Errorf("oversized request = %s, want the 24h ceiling", d)
	}
	if d := def.BeaconLifetime(30); d != time.Minute {
		t.Errorf("tiny request = %s, want the 1m floor", d)
	}
	capped := RoomConfig{BeaconTTL: Duration(30 * time.Minute)}
	if d := capped.BeaconLifetime(3600); d != 30*time.Minute {
		t.Errorf("request above beacon_ttl = %s, want it capped to 30m", d)
	}
}
