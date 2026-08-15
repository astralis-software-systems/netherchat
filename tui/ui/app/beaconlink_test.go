package app

import (
	"net/url"
	"strings"
	"testing"
)

// The TUI's /beacon link builder is a second, independent copy of the CLI's
// beaconLinkURL. It must emit the SAME shape — key in the fragment, never in the
// query — because one web reader parses both. The vector below is asserted
// byte-for-byte in cmd/netherchat/beaconcmd_test.go and in the web tests too.

func TestBeaconLinkPutsKeyInFragmentNotQuery(t *testing.T) {
	m := newModel("wss://chat.example.com/ws", "alice", "", "ops", "")

	// A key whose base64 has the characters that must survive escaping.
	const key = "+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/s="
	link := m.beaconLink("ops", key, 7200)

	rawQuery, rawFragment, found := strings.Cut(link, "#")
	if !found {
		t.Fatalf("link has no fragment: %s", link)
	}
	if strings.Contains(rawQuery, "key") {
		t.Fatalf("the query mentions a key — it must not: %s", rawQuery)
	}

	u, err := url.Parse(link)
	if err != nil {
		t.Fatalf("link does not parse: %v", err)
	}
	if u.Query().Get("room") != "ops" || u.Query().Get("ttl") != "7200" {
		t.Errorf("query = %q, want room=ops and ttl=7200", u.RawQuery)
	}

	f, err := url.ParseQuery(rawFragment)
	if err != nil {
		t.Fatalf("fragment does not parse: %v", err)
	}
	if got := f.Get("key"); got != key {
		t.Fatalf("key from fragment = %q, want %q", got, key)
	}
}

// TestBeaconLinkMatchesCLIShape holds the TUI builder to the same string the CLI
// emits, so the two cannot drift apart under one web reader.
func TestBeaconLinkMatchesCLIShape(t *testing.T) {
	m := newModel("wss://chat.example.com/ws", "alice", "", "ops", "")
	const (
		key  = "o4qq5R8jF5zoXjiPj3reJsRFk/3Iok9ZFyJR0PJSAQQ="
		want = "https://chat.example.com/beacon?room=ops&ttl=7200#key=o4qq5R8jF5zoXjiPj3reJsRFk%2F3Iok9ZFyJR0PJSAQQ%3D"
	)
	if got := m.beaconLink("ops", key, 7200); got != want {
		t.Errorf("beacon link\n got: %s\nwant: %s", got, want)
	}

	// --web-url overrides the derived origin but not the shape.
	m.webURL = "https://status.example.com/"
	if got := m.beaconLink("ops", key, 7200); !strings.HasPrefix(got, "https://status.example.com/beacon?") || !strings.Contains(got, "#key=") {
		t.Errorf("with --web-url: %s", got)
	}
}
