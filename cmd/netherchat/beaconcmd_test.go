package main

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

// The beacon key must never travel in a place a browser sends to a server. These
// tests pin the link SHAPE that makes docs/encryption.md's "the beacon key is never
// sent to the server" true: room and ttl in the query, key in the fragment only.

// beaconKeyB64 is a 32-byte key whose standard base64 contains "+", "/" and "=" —
// the three characters that must survive fragment escaping intact.
func beaconKeyB64() string {
	k := make([]byte, 32)
	for i := range k {
		k[i] = 0xfb
	}
	return base64.StdEncoding.EncodeToString(k)
}

func TestBeaconLinkURLPutsKeyInFragmentNotQuery(t *testing.T) {
	key := beaconKeyB64()
	for _, c := range []string{"+", "/", "="} {
		if !strings.Contains(key, c) {
			t.Fatalf("test key %q should contain %q to exercise escaping", key, c)
		}
	}

	link := beaconLinkURL("https://chat.example.com", "ops", key, 7200)

	rawQuery, rawFragment, found := strings.Cut(strings.TrimPrefix(link, "https://chat.example.com/beacon?"), "#")
	if !found {
		t.Fatalf("link has no fragment: %s", link)
	}

	// The query carries the non-secrets and nothing else. Substring, not parse:
	// the key must not appear anywhere before the "#", however it is spelled.
	if strings.Contains(rawQuery, "key") {
		t.Fatalf("query mentions a key — it must not: %s", rawQuery)
	}
	if strings.Contains(rawQuery, url.QueryEscape(key)) || strings.Contains(rawQuery, key) {
		t.Fatalf("the beacon key is in the query string: %s", rawQuery)
	}
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		t.Fatalf("query does not parse: %v", err)
	}
	if got := q.Get("room"); got != "ops" {
		t.Errorf("room = %q, want %q", got, "ops")
	}
	if got := q.Get("ttl"); got != "7200" {
		t.Errorf("ttl = %q, want %q", got, "7200")
	}

	// The fragment carries the key, and it round-trips byte-for-byte.
	f, err := url.ParseQuery(rawFragment)
	if err != nil {
		t.Fatalf("fragment does not parse: %v", err)
	}
	if got := f.Get("key"); got != key {
		t.Fatalf("key from fragment = %q, want %q", got, key)
	}
	if strings.ContainsAny(rawFragment, "+/") {
		t.Errorf("fragment holds unescaped +/ — a browser's form decoding would corrupt it: %s", rawFragment)
	}
}

// TestBeaconLinkURLMatchesWebVector is the cross-language contract: this exact
// string is parsed by the web reader in web/src/beacon/link.test.ts and by
// web/scripts/interop-check.ts. If either side changes shape, one of the three
// fails. The key is the beacon interop vector (room key 0x00..0x1f).
func TestBeaconLinkURLMatchesWebVector(t *testing.T) {
	const (
		key  = "o4qq5R8jF5zoXjiPj3reJsRFk/3Iok9ZFyJR0PJSAQQ="
		want = "https://chat.example.com/beacon?room=ops&ttl=7200#key=o4qq5R8jF5zoXjiPj3reJsRFk%2F3Iok9ZFyJR0PJSAQQ%3D"
	)
	if got := beaconLinkURL("https://chat.example.com/", "ops", key, 7200); got != want {
		t.Errorf("beacon link\n got: %s\nwant: %s", got, want)
	}
}

// TestWebBaseFor pins where a beacon link points by default: the origin THIS
// CLIENT DIALED, with ws(s) mapped to http(s) and the path dropped.
//
// That is not the same claim as "the relay's own origin", and the difference is
// worth stating because the shorter phrasing reads as a defect. The relay process
// serves no HTML (docs/self-hosting.md, "Serving the web client") — but the supported deployment
// requires the pages and `/ws` to be on ONE origin (same section, and `HandleWS`
// enforces same-origin on the handshake), so the origin a client dialed IS the
// origin that serves the pages. `wss://chat.example.com/ws` → the proxy at
// `https://chat.example.com`, which serves join.html and beacon.html. The
// derivation is correct there, which is the case it is a default for.
//
// It is wrong in exactly one situation: the client was pointed straight at the
// relay's listen address while the pages are served somewhere else — `ws://
// localhost:3000` with a separate `vite preview` on `:5173`. `--web-url` is the
// remedy and the "explicit web url wins" row below is what pins it; it must be
// passed to EVERY CLIENT that mints a link, because the relay's own `-web-url`
// reaches no client (see docs/self-hosting.md, flags).
func TestWebBaseFor(t *testing.T) {
	for _, tc := range []struct {
		name, server, webURL, want string
	}{
		{"ws becomes http", "ws://localhost:3000", "", "http://localhost:3000"},
		{"wss becomes https", "wss://chat.example.com", "", "https://chat.example.com"},
		{"path is dropped", "wss://chat.example.com/ws", "", "https://chat.example.com"},
		{"explicit web url wins", "wss://chat.example.com", "https://status.example.com", "https://status.example.com"},
		{"unparseable server passes through", "not a url", "", "not a url"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := webBaseFor(tc.server, tc.webURL); got != tc.want {
				t.Errorf("webBaseFor(%q, %q) = %q, want %q", tc.server, tc.webURL, got, tc.want)
			}
		})
	}
}
