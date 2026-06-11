package tfconfig

import (
	"strings"
	"testing"
)

// reparse renders the config and parses it back — exercising the full write→read
// round-trip the provider performs on every operation.
func reparse(t *testing.T, c *Config) *Config {
	t.Helper()
	b, err := c.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	got, err := Parse(b)
	if err != nil {
		t.Fatalf("re-Parse: %v\n%s", err, b)
	}
	return got
}

func TestRoomRoundTrip(t *testing.T) {
	c := Empty()
	c.SetRoom("ops", Room{InviteOnly: true, Webhook: true, WebhookToken: "tok", TTL: "24h"})
	got, ok := reparse(t, c).GetRoom("ops")
	if !ok {
		t.Fatal("room ops missing after round-trip")
	}
	if !got.InviteOnly || !got.Webhook || got.WebhookToken != "tok" || got.TTL != "24h" {
		t.Fatalf("room round-trip mismatch: %+v", got)
	}
}

// TestPreservesUnmanaged is the crux of B1: editing a managed section must not
// destroy sections the provider does not manage.
func TestPreservesUnmanaged(t *testing.T) {
	src := `
[server]
addr = ":8443"
tls_cert = "/etc/nc/cert.pem"

[limits]
messages_per_second = 5.0
burst = 10

[persistence]
enabled = true
path = "/var/lib/nc.db"

[[trust]]
handle = "alice"
fpr = "SHA256:abc"
`
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Manage a room and a trust entry; everything else must survive verbatim.
	c.SetRoom("ops", Room{Webhook: true})
	c.SetTrust(Trust{Handle: "bob", KeysURL: "https://github.com/bob.keys"})

	out, err := c.Bytes()
	if err != nil {
		t.Fatalf("bytes: %v", err)
	}
	s := string(out)
	for _, want := range []string{
		`addr = ':8443'`, `tls_cert`, `messages_per_second`, `burst`,
		`[persistence]`, `path = '/var/lib/nc.db'`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("unmanaged content %q was destroyed:\n%s", want, s)
		}
	}
	// Both trust entries survive; the room landed.
	rt := reparse(t, c)
	if _, ok := rt.GetTrust("alice"); !ok {
		t.Fatal("pre-existing trust entry alice was lost")
	}
	if _, ok := rt.GetTrust("bob"); !ok {
		t.Fatal("new trust entry bob missing")
	}
	if _, ok := rt.GetRoom("ops"); !ok {
		t.Fatal("new room ops missing")
	}
}

func TestTrustUpsertDelete(t *testing.T) {
	c := Empty()
	c.SetTrust(Trust{Handle: "alice", Fpr: "SHA256:one"})
	c.SetTrust(Trust{Handle: "alice", Fpr: "SHA256:two"}) // upsert, not duplicate
	got, ok := reparse(t, c).GetTrust("alice")
	if !ok || got.Fpr != "SHA256:two" {
		t.Fatalf("trust upsert = %+v, ok=%v", got, ok)
	}
	c.DeleteTrust("alice")
	if _, ok := reparse(t, c).GetTrust("alice"); ok {
		t.Fatal("trust alice should be gone after delete")
	}
}

func TestRouteUpsertDelete(t *testing.T) {
	c := Empty()
	c.SetRoute(Route{RoomPrefix: "inc", Action: "break-glass", Match: map[string]string{"severity": "high"}, Invite: []string{"@alice", "@bob"}, TTL: "24h"})
	got, ok := reparse(t, c).GetRoute("inc")
	if !ok {
		t.Fatal("route inc missing")
	}
	if got.Action != "break-glass" || got.Match["severity"] != "high" || len(got.Invite) != 2 || got.TTL != "24h" {
		t.Fatalf("route round-trip mismatch: %+v", got)
	}
	c.SetRoute(Route{RoomPrefix: "inc", Action: "break-glass", TTL: "1h"}) // upsert
	if got, _ := reparse(t, c).GetRoute("inc"); got.TTL != "1h" {
		t.Fatalf("route upsert TTL = %q, want 1h", got.TTL)
	}
	c.DeleteRoute("inc")
	if _, ok := reparse(t, c).GetRoute("inc"); ok {
		t.Fatal("route inc should be gone")
	}
}

func TestActionQuorum(t *testing.T) {
	c := Empty()
	c.SetActionQuorum("scuttle", 2)
	q, ok := reparse(t, c).GetActionQuorum("scuttle")
	if !ok || q != 2 {
		t.Fatalf("action quorum = %d, ok=%v, want 2", q, ok)
	}
	c.DeleteAction("scuttle")
	if _, ok := reparse(t, c).GetActionQuorum("scuttle"); ok {
		t.Fatal("action scuttle should be gone")
	}
}

func TestDeleteRoomPrunesTable(t *testing.T) {
	c := Empty()
	c.SetRoom("ops", Room{Webhook: true})
	c.DeleteRoom("ops")
	b, _ := c.Bytes()
	if strings.Contains(string(b), "rooms") {
		t.Fatalf("empty rooms table should be pruned:\n%s", b)
	}
}
