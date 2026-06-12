package e2e

import (
	"context"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/connector"
	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/record"
)

// nc2Config registers one token-authenticated source and a catch-all-on-severity
// route that invites two responders — the minimal relay setup an NC-2 adapter
// targets.
func nc2Config() config.Config {
	c := config.Default()
	c.Sources = []config.SourceConfig{{Name: "scanner", Token: "tok"}}
	c.Routes = []config.RouteConfig{{
		Action:     "break-glass",
		Match:      map[string]string{"severity": "high"},
		Invite:     []string{"alice", "bob"},
		RoomPrefix: "inc",
	}}
	return c
}

func tokenFromLink(t *testing.T, link string) string {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatalf("parse link %q: %v", link, err)
	}
	tok := u.Query().Get("token")
	if tok == "" {
		t.Fatalf("no token in link %q", link)
	}
	return tok
}

// TestNC2DetectRespondAttest proves the full NC-2 loop end to end: an authenticated
// metadata alert (exactly what the findings adapter emits) spawns a war room via
// routing; two responders join through the one-time links; they record a decision
// and an action; the record is sealed by both; and it verifies offline. This is the
// automated counterpart to scripts/demo-nc2.sh — the parts a shell script cannot
// drive (the in-room, human two-person attest) are exercised here in Go.
func TestNC2DetectRespondAttest(t *testing.T) {
	ts := httptest.NewServer(server.Handler(nc2Config(), quietLogger()))
	defer ts.Close()

	// 1. Detection: an authenticated, metadata-only alert (findings-adapter shape).
	cl := &connector.Client{Server: ts.URL, Token: "tok"}
	res, err := cl.Send(context.Background(), connector.Alert{
		Source:   "scanner",
		Severity: "high",
		Kind:     "security-finding",
		Summary:  "CIS-1.20: S3 bucket allows public read (arn:aws:s3:::bucket)",
		Ref:      "f-001",
		TS:       time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("alert: %v", err)
	}
	if !res.Spawned || res.Room == "" {
		t.Fatalf("alert did not spawn a war room: %+v", res)
	}
	if res.Links["alice"] == "" || res.Links["bob"] == "" {
		t.Fatalf("missing invite links: %+v", res.Links)
	}

	// 2. Respond: both responders join the spawned room via their one-time links.
	room := res.Room
	alice := connect(t, ts.URL, room, "alice", tokenFromLink(t, res.Links["alice"]))
	waitMatch[client.EvKeyReady](t, alice, nil, 5*time.Second)
	bob := connect(t, ts.URL, room, "bob", tokenFromLink(t, res.Links["bob"]))
	waitMatch[client.EvKeyReady](t, bob, nil, 5*time.Second)
	waitMatch[client.EvMemberJoined](t, alice, func(e client.EvMemberJoined) bool { return e.Name == "bob" }, 5*time.Second)

	// 3. Attest: record a decision + an action, building the same chain on both.
	if err := alice.Decide("contained: bucket set private, keys rotated"); err != nil {
		t.Fatalf("decide: %v", err)
	}
	waitMatch[client.EvRecordEntry](t, bob, func(e client.EvRecordEntry) bool {
		return !e.Self && e.Kind == record.KindDecision
	}, 5*time.Second)
	if err := alice.Action("bob", "file the incident report"); err != nil {
		t.Fatalf("action: %v", err)
	}
	waitMatch[client.EvRecordEntry](t, bob, func(e client.EvRecordEntry) bool {
		return !e.Self && e.Kind == record.KindAction
	}, 5*time.Second)

	// 4. Seal (two-party) and verify the record offline.
	if err := alice.Seal(); err != nil {
		t.Fatalf("alice seal: %v", err)
	}
	waitMatch[client.EvSealRequest](t, bob, func(e client.EvSealRequest) bool { return !e.Self && e.Matches }, 5*time.Second)
	if err := bob.Seal(); err != nil {
		t.Fatalf("bob seal: %v", err)
	}
	done := waitMatch[client.EvSealComplete](t, alice, nil, 10*time.Second)

	rec := done.Record
	if rec == nil {
		t.Fatal("seal complete carried no record")
	}
	v, err := record.Verify(rec)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !v.Valid {
		t.Fatalf("sealed record did not verify: %s", v.Reason)
	}
	if len(v.Signers) != 2 {
		t.Errorf("verified %d signers, want 2 (alice + bob)", len(v.Signers))
	}
}
