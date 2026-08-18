package app

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/tui/client"
)

// Every link this client prints — /beacon link, /invite, /break-glass — is built
// on webBase(), and with --web-url unset that is derived from the relay URL this
// client dialed. In the supported single-origin deployment that is right. Point a
// client straight at the relay's listen address while the pages are served
// somewhere else and it is wrong, and it is wrong SILENTLY in all three
// directions: the sender sees a plausible link, the recipient sees a bare 404, and
// the beacon key is in the fragment so it never reaches a server that could log
// the miss. Nothing on the wire carries the relay's own -web-url to a client, so
// no client can detect the split by itself.
//
// So the only available signal is at mint time, and these tests pin that it exists
// on every one of the three paths and is absent once --web-url is set.

// lastLines returns the active room's transcript text, joined.
func lastLines(m *Model) string {
	var b strings.Builder
	for _, l := range m.activeRoom().lines {
		b.WriteString(l.text)
		b.WriteString("\n")
	}
	return b.String()
}

// derivedBaseMarker is the phrase the notice must contain. It is asserted as a
// substring rather than the whole sentence so the wording can be improved without
// four test edits, but it names the flag, because the flag is the remedy and a
// warning that does not name its remedy is noise.
const derivedBaseMarker = "--web-url"

func TestBeaconLinkWarnsWhenWebURLUnset(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), discardLogger()))
	defer ts.Close()

	core := connectCore(t, ts.URL, "ops", "alice")
	waitKeyReady(t, core)

	m := newModel(ts.URL, "alice", "", "ops", "")
	r := m.activeRoom()
	r.client = core
	r.connected = true

	m.runBeaconLink(r, "")
	out := lastLines(m)
	if !strings.Contains(out, "/beacon?room=ops") {
		t.Fatalf("no beacon link in the transcript:\n%s", out)
	}
	if !strings.Contains(out, derivedBaseMarker) {
		t.Fatalf("/beacon link minted a derived-base link with no notice naming %s:\n%s", derivedBaseMarker, out)
	}
}

func TestBeaconLinkQuietWhenWebURLSet(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), discardLogger()))
	defer ts.Close()

	core := connectCore(t, ts.URL, "ops", "alice")
	waitKeyReady(t, core)

	m := newModel(ts.URL, "alice", "", "ops", "")
	m.webURL = "https://pages.example.com"
	r := m.activeRoom()
	r.client = core
	r.connected = true

	m.runBeaconLink(r, "")
	out := lastLines(m)
	if !strings.Contains(out, "https://pages.example.com/beacon?room=ops") {
		t.Fatalf("--web-url was not used for the link base:\n%s", out)
	}
	if strings.Contains(out, derivedBaseMarker) {
		t.Fatalf("the operator set --web-url and was warned about it anyway:\n%s", out)
	}
}

func TestInviteWarnsWhenWebURLUnset(t *testing.T) {
	m := newModel("ws://localhost:3000", "alice", "", "ops", "")
	out := m.renderInvite("ops", client.EvInvite{Room: "ops", Token: "tok-123"})
	if !strings.Contains(out, "http://localhost:3000/join?") {
		t.Fatalf("no derived join link in the invite block:\n%s", out)
	}
	if !strings.Contains(out, derivedBaseMarker) {
		t.Fatalf("/invite minted a derived-base link with no notice naming %s:\n%s", derivedBaseMarker, out)
	}
}

func TestInviteQuietWhenWebURLSet(t *testing.T) {
	m := newModel("ws://localhost:3000", "alice", "", "ops", "")
	m.webURL = "https://pages.example.com"
	out := m.renderInvite("ops", client.EvInvite{Room: "ops", Token: "tok-123"})
	if !strings.Contains(out, "https://pages.example.com/join?") {
		t.Fatalf("--web-url was not used for the invite link:\n%s", out)
	}
	if strings.Contains(out, derivedBaseMarker) {
		t.Fatalf("the operator set --web-url and was warned about it anyway:\n%s", out)
	}
}

// /break-glass is the third consumer of webBase() and the one that matters most in
// the demo, because its whole output is a list of links to paste to other people.
func TestBreakGlassWarnsWhenWebURLUnset(t *testing.T) {
	m := newModel("ws://localhost:3000", "alice", "", "ops", "")
	out := m.renderBreakGlass(client.EvBreakGlass{
		Room:    "sev1",
		Expires: time.Now().Add(time.Hour),
		Invites: []client.BreakGlassInvite{{Name: "bob", Token: "tok-abc"}},
	})
	if !strings.Contains(out, "http://localhost:3000/join?") {
		t.Fatalf("no derived join link in the break-glass banner:\n%s", out)
	}
	if !strings.Contains(out, derivedBaseMarker) {
		t.Fatalf("/break-glass minted derived-base links with no notice naming %s:\n%s", derivedBaseMarker, out)
	}
}

func TestBreakGlassQuietWhenWebURLSet(t *testing.T) {
	m := newModel("ws://localhost:3000", "alice", "", "ops", "")
	m.webURL = "https://pages.example.com"
	out := m.renderBreakGlass(client.EvBreakGlass{
		Room:    "sev1",
		Expires: time.Now().Add(time.Hour),
		Invites: []client.BreakGlassInvite{{Name: "bob", Token: "tok-abc"}},
	})
	if !strings.Contains(out, "https://pages.example.com/join?") {
		t.Fatalf("--web-url was not used for the break-glass links:\n%s", out)
	}
	if strings.Contains(out, derivedBaseMarker) {
		t.Fatalf("the operator set --web-url and was warned about it anyway:\n%s", out)
	}
}
