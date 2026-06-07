package e2e

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cretz/bine/tor"
	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// TestTorOnionRoundTrip publishes the relay as a v3 onion service and exchanges an
// end-to-end-encrypted message between two clients that dial it over Tor (§1.5):
// no public IP, no DNS, no TLS — the .onion address IS the relay's key.
//
// It SKIPS when tor is not installed so CI never fails for tor's absence
// (FEATURE_ROADMAP_FREE.md §6: the Tor integration is the highest-variance
// dependency and must not block the core). When tor IS present it is a real
// round trip: tor bootstraps, the descriptor publishes, and the clients rendezvous.
func TestTorOnionRoundTrip(t *testing.T) {
	if !server.TorInstalled() {
		t.Skip("tor not in PATH; skipping onion-service integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tr, err := tor.Start(ctx, &tor.StartConf{DataDir: t.TempDir()})
	if err != nil {
		t.Fatalf("start tor: %v", err)
	}
	defer tr.Close()

	onion, err := tr.Listen(ctx, &tor.ListenConf{Version3: true, RemotePorts: []int{80}})
	if err != nil {
		t.Fatalf("publish onion service: %v", err)
	}
	defer onion.Close()

	// Serve the real relay handler over the onion listener.
	srv := &http.Server{Handler: server.Handler(config.Default(), quietLogger())}
	go func() { _ = srv.Serve(onion) }()
	defer srv.Close()

	// Dial through this tor instance's own SOCKS proxy.
	info, err := tr.Control.GetInfo("net/listeners/socks")
	if err != nil || len(info) == 0 {
		t.Fatalf("discover tor SOCKS address: %v", err)
	}
	socks := strings.Trim(info[0].Val, "\"")
	url := "ws://" + onion.ID + ".onion:80"

	dialOverTor := func(name string) *client.Client {
		t.Helper()
		id, err := crypto.GenerateIdentity()
		if err != nil {
			t.Fatalf("identity: %v", err)
		}
		c, err := client.NewWithIdentity(url, "ops", name, id)
		if err != nil {
			t.Fatalf("new client: %v", err)
		}
		if err := c.UseTorProxy(socks); err != nil {
			t.Fatalf("configure tor proxy: %v", err)
		}
		cctx, ccancel := context.WithTimeout(ctx, 90*time.Second)
		defer ccancel()
		if err := c.Connect(cctx); err != nil {
			t.Fatalf("connect %s over tor: %v", name, err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}

	alice := dialOverTor("alice")
	waitMatch[client.EvKeyReady](t, alice, nil, 30*time.Second)
	bob := dialOverTor("bob")
	waitMatch[client.EvKeyReady](t, bob, nil, 30*time.Second)

	if err := alice.Send("hello over tor"); err != nil {
		t.Fatalf("send: %v", err)
	}
	got := waitMatch[client.EvMessage](t, bob, func(e client.EvMessage) bool {
		return !e.Self && e.Text == "hello over tor"
	}, 30*time.Second)
	if !got.Signed {
		t.Error("E2E message over tor should still be Ed25519-signed")
	}
}
