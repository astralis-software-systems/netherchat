package client

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// This white-box test drives the action-request expiry timer, which is otherwise
// the spec's 60s — too long for a test. It shortens the unexported actionRequestTTL
// (only the client package can), so it lives here rather than in tui/e2e.

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func dialClient(t *testing.T, url, room, name string) *Client {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	c, err := NewWithIdentity(url, room, name, id)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("connect %s: %v", name, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func waitFor[T Event](t *testing.T, c *Client, timeout time.Duration) T {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case ev := <-c.Events():
			if v, ok := ev.(T); ok {
				return v
			}
		case <-c.Done():
			t.Fatalf("connection closed while waiting for %T", *new(T))
		case <-deadline:
			t.Fatalf("timed out waiting for %T", *new(T))
		}
	}
}

// TestActionRequestExpires proves a request that never reaches quorum is discarded
// after its window with an EvActionExpired carrying the requester-only endorsement
// count (1) — and the action does not fire.
func TestActionRequestExpires(t *testing.T) {
	old := actionRequestTTL
	actionRequestTTL = 200 * time.Millisecond
	defer func() { actionRequestTTL = old }()

	ts := httptest.NewServer(server.Handler(config.Default(), quietLog()))
	defer ts.Close()

	alice := dialClient(t, ts.URL, "ops", "alice")
	waitFor[EvKeyReady](t, alice, 5*time.Second)

	executed := false
	if _, err := alice.RequestAction("scuttle", "room=ops, reason=manual", 2, func() { executed = true }); err != nil {
		t.Fatalf("request action: %v", err)
	}
	exp := waitFor[EvActionExpired](t, alice, 2*time.Second)
	if exp.ApprovalsReceived != 1 || exp.QuorumNeeded != 2 {
		t.Fatalf("expired event = %+v, want approvals_received=1 quorum_needed=2", exp)
	}
	if executed {
		t.Fatal("an expired request must not execute")
	}
	if len(alice.PendingActions()) != 0 {
		t.Fatal("an expired request must be dropped from the pending list")
	}
}
