package app

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/tui/client"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func connectCore(t *testing.T, url, room, name string) *client.Client {
	t.Helper()
	c, err := client.NewEphemeral(url, room, name)
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

func waitKeyReady(t *testing.T, c *client.Client) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case ev := <-c.Events():
			if _, ok := ev.(client.EvKeyReady); ok {
				return
			}
		case <-deadline:
			t.Fatal("timed out waiting for key")
		}
	}
}

func waitPending(t *testing.T, c *client.Client) client.PendingAction {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if p := c.PendingActions(); len(p) > 0 {
			return p[0]
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timed out waiting for a pending request")
	return client.PendingAction{}
}

// TestApproveDoubleConfirm proves /approve <id> only previews (no approval is sent),
// while /approve <id> confirm actually signs — the double-confirm that prevents an
// accidental approval (§1.3). The approver is driven through the real Model command.
func TestApproveDoubleConfirm(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), discardLogger()))
	defer ts.Close()

	// The requester opens a quorum-gated request; its onApprove signals execution.
	requester := connectCore(t, ts.URL, "ops", "requester")
	waitKeyReady(t, requester)
	approver := connectCore(t, ts.URL, "ops", "approver")
	waitKeyReady(t, approver)

	executed := make(chan struct{}, 1)
	id, err := requester.RequestAction("scuttle", "room=ops, reason=manual", 2, func() { executed <- struct{}{} })
	if err != nil {
		t.Fatalf("request action: %v", err)
	}

	// Drive the approver through a Model, as the TUI does.
	m := newModel(ts.URL, "approver", "", "ops", "")
	r := m.activeRoom()
	r.client = approver
	r.connected = true

	p := waitPending(t, approver)
	if p.RequestID != id || p.Initiator {
		t.Fatalf("approver pending = %+v (want id=%s, not initiator)", p, id)
	}

	// /approve <id> WITHOUT confirm: a preview only — nothing is signed or sent.
	m.runApprove(r, id)
	select {
	case <-executed:
		t.Fatal("the action executed after a preview-only /approve (no confirm)")
	case <-time.After(400 * time.Millisecond):
	}
	if approver.PendingActions()[0].Approved {
		t.Fatal("preview-only /approve must not record an approval")
	}

	// /approve <id> confirm: signs and sends → the requester reaches quorum and runs.
	m.runApprove(r, id+" confirm")
	select {
	case <-executed:
	case <-time.After(3 * time.Second):
		t.Fatal("the action did not execute after /approve confirm")
	}
}

// TestPendingShowsState proves /pending reflects an open request: a pending entry
// with the requester counted as endorser #1 (1/2), then gone once vetoed.
func TestPendingShowsState(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), discardLogger()))
	defer ts.Close()

	requester := connectCore(t, ts.URL, "ops", "requester")
	waitKeyReady(t, requester)
	observer := connectCore(t, ts.URL, "ops", "observer")
	waitKeyReady(t, observer)

	id, err := requester.RequestAction("break_glass", "invite=x, ttl=4h", 2, func() {})
	if err != nil {
		t.Fatalf("request action: %v", err)
	}

	// The requester's own pending list shows it as theirs, at 1/2 (endorser #1).
	if p := requester.PendingActions(); len(p) != 1 || p[0].Count != 1 || p[0].Needed != 2 || !p[0].Initiator {
		t.Fatalf("requester pending = %+v, want one 1/2 initiator entry", p)
	}
	// The observer sees the same request (not as initiator).
	po := waitPending(t, observer)
	if po.RequestID != id || po.Initiator || po.Count != 1 {
		t.Fatalf("observer pending = %+v", po)
	}

	// A veto clears it from both sides.
	if err := observer.VetoAction(id, "not now"); err != nil {
		t.Fatalf("veto: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(requester.PendingActions()) == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("a vetoed request should be cleared from the requester's pending list")
}
