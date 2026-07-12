package sneakernet

import (
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/client"
)

// waitScuttleControl waits for the dead-man's-switch control to reach a relay-less
// peer (the coordinator broadcasts it on a burn).
func waitScuttleControl(t *testing.T, c *client.Client, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case ev := <-c.Events():
			if e, ok := ev.(client.EvControl); ok && e.Action == "scuttle" {
				return
			}
		case <-deadline:
			t.Fatal("timed out waiting for the scuttle control")
		case <-c.Done():
			t.Fatal("connection closed before the scuttle control")
		}
	}
}

// assertNoScuttle fails if a scuttle control reaches c within d.
func assertNoScuttle(t *testing.T, c *client.Client, d time.Duration) {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case ev := <-c.Events():
			if e, ok := ev.(client.EvControl); ok && e.Action == "scuttle" {
				t.Fatal("a scuttle control arrived but the action should have been refused")
			}
		case <-deadline:
			return
		case <-c.Done():
			return
		}
	}
}

// TestScuttleRefusedRelayLessWithQuorum is the relay-less regression (§3.2): with a
// configured [action.scuttle] quorum >= 2, a relay-less scuttle FAILS CLOSED — the
// client refuses (there is no way to route an approval to a peer without a relay) and
// does NOT burn unilaterally. This closes the shipping bypass in the pair REPL.
func TestScuttleRefusedRelayLessWithQuorum(t *testing.T) {
	host, joiner, _ := directPair(t)
	host.SetActionQuorum(map[string]int{protocol.ActionScuttleAction: 2})
	before := host.Epoch()

	err := host.ScuttleNow()
	if err == nil {
		t.Fatal("relay-less ScuttleNow with quorum 2 must be refused (fail closed)")
	}
	// Nothing burned: the host's key is unchanged and the joiner sees no scuttle.
	assertNoScuttle(t, joiner, 500*time.Millisecond)
	if host.Epoch() != before {
		t.Fatal("the room burned relay-less despite the quorum-2 refusal")
	}
}

// TestScuttleInstantRelayLessAtQuorumOne proves the emergency single-actor scuttle is
// preserved relay-less (D1): quorum 1 burns immediately and the coordinator propagates
// the control to the peer.
func TestScuttleInstantRelayLessAtQuorumOne(t *testing.T) {
	host, joiner, _ := directPair(t)
	host.SetActionQuorum(map[string]int{protocol.ActionScuttleAction: 1})

	if err := host.ScuttleNow(); err != nil {
		t.Fatalf("relay-less instant scuttle returned error: %v", err)
	}
	waitScuttleControl(t, joiner, 5*time.Second)
}
