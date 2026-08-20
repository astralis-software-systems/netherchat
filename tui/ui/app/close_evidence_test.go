package app

import (
	"net/http/httptest"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/record"
)

// This test starts where the operator starts: /approve-artifact typed into the
// TUI, and ctrl+c pressed on the success notice. Nothing here reaches into the
// client's send queue or its close sequence — it drives the two commands a person
// drives and then reads the room's record from a third participant who never left.
//
// The shape it reproduces is the one that loses evidence in the field:
//
//	an operator approves an artifact,
//	their client is elected writer (minFpr — NOT the approver who completed quorum),
//	EvArtifactSealed fires and the TUI says it worked,
//	they close the window a few milliseconds later.
//
// The artifact entry is authored on the operator's own chain and never reaches
// anybody else's. No error is raised on any client, the TUI shows nothing, and
// Close's return value — which the teardown discards, as every caller does — is nil.

// waitEvent drains c's event stream until an event of type T arrives.
func waitEvent[T client.Event](t *testing.T, c *client.Client, timeout time.Duration) T {
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

// waitMemberLeft drains c's events until the member named name departs. The relay
// serves each member one ordered outbound stream, so anything that member sent
// before the socket closed has already been delivered by the time this returns:
// it is the deterministic "nothing more is coming from them" point, and it needs
// no sleep.
func waitMemberLeft(t *testing.T, c *client.Client, name string, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case ev := <-c.Events():
			if l, ok := ev.(client.EvMemberLeft); ok && l.Name == name {
				return
			}
		case <-c.Done():
			t.Fatalf("connection closed while waiting for %s to leave", name)
		case <-deadline:
			t.Fatalf("timed out waiting for %s to leave", name)
		}
	}
}

// hasArtifactEntry reports whether c's chain holds the artifact entry for id.
func hasArtifactEntry(c *client.Client, id string) bool {
	for _, e := range c.RecordEntries() {
		if e.Kind != record.KindArtifact {
			continue
		}
		if meta, err := record.ParseArtifactBody(e.Body); err == nil && meta.ProposalID == id {
			return true
		}
	}
	return false
}

// chainSummary renders a chain as "seq:kind" pairs for a failure message.
func chainSummary(c *client.Client) []string {
	var out []string
	for _, e := range c.RecordEntries() {
		out = append(out, e.Kind)
	}
	return out
}

// TestClosingTheTUIAfterApprovalKeepsTheEntryInTheRoom is the operator-shaped
// reproduction of the Close()-discards-queued-evidence defect.
func TestClosingTheTUIAfterApprovalKeepsTheEntryInTheRoom(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), discardLogger()))
	t.Cleanup(ts.Close)

	// Two humans and the agent that proposes. witness never leaves: it stands in for
	// everyone else in the room, and for whoever seals the record later.
	agent := connectCore(t, ts.URL, "ops", "agent")
	waitKeyReady(t, agent)
	one := connectCore(t, ts.URL, "ops", "one")
	waitKeyReady(t, one)
	two := connectCore(t, ts.URL, "ops", "two")
	waitKeyReady(t, two)
	witness := connectCore(t, ts.URL, "ops", "witness")
	waitKeyReady(t, witness)

	// The operator is whichever human the writer election picks — minFpr over the
	// completed approver set. The OTHER human completes quorum, so the operator is
	// the writer without ever having cast the deciding approval: exactly the case
	// countArtifactApproval's "whoever completed it" comment rejects.
	operator, completer := one, two
	operatorName := "one"
	if two.Fingerprint() < one.Fingerprint() {
		operator, completer = two, one
		operatorName = "two"
	}

	// Both humans carry a credential, so the writer files three entries — each
	// approver's identity attestation, then the artifact entry last. That is the
	// ordinary attested case, and it is what puts the artifact entry at the back of
	// the queue.
	if err := operator.UseIdentity(credential(t, operator.Fingerprint(), "qa")); err != nil {
		t.Fatalf("operator identity: %v", err)
	}
	if err := completer.UseIdentity(credential(t, completer.Fingerprint(), "system-owner")); err != nil {
		t.Fatalf("completer identity: %v", err)
	}

	id, err := agent.Propose("planner-agent", "Q3-plan", sha256hex("the plan"), "", 2)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	waitEvent[client.EvArtifactProposed](t, operator, 5*time.Second)
	waitEvent[client.EvArtifactProposed](t, completer, 5*time.Second)
	waitEvent[client.EvArtifactProposed](t, witness, 5*time.Second)

	// The operator's TUI. r.client is the operator's core, wired the way the real
	// model wires it after a connection completes.
	m := newModel(ts.URL, "operator", "", "ops", "")
	r := m.activeRoom()
	r.client = operator
	r.connected = true

	// 1. The operator approves, by typing the command.
	if cmd := m.runCommand("/approve-artifact " + id); cmd != nil {
		cmd()
	}
	waitEvent[client.EvArtifactApproved](t, operator, 5*time.Second)

	// 2. The second human approves, completing quorum. The operator is the writer.
	if err := completer.ApproveArtifact(id, ""); err != nil {
		t.Fatalf("completer approve: %v", err)
	}

	// 3. The operator's own success signal. This is every signal they have: the
	//    proposal is resolved, the room reported it sealed, and the entry is on the
	//    operator's chain. Nothing tells them it has not left the machine.
	waitEvent[client.EvArtifactSealed](t, operator, 5*time.Second)
	if !hasArtifactEntry(operator, id) {
		t.Fatalf("the writer must have authored the entry locally; chain = %v", chainSummary(operator))
	}

	// 4. The operator closes the window.
	if _, cmd := m.onKey(tea.KeyMsg{Type: tea.KeyCtrlC}); cmd == nil {
		t.Fatal("ctrl+c must quit")
	}

	// The operator's socket is gone: everything they ever sent has been delivered.
	waitMemberLeft(t, witness, operatorName, 10*time.Second)

	if !hasArtifactEntry(witness, id) {
		t.Fatalf("the approval is not in the room's record.\n"+
			"  writer chain  = %v  (has the entry)\n"+
			"  witness chain = %v  (does not)\n"+
			"  errors on the witness: %v\n"+
			"  errors in the TUI:     %v\n"+
			"Close discarded it: the frame was queued in sendCh when the context was cancelled.",
			chainSummary(operator), chainSummary(witness), drainErrors(witness), errorLines(r))
	}
}

// drainErrors reports any EvError still queued on c — the "nothing was surfaced"
// half of the failure message.
func drainErrors(c *client.Client) []string {
	var out []string
	for {
		select {
		case ev := <-c.Events():
			if e, ok := ev.(client.EvError); ok {
				out = append(out, e.Err.Error())
			}
		default:
			return out
		}
	}
}
