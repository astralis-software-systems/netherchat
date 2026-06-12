package main

import (
	"strings"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/record"
)

func newNotifier(on ...string) *notifier {
	set := map[string]bool{}
	for _, e := range on {
		set[e] = true
	}
	return &notifier{
		room:          "inc-1",
		on:            set,
		webBase:       "http://relay.example.com",
		requestInvite: func() {},
		clockElapsed:  func() (time.Duration, bool, bool) { return 0, false, false },
	}
}

func one(t *testing.T, msgs [][]byte) string {
	t.Helper()
	if len(msgs) != 1 {
		t.Fatalf("expected exactly 1 message, got %d", len(msgs))
	}
	return string(msgs[0])
}

// TestSealMessageNoContentLeak is THE boundary test for notify: the seal message
// must carry only the head hash and signer count — never the sealed decision text.
func TestSealMessageNoContentLeak(t *testing.T) {
	n := newNotifier("seal")
	n.clockElapsed = func() (time.Duration, bool, bool) { return 90 * time.Second, false, true }
	rec := &record.SealedRecord{
		Room:       "inc-1",
		HeadHash:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Signatures: map[string]string{"fpr1": "a", "fpr2": "b"},
		Entries: []record.Entry{
			{Kind: record.KindDecision, AuthorName: "alice", Body: "SECRET_DECISION_ROLL_BACK_PROD"},
			{Kind: record.KindAction, AuthorName: "alice", Actionee: "bob", Body: "SECRET_ACTION_PAGE_ONCALL"},
		},
	}
	msg := one(t, n.messages(client.EvSealComplete{Record: rec, Entries: 2, Signers: 2}))

	for _, want := range []string{"Incident sealed: #inc-1", "Sealed by 2 member(s)", "Duration: 1m30s", "Hash: 0123456789abcdef..."} {
		if !strings.Contains(msg, want) {
			t.Errorf("seal message missing %q\n%s", want, msg)
		}
	}
	for _, leak := range []string{"SECRET_DECISION_ROLL_BACK_PROD", "SECRET_ACTION_PAGE_ONCALL", "roll", "page"} {
		if strings.Contains(msg, leak) {
			t.Fatalf("BOUNDARY VIOLATED: seal message contains content %q\n%s", leak, msg)
		}
	}
	if strings.Contains(msg, rec.HeadHash) {
		t.Fatal("seal message leaked the full head hash")
	}
}

func TestScuttleMessage(t *testing.T) {
	n := newNotifier("scuttle")
	if msgs := n.messages(client.EvControl{Action: "scuttle", ByName: "alice", Reason: "manual"}); len(msgs) != 0 {
		t.Fatalf("control frame should produce no message yet, got %d", len(msgs))
	}
	receipt := &attest.ScuttleReceipt{
		ReceiptCore: attest.ReceiptCore{Reason: "manual", ScuttledBy: "SHA256:zzz"},
		ReceiptHash: "abcdef0123456789abcdef0123456789",
	}
	msg := one(t, n.messages(client.EvScuttleReceipt{Receipt: receipt}))
	for _, want := range []string{"Room scuttled: #inc-1", "By: alice · Reason: manual", "Receipt: abcdef0123456789..."} {
		if !strings.Contains(msg, want) {
			t.Errorf("scuttle message missing %q\n%s", want, msg)
		}
	}
}

func TestOpenMessageFlow(t *testing.T) {
	n := newNotifier("open")
	invited := false
	n.requestInvite = func() { invited = true }

	if msgs := n.messages(client.EvServerMessage{Kind: "alert", Text: "[high] scanner/security-finding: S3 bucket public (ref f-1)"}); len(msgs) != 0 {
		t.Fatalf("alert notice should not produce a message before the invite, got %d", len(msgs))
	}
	if !invited {
		t.Fatal("alert notice should have requested an invite")
	}
	msg := one(t, n.messages(client.EvInvite{Room: "inc-1", Token: "tok123"}))
	for _, want := range []string{"War room opened: #inc-1", "Severity: high", "Source: scanner", "room=inc-1", "token=tok123"} {
		if !strings.Contains(msg, want) {
			t.Errorf("open message missing %q\n%s", want, msg)
		}
	}
}

// TestFiresOnlyOnSubscribed: messages fire on subscribed events and nothing else.
func TestFiresOnlyOnSubscribed(t *testing.T) {
	n := newNotifier("seal") // only seal subscribed
	if msgs := n.messages(client.EvSealComplete{Record: &record.SealedRecord{HeadHash: "x"}, Signers: 1}); len(msgs) != 1 {
		t.Errorf("seal subscribed → want 1 message, got %d", len(msgs))
	}
	n.messages(client.EvControl{Action: "scuttle", ByName: "a", Reason: "manual"})
	if msgs := n.messages(client.EvScuttleReceipt{Receipt: &attest.ScuttleReceipt{ReceiptHash: "h"}}); len(msgs) != 0 {
		t.Errorf("scuttle not subscribed → want 0 messages, got %d", len(msgs))
	}
	if msgs := n.messages(client.EvServerMessage{Kind: "alert", Text: "[high] s/k:x"}); len(msgs) != 0 {
		t.Errorf("open not subscribed → want 0 messages, got %d", len(msgs))
	}
	if msgs := n.messages(client.EvServerMessage{Kind: "webhook", Text: "deploy done"}); len(msgs) != 0 {
		t.Errorf("non-alert server message → want 0 messages, got %d", len(msgs))
	}
}

func TestParseAlertNotice(t *testing.T) {
	sev, src := parseAlertNotice("[critical] siem/siem-alert: rule triggered (ref r1)")
	if sev != "critical" || src != "siem" {
		t.Errorf("parsed sev=%q src=%q", sev, src)
	}
	if s, _ := parseAlertNotice("not a notice"); s != "" {
		t.Errorf("non-notice should parse empty, got %q", s)
	}
}

func TestParseEvents(t *testing.T) {
	if _, err := parseEvents("open,seal,scuttle"); err != nil {
		t.Errorf("valid events rejected: %v", err)
	}
	if _, err := parseEvents("open,decision"); err == nil {
		t.Error("unknown event should be rejected")
	}
	if _, err := parseEvents(""); err == nil {
		t.Error("empty should error")
	}
}
