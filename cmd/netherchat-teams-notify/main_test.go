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

func one(t *testing.T, cards [][]byte) string {
	t.Helper()
	if len(cards) != 1 {
		t.Fatalf("expected exactly 1 card, got %d", len(cards))
	}
	return string(cards[0])
}

// TestSealCardNoContentLeak is THE boundary test for notify: the seal card must
// carry only the head hash and signer count — never the sealed decision text.
func TestSealCardNoContentLeak(t *testing.T) {
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
	card := one(t, n.cards(client.EvSealComplete{Record: rec, Entries: 2, Signers: 2}))

	for _, want := range []string{"Incident sealed: #inc-1", "Sealed by: 2 member(s)", "Duration: 1m30s", "Record hash: 0123456789abcdef..."} {
		if !strings.Contains(card, want) {
			t.Errorf("seal card missing %q\n%s", want, card)
		}
	}
	for _, leak := range []string{"SECRET_DECISION_ROLL_BACK_PROD", "SECRET_ACTION_PAGE_ONCALL", "roll", "page"} {
		if strings.Contains(card, leak) {
			t.Fatalf("BOUNDARY VIOLATED: seal card contains content %q\n%s", leak, card)
		}
	}
	// The full head hash must never appear — only the short prefix.
	if strings.Contains(card, rec.HeadHash) {
		t.Fatal("seal card leaked the full head hash")
	}
}

func TestScuttleCard(t *testing.T) {
	n := newNotifier("scuttle")
	// The control frame names who scuttled; the receipt carries reason + proof hash.
	if cards := n.cards(client.EvControl{Action: "scuttle", ByName: "alice", Reason: "manual"}); len(cards) != 0 {
		t.Fatalf("control frame should produce no card yet, got %d", len(cards))
	}
	receipt := &attest.ScuttleReceipt{
		ReceiptCore: attest.ReceiptCore{Reason: "manual", ScuttledBy: "SHA256:zzz"},
		ReceiptHash: "abcdef0123456789abcdef0123456789",
	}
	card := one(t, n.cards(client.EvScuttleReceipt{Receipt: receipt}))
	for _, want := range []string{"Room scuttled: #inc-1", "Scuttled by: alice · Reason: manual", "Receipt: abcdef0123456789..."} {
		if !strings.Contains(card, want) {
			t.Errorf("scuttle card missing %q\n%s", want, card)
		}
	}
}

func TestOpenCardFlow(t *testing.T) {
	n := newNotifier("open")
	invited := false
	n.requestInvite = func() { invited = true }

	// The ingress notice arrives → request an invite, no card yet.
	if cards := n.cards(client.EvServerMessage{Kind: "alert", Text: "[high] scanner/security-finding: S3 bucket public (ref f-1)"}); len(cards) != 0 {
		t.Fatalf("alert notice should not produce a card before the invite, got %d", len(cards))
	}
	if !invited {
		t.Fatal("alert notice should have requested an invite")
	}
	// The minted invite → the open card with a join link.
	card := one(t, n.cards(client.EvInvite{Room: "inc-1", Token: "tok123"}))
	for _, want := range []string{"War room opened: #inc-1", "Severity: high", "Source: scanner", "Opened by: ingress"} {
		if !strings.Contains(card, want) {
			t.Errorf("open card missing %q\n%s", want, card)
		}
	}
	if !strings.Contains(card, "room=inc-1") || !strings.Contains(card, "token=tok123") {
		t.Errorf("open card missing the one-time join link\n%s", card)
	}
}

// TestFiresOnlyOnSubscribed: cards fire on subscribed events and nothing else.
func TestFiresOnlyOnSubscribed(t *testing.T) {
	n := newNotifier("seal") // only seal subscribed
	if cards := n.cards(client.EvSealComplete{Record: &record.SealedRecord{HeadHash: "x"}, Signers: 1}); len(cards) != 1 {
		t.Errorf("seal subscribed → want 1 card, got %d", len(cards))
	}
	n.cards(client.EvControl{Action: "scuttle", ByName: "a", Reason: "manual"})
	if cards := n.cards(client.EvScuttleReceipt{Receipt: &attest.ScuttleReceipt{ReceiptHash: "h"}}); len(cards) != 0 {
		t.Errorf("scuttle not subscribed → want 0 cards, got %d", len(cards))
	}
	if cards := n.cards(client.EvServerMessage{Kind: "alert", Text: "[high] s/k:x"}); len(cards) != 0 {
		t.Errorf("open not subscribed → want 0 cards, got %d", len(cards))
	}
	if cards := n.cards(client.EvServerMessage{Kind: "webhook", Text: "deploy done"}); len(cards) != 0 {
		t.Errorf("non-alert server message → want 0 cards, got %d", len(cards))
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
