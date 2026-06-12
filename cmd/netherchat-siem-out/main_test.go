package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/siemout"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/record"
)

var fixedNow = time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)

func mapOne(t *testing.T, ev client.Event) siemout.Event {
	t.Helper()
	br := &bridge{room: "inc-1"}
	e, ok := br.mapEvent(ev, 5, fixedNow)
	if !ok {
		t.Fatalf("event %T should map", ev)
	}
	if e.Room != "inc-1" || e.RoomEpoch != 5 {
		t.Fatalf("room/epoch wrong: %+v", e)
	}
	return e
}

func TestMapsLifecycleEvents(t *testing.T) {
	at := time.Date(2026, 6, 12, 11, 30, 0, 0, time.UTC)
	cases := []struct {
		ev        client.Event
		wantType  string
		wantActor string
		wantFpr   string
	}{
		{client.EvMemberJoined{Name: "alice", Fingerprint: "SHA256:aaa"}, "join", "alice", "SHA256:aaa"},
		{client.EvMemberLeft{Name: "bob"}, "leave", "bob", ""},
		{client.EvAck{Actor: "carol", Fpr: "SHA256:ccc", At: at}, "ack", "carol", "SHA256:ccc"},
		{client.EvControl{Action: protocol.ActionVanish, ByName: "dave"}, "vanish", "dave", ""},
		{client.EvControl{Action: protocol.ActionScuttle, ByName: "erin"}, "scuttle", "erin", ""},
		{client.EvClockStart{Actor: "frank", Fpr: "SHA256:fff", At: at}, "clock_start", "frank", "SHA256:fff"},
		{client.EvClockStop{Actor: "grace", Fpr: "SHA256:ggg", At: at}, "clock_stop", "grace", "SHA256:ggg"},
		{client.EvActionRequest{RequesterName: "heidi", RequesterFpr: "SHA256:hhh", At: at}, "action_request", "heidi", "SHA256:hhh"},
		{client.EvActionExecuted{RequesterName: "ivan", RequesterFpr: "SHA256:iii", At: at}, "action_executed", "ivan", "SHA256:iii"},
		{client.EvActionVetoed{VetoerName: "judy", VetoerFpr: "SHA256:jjj", At: at}, "action_vetoed", "judy", "SHA256:jjj"},
	}
	for _, c := range cases {
		e := mapOne(t, c.ev)
		if e.Type != c.wantType || e.Actor != c.wantActor || e.Fpr != c.wantFpr {
			t.Errorf("%T → {%q,%q,%q}, want {%q,%q,%q}", c.ev, e.Type, e.Actor, e.Fpr, c.wantType, c.wantActor, c.wantFpr)
		}
		if e.TS == "" {
			t.Errorf("%T produced empty ts", c.ev)
		}
	}
}

func TestSealMapsFingerprintOnly(t *testing.T) {
	rec := &record.SealedRecord{
		Room:     "inc-1",
		SealedBy: "SHA256:sealer",
		HeadHash: "deadbeef",
		Entries:  []record.Entry{{Kind: record.KindDecision, Body: "SECRET_DECISION"}},
	}
	e := mapOne(t, client.EvSealComplete{Record: rec, Signers: 2})
	if e.Type != "seal" || e.Fpr != "SHA256:sealer" {
		t.Fatalf("seal map wrong: %+v", e)
	}
}

// TestContentNeverCrosses is THE boundary test for the bridge: client events that
// carry content (an ack tag, a scuttle reason, an action's params, a seal's
// decisions) must map to events that contain none of it.
func TestContentNeverCrosses(t *testing.T) {
	br := &bridge{room: "inc-1"}
	events := []client.Event{
		client.EvAck{Tag: "SECRET_TAG", Actor: "a", Fpr: "f", At: fixedNow},
		client.EvControl{Action: protocol.ActionScuttle, ByName: "b", Reason: "SECRET_REASON"},
		client.EvActionRequest{Action: "scuttle", Params: "SECRET_PARAMS", ParamsHash: "h", RequesterName: "c", RequesterFpr: "f2", At: fixedNow},
		client.EvSealComplete{Record: &record.SealedRecord{Room: "inc-1", SealedBy: "SHA256:x", Entries: []record.Entry{{Body: "SECRET_DECISION"}}}, Signers: 1},
	}
	for _, ev := range events {
		out, ok := br.mapEvent(ev, 1, fixedNow)
		if !ok {
			t.Fatalf("%T should map", ev)
		}
		b, err := json.Marshal(out)
		if err != nil {
			t.Fatal(err)
		}
		extra, err := siemout.UnexpectedFields(b)
		if err != nil {
			t.Fatal(err)
		}
		if len(extra) != 0 {
			t.Fatalf("boundary violated: unexpected fields %v in %s", extra, b)
		}
		for _, leak := range []string{"SECRET_TAG", "SECRET_REASON", "SECRET_PARAMS", "SECRET_DECISION", "tag", "reason", "params", "decision"} {
			if strings.Contains(string(b), leak) {
				t.Fatalf("BOUNDARY VIOLATED: %q present in %s", leak, b)
			}
		}
	}
}

// TestUnmappedEventsIgnored: events that are not part of the audit trail (chat
// messages, key-ready, a TTL control) produce nothing.
func TestUnmappedEventsIgnored(t *testing.T) {
	br := &bridge{room: "inc-1"}
	for _, ev := range []client.Event{
		client.EvMessage{Text: "hello world"},
		client.EvKeyReady{Epoch: 2},
		client.EvControl{Action: protocol.ActionTTL, TTLSeconds: 60},
		client.EvServerMessage{Kind: "webhook", Text: "deploy done"},
	} {
		if _, ok := br.mapEvent(ev, 1, fixedNow); ok {
			t.Errorf("%T should NOT map to a SIEM event", ev)
		}
	}
}

func TestParseInterval(t *testing.T) {
	if d := parseInterval("10s", time.Second); d != 10*time.Second {
		t.Errorf("parseInterval(10s) = %v", d)
	}
	if d := parseInterval("", 5*time.Second); d != 5*time.Second {
		t.Errorf("empty should default: %v", d)
	}
	if d := parseInterval("garbage", 5*time.Second); d != 5*time.Second {
		t.Errorf("invalid should default: %v", d)
	}
}
