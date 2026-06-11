package notify

import (
	"errors"
	"strings"
	"testing"
)

func TestMentioned(t *testing.T) {
	cases := []struct {
		text, name string
		want       bool
	}{
		{"hey @alice can you ack", "alice", true},
		{"ALICE please look", "alice", true},
		{"ping alice, the deploy failed", "alice", true},
		{"talk to oncall-2 about it", "oncall-2", true},
		{"alicebob is a different person", "alice", false},
		{"nothing to see here", "alice", false},
		{"", "alice", false},
		{"hi", "", false},
	}
	for _, c := range cases {
		if got := mentioned(c.text, c.name); got != c.want {
			t.Errorf("mentioned(%q, %q) = %v, want %v", c.text, c.name, got, c.want)
		}
	}
}

func TestMentionTriggersOnlyOnMatch(t *testing.T) {
	n := &Notifier{on: map[string]bool{"mention": true}, name: "alice", osName: "linux"}

	// A mention produces a body to deliver…
	body, ok := n.messageBody("ops", "bob", "hey @alice look at this")
	if !ok || !strings.Contains(body, "mentioned you in #ops") {
		t.Fatalf("mention body = %q, ok=%v", body, ok)
	}
	// …and that body routes to the OS notifier (synchronously, via deliver).
	var got []string
	n.run = func(name string, args ...string) error { got = append([]string{name}, args...); return nil }
	n.bell = func() {}
	n.deliver(title, body)
	if len(got) == 0 || got[0] != "notify-send" {
		t.Fatalf("delivery command = %v, want notify-send", got)
	}

	// A non-mention produces nothing.
	if _, ok := n.messageBody("ops", "bob", "no names here"); ok {
		t.Fatal("a non-mention should not produce a notification")
	}
}

func TestCommandForRoutesPerOS(t *testing.T) {
	name, args := commandFor("linux", "T", "B")
	if name != "notify-send" || len(args) != 2 || args[0] != "T" || args[1] != "B" {
		t.Errorf("linux routing = %s %v", name, args)
	}
	name, args = commandFor("darwin", "T", "B")
	if name != "osascript" || args[0] != "-e" || !strings.Contains(args[1], "display notification") {
		t.Errorf("darwin routing = %s %v", name, args)
	}
	name, args = commandFor("windows", "T", "B")
	if name != "powershell" || !strings.Contains(strings.Join(args, " "), "BurntToast") {
		t.Errorf("windows routing = %s %v", name, args)
	}
}

func TestBellFallbackWhenCommandFails(t *testing.T) {
	belled := false
	n := &Notifier{
		on: map[string]bool{"decision": true}, osName: "linux",
		run:  func(name string, args ...string) error { return errors.New("exec: notify-send not found") },
		bell: func() { belled = true },
	}
	n.deliver(title, "Decision in #ops: rolled back")
	if !belled {
		t.Fatal("expected the terminal bell fallback when the notifier command fails")
	}
}

func TestDisabledEventsAreSilent(t *testing.T) {
	fired := false
	n := &Notifier{
		on: map[string]bool{"mention": true}, name: "alice", osName: "linux",
		run:  func(name string, args ...string) error { fired = true; return nil },
		bell: func() { fired = true },
	}
	// decision is not enabled → silent.
	n.Decision("ops", "rolled back")
	if fired {
		t.Fatal("a disabled event fired a notification")
	}
}

func TestSummary(t *testing.T) {
	if got := New([]string{"mention", "decision"}, "alice").Summary(); got != "on (decision, mention)" {
		t.Errorf("summary = %q", got)
	}
	if got := New(nil, "alice").Summary(); got != "off" {
		t.Errorf("empty summary = %q", got)
	}
	var nilN *Notifier
	if got := nilN.Summary(); got != "off" {
		t.Errorf("nil summary = %q", got)
	}
}
