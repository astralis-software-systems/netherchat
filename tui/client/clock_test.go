package client

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
)

func TestFormatParseHMS(t *testing.T) {
	cases := map[time.Duration]string{
		0:                               "00:00:00",
		47*time.Minute + 23*time.Second: "00:47:23",
		2*time.Hour + 5*time.Minute:     "02:05:00",
		100*time.Hour + 1:               "100:00:00",
	}
	for d, want := range cases {
		if got := formatHMS(d); got != want {
			t.Errorf("formatHMS(%v) = %q, want %q", d, got, want)
		}
	}
	if got := parseHMS("00:47:23"); got != 47*time.Minute+23*time.Second {
		t.Errorf("parseHMS round-trip = %v", got)
	}
	if got := parseHMS("garbage"); got != 0 {
		t.Errorf("parseHMS(garbage) = %v, want 0", got)
	}
}

// TestClockRoundTrip proves /clock start and stop sync to other members and carry
// the elapsed duration (A1).
func TestClockRoundTrip(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLog()))
	defer ts.Close()
	alice := dialClient(t, ts.URL, "ops", "alice")
	waitFor[EvKeyReady](t, alice, 5*time.Second)
	bob := dialClient(t, ts.URL, "ops", "bob")
	waitFor[EvKeyReady](t, bob, 5*time.Second)

	alice.ClockStart()
	if _, running, ok := alice.ClockElapsed(); !ok || !running {
		t.Fatal("alice's clock should be running after start")
	}
	got := waitFor[EvClockStart](t, bob, 5*time.Second)
	if got.Actor != "alice" {
		t.Fatalf("clock start actor = %q", got.Actor)
	}

	time.Sleep(1100 * time.Millisecond) // accumulate ~1s
	alice.ClockStop()
	if _, running, _ := alice.ClockElapsed(); running {
		t.Fatal("clock should be stopped")
	}
	stop := waitFor[EvClockStop](t, bob, 5*time.Second)
	if stop.Actor != "alice" || stop.ElapsedSeconds < 1 {
		t.Fatalf("clock stop = %+v, want alice with elapsed >= 1s", stop)
	}
}

// TestClockSealNotes proves a seal injects two signed timing notes into the record
// (A1) — even when the clock is the only thing in the room.
func TestClockSealNotes(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLog()))
	defer ts.Close()
	alice := dialClient(t, ts.URL, "ops", "alice")
	waitFor[EvKeyReady](t, alice, 5*time.Second)

	alice.ClockStart()
	alice.ClockStop()
	if err := alice.Seal(); err != nil {
		t.Fatalf("seal: %v", err)
	}
	done := waitFor[EvSealComplete](t, alice, 5*time.Second)
	if done.Record == nil || len(done.Record.Entries) != 2 {
		t.Fatalf("sealed record should have the 2 clock notes, got %d entries", len(done.Record.Entries))
	}
	var started, duration bool
	for _, e := range done.Record.Entries {
		if e.Kind != "note" {
			t.Fatalf("clock entry kind = %q, want note", e.Kind)
		}
		if strings.HasPrefix(e.Body, clockNoteStarted) {
			started = true
		}
		if strings.HasPrefix(e.Body, clockNoteDuration) && strings.Contains(e.Body, "(resolved)") {
			duration = true
		}
	}
	if !started || !duration {
		t.Fatalf("sealed record missing clock notes: %+v", done.Record.Entries)
	}
}

// TestClockOngoingNote proves a seal with a still-running clock records "(ongoing)".
func TestClockOngoingNote(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLog()))
	defer ts.Close()
	alice := dialClient(t, ts.URL, "ops", "alice")
	waitFor[EvKeyReady](t, alice, 5*time.Second)

	alice.ClockStart()
	if err := alice.Seal(); err != nil {
		t.Fatalf("seal: %v", err)
	}
	done := waitFor[EvSealComplete](t, alice, 5*time.Second)
	found := false
	for _, e := range done.Record.Entries {
		if strings.HasPrefix(e.Body, clockNoteDuration) && strings.Contains(e.Body, "(ongoing)") {
			found = true
		}
	}
	if !found {
		t.Fatal("a seal with a running clock should record an (ongoing) duration note")
	}
}

// TestClockClearedOnVanish proves /vanish clears the clock (A1).
func TestClockClearedOnVanish(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLog()))
	defer ts.Close()
	alice := dialClient(t, ts.URL, "ops", "alice")
	waitFor[EvKeyReady](t, alice, 5*time.Second)

	alice.ClockStart()
	if _, _, ok := alice.ClockElapsed(); !ok {
		t.Fatal("clock should be running")
	}
	alice.Vanish()
	if _, _, ok := alice.ClockElapsed(); ok {
		t.Fatal("/vanish must clear the incident clock")
	}
}
