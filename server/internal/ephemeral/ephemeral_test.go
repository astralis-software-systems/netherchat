package ephemeral

import (
	"strings"
	"testing"
	"time"
)

func TestClampTTL(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want time.Duration
	}{
		{0, MinTTL},
		{time.Second, MinTTL},
		{30 * time.Minute, 30 * time.Minute},
		{30 * 24 * time.Hour, MaxTTL},
	}
	for _, c := range cases {
		if got := ClampTTL(c.in); got != c.want {
			t.Errorf("ClampTTL(%s) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestCreateAndGet(t *testing.T) {
	r := New(nil)
	room := r.Create(2*time.Hour, "host-1")

	if !strings.HasPrefix(room.Name, "war-") {
		t.Errorf("room name %q does not look ephemeral", room.Name)
	}
	if room.CreatedBy != "host-1" {
		t.Errorf("CreatedBy = %q", room.CreatedBy)
	}
	if d := time.Until(room.Deadline); d < time.Hour || d > 2*time.Hour+time.Minute {
		t.Errorf("deadline ~%s out, want ~2h", d)
	}

	got, ok := r.Get(room.Name)
	if !ok || got.Name != room.Name {
		t.Fatalf("Get(%q) = %+v, %v", room.Name, got, ok)
	}
	if _, ok := r.Get("war-deadbeef"); ok {
		t.Error("Get of an unknown room should be false")
	}
}

func TestNamesAreUnique(t *testing.T) {
	r := New(nil)
	seen := make(map[string]bool)
	for i := 0; i < 200; i++ {
		name := r.Create(time.Hour, "host").Name
		if seen[name] {
			t.Fatalf("duplicate ephemeral room name %q", name)
		}
		seen[name] = true
	}
}

func TestSweepExpiresPastDeadline(t *testing.T) {
	r := New(nil)
	var expired []string
	r.Start(func(room, _ string) { expired = append(expired, room) })

	room := r.Create(time.Hour, "host")

	// Before the deadline: nothing happens.
	r.sweep(time.Now())
	if len(expired) != 0 {
		t.Fatalf("room expired early: %v", expired)
	}
	if _, ok := r.Get(room.Name); !ok {
		t.Fatal("room vanished before its deadline")
	}

	// After the deadline: the room is closed exactly once and forgotten.
	r.sweep(room.Deadline.Add(time.Second))
	if len(expired) != 1 || expired[0] != room.Name {
		t.Fatalf("expired = %v, want [%s]", expired, room.Name)
	}
	if _, ok := r.Get(room.Name); ok {
		t.Error("expired room should no longer be tracked")
	}

	// Idempotent: a second sweep does not re-fire.
	r.sweep(room.Deadline.Add(time.Hour))
	if len(expired) != 1 {
		t.Fatalf("room expired twice: %v", expired)
	}
}
