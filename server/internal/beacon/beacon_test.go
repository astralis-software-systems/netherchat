package beacon

import (
	"testing"
	"time"
)

// TestStoreSetGetDelete proves the basic lifecycle: set, read back, overwrite, and
// delete a room's beacon ciphertext.
func TestStoreSetGetDelete(t *testing.T) {
	s := New()
	if _, ok := s.Get("ops"); ok {
		t.Fatal("an empty store should have no beacon")
	}

	s.Set("ops", []byte("ciphertext-1"), time.Hour)
	e, ok := s.Get("ops")
	if !ok || string(e.Ciphertext) != "ciphertext-1" {
		t.Fatalf("get after set = %q, %v", e.Ciphertext, ok)
	}
	if e.UpdatedAt.IsZero() {
		t.Error("updated_at should be set")
	}

	// Set overwrites the previous beacon (one per room).
	s.Set("ops", []byte("ciphertext-2"), time.Hour)
	if e, _ := s.Get("ops"); string(e.Ciphertext) != "ciphertext-2" {
		t.Fatalf("set should overwrite, got %q", e.Ciphertext)
	}

	s.Delete("ops")
	if _, ok := s.Get("ops"); ok {
		t.Fatal("a deleted beacon must be gone")
	}
}

// TestStoreTTLExpiry proves a beacon is no longer returned once its TTL passes
// (lazy purge on Get), independent of any janitor.
func TestStoreTTLExpiry(t *testing.T) {
	s := New()
	s.Set("ops", []byte("ct"), 40*time.Millisecond)
	if _, ok := s.Get("ops"); !ok {
		t.Fatal("beacon should be live before its TTL")
	}
	time.Sleep(70 * time.Millisecond)
	if _, ok := s.Get("ops"); ok {
		t.Fatal("beacon should expire after its TTL")
	}
}

// TestStoreCopiesCiphertext proves the store does not alias the caller's slice.
func TestStoreCopiesCiphertext(t *testing.T) {
	s := New()
	ct := []byte("secret-ish")
	s.Set("ops", ct, time.Hour)
	ct[0] = 'X' // mutate the caller's slice
	if e, _ := s.Get("ops"); string(e.Ciphertext) != "secret-ish" {
		t.Fatalf("store aliased the caller's slice: %q", e.Ciphertext)
	}
}
