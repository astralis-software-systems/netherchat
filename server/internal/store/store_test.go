package store

import (
	"fmt"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/salehkreiner/netherchat/protocol"
)

func msg(text string) protocol.Envelope {
	env, _ := protocol.Encode(protocol.OpMessage, protocol.Message{Ciphertext: []byte(text)})
	return env
}

func text(t *testing.T, env protocol.Envelope) string {
	t.Helper()
	var m protocol.Message
	if err := env.Decode(&m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return string(m.Ciphertext)
}

func texts(t *testing.T, envs []protocol.Envelope) []string {
	out := make([]string, len(envs))
	for i, e := range envs {
		out[i] = text(t, e)
	}
	return out
}

func runStoreContract(t *testing.T, s Store) {
	t.Helper()
	for i := 0; i < 5; i++ {
		if err := s.Append("ops", msg(fmt.Sprintf("m%d", i))); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if err := s.Append("other", msg("z")); err != nil {
		t.Fatal(err)
	}

	// History returns the most-recent `limit`, oldest-first.
	h, err := s.History("ops", 3)
	if err != nil {
		t.Fatal(err)
	}
	if got := texts(t, h); !reflect.DeepEqual(got, []string{"m2", "m3", "m4"}) {
		t.Fatalf("ops history = %v, want [m2 m3 m4]", got)
	}

	// Rooms are isolated.
	o, err := s.History("other", 10)
	if err != nil {
		t.Fatal(err)
	}
	if got := texts(t, o); !reflect.DeepEqual(got, []string{"z"}) {
		t.Fatalf("other history = %v, want [z]", got)
	}
}

func TestMemoryContract(t *testing.T) { runStoreContract(t, NewMemory(100)) }

func TestSQLiteContract(t *testing.T) {
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "history.db"), 100)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	runStoreContract(t, s)
}

func TestMaxCapEvicts(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func() Store
	}{
		{"memory", func() Store { return NewMemory(2) }},
		{"sqlite", func() Store {
			s, err := OpenSQLite(filepath.Join(t.TempDir(), "cap.db"), 2)
			if err != nil {
				t.Fatal(err)
			}
			return s
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.make()
			defer s.Close()
			for i := 0; i < 5; i++ {
				if err := s.Append("r", msg(fmt.Sprintf("m%d", i))); err != nil {
					t.Fatal(err)
				}
			}
			h, _ := s.History("r", 100)
			if got := texts(t, h); !reflect.DeepEqual(got, []string{"m3", "m4"}) {
				t.Fatalf("capped history = %v, want [m3 m4]", got)
			}
		})
	}
}

func TestSQLiteDurableAcrossOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "durable.db")
	s1, err := OpenSQLite(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	_ = s1.Append("r", msg("persisted"))
	s1.Close()

	s2, err := OpenSQLite(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	h, _ := s2.History("r", 10)
	if got := texts(t, h); !reflect.DeepEqual(got, []string{"persisted"}) {
		t.Fatalf("reopened history = %v, want [persisted]", got)
	}
}
