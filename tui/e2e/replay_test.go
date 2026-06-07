package e2e

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
	"github.com/salehkreiner/netherchat/tui/record"
)

// sealedFixture builds a small, fully-signed sealed record in memory — the
// artifact a prior incident's /seal would have written. Two identities author a
// decision and an action; both co-sign the chain head over the room-bound seal
// preimage, so the record verifies before we replay it.
func sealedFixture(t *testing.T, room string) *record.SealedRecord {
	t.Helper()
	alice, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	bob, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	c := record.NewChain()
	author := record.Author{ID: alice.Fingerprint(), Name: "alice", Key: alice.SignPub, Sign: alice.Sign}
	if _, err := c.AppendNew(author, record.KindDecision, "", "rolled back to v2.3.1"); err != nil {
		t.Fatalf("append decision: %v", err)
	}
	if _, err := c.AppendNew(author, record.KindAction, "bob", "write the post-mortem"); err != nil {
		t.Fatalf("append action: %v", err)
	}

	head := c.Head()
	sigs := map[string][]byte{}
	keys := map[string][]byte{}
	for _, id := range []*crypto.Identity{alice, bob} {
		s, err := id.Sign(protocol.SealSigningBytes(room, head))
		if err != nil {
			t.Fatalf("seal sign: %v", err)
		}
		sigs[id.Fingerprint()] = s
		keys[id.Fingerprint()] = id.SignPub
	}

	rec := record.NewSealedRecord(room, alice.Fingerprint(), c.Entries(), head, sigs, keys)
	if res, _ := record.Verify(rec); !res.Valid {
		t.Fatalf("fixture record did not verify: %s", res.Reason)
	}
	return rec
}

// TestReplayIntoRoom is the §2.7 acceptance test: a sealed record's entries are
// streamed into a fresh room, and a watcher already in the room receives them in
// order, flagged as replayed, rebuilding the original chain head-for-head. The
// original signatures verify even though the entries were authored by identities
// that were never connected to this server — the proof travels with the entry.
func TestReplayIntoRoom(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLogger()))
	defer ts.Close()

	rec := sealedFixture(t, "inc-001")

	// A watcher is in the (fresh, empty) retro room when the record is replayed in.
	watcher := connect(t, ts.URL, "retro", "watcher", "")
	waitMatch[client.EvKeyReady](t, watcher, nil, 5*time.Second)

	// The replayer joins and, once it sees the room key, streams the record.
	replayer := connect(t, ts.URL, "retro", "replayer", "")
	waitMatch[client.EvKeyReady](t, replayer, nil, 5*time.Second)
	// The watcher must observe the replayer present so the relay fans entries to it.
	waitMatch[client.EvMemberJoined](t, watcher, func(e client.EvMemberJoined) bool {
		return e.Name == "replayer"
	}, 5*time.Second)

	n, err := replayer.Replay(rec.Entries)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if n != len(rec.Entries) {
		t.Fatalf("replayed %d entries, want %d", n, len(rec.Entries))
	}

	// The watcher receives each entry, flagged replayed, in chain order.
	dec := waitMatch[client.EvRecordEntry](t, watcher, func(e client.EvRecordEntry) bool {
		return e.Replayed && e.Kind == record.KindDecision && strings.Contains(e.Body, "v2.3.1")
	}, 5*time.Second)
	if dec.Self {
		t.Error("a replayed entry must not be marked Self on the receiver")
	}
	waitMatch[client.EvRecordEntry](t, watcher, func(e client.EvRecordEntry) bool {
		return e.Replayed && e.Kind == record.KindAction && e.Actionee == "bob"
	}, 5*time.Second)

	// The watcher rebuilt the original chain from the replayed entries: identical
	// hashes (the replayed flag is excluded from the canonical signed bytes), and
	// every entry carries the provenance flag.
	got := watcher.RecordEntries()
	if len(got) != len(rec.Entries) {
		t.Fatalf("watcher chain length = %d, want %d", len(got), len(rec.Entries))
	}
	for i := range got {
		if got[i].Hash() != rec.Entries[i].Hash() {
			t.Fatalf("replayed entry %d differs from the source (chain not faithfully reproduced)", i)
		}
		if !got[i].Replayed {
			t.Errorf("replayed entry %d not flagged on the watcher", i)
		}
	}
}

// TestReplayRejectsTamperedRecord proves the client-side guard: a record whose
// chain has been tampered with does not verify, and the replay path refuses it
// before any frame is sent. (The command verifies first; here we assert the
// underlying record.Verify it gates on catches the tamper.)
func TestReplayRejectsTamperedRecord(t *testing.T) {
	rec := sealedFixture(t, "inc-001")
	rec.Entries[0].Body = "rolled forward to v9.9.9" // tamper after sealing

	res, err := record.Verify(rec)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if res.Valid {
		t.Fatal("tampered record verified — replay would have streamed altered minutes")
	}
}
