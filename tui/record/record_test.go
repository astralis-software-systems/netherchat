package record

import (
	"bytes"
	"testing"

	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// testAuthor returns an Author backed by a freshly generated identity.
func testAuthor(t *testing.T) Author {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return Author{ID: id.Fingerprint(), Name: "tester", Key: id.SignPub, Sign: id.Sign}
}

// TestChainDeterministicHead proves the chain is a pure function of its entries:
// rebuilding the same entries (here, by replaying one chain into another) yields
// the identical head hash.
func TestChainDeterministicHead(t *testing.T) {
	a := testAuthor(t)
	c1 := NewChain()
	if _, err := c1.AppendNew(a, KindDecision, "", "rolled back to v2.3.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := c1.AppendNew(a, KindAction, "bob", "write the post-mortem"); err != nil {
		t.Fatal(err)
	}

	// Rebuild a second chain from the first chain's exact entries.
	c2 := NewChain()
	for _, e := range c1.Entries() {
		if err := c2.AppendRemote(e); err != nil {
			t.Fatalf("append remote: %v", err)
		}
	}
	if !bytes.Equal(c1.Head(), c2.Head()) {
		t.Fatalf("same entries produced different heads:\n c1 %x\n c2 %x", c1.Head(), c2.Head())
	}
	if c1.Len() != 2 {
		t.Fatalf("len = %d, want 2", c1.Len())
	}
}

// TestGenesisAndLinks pins the genesis PrevHash (zeros) and that each entry's
// PrevHash equals the prior entry's hash.
func TestGenesisAndLinks(t *testing.T) {
	a := testAuthor(t)
	c := NewChain()
	e0, _ := c.AppendNew(a, KindDecision, "", "first")
	e1, _ := c.AppendNew(a, KindNote, "", "second")

	if !bytes.Equal(e0.PrevHash, make([]byte, 32)) {
		t.Errorf("genesis prev_hash = %x, want 32 zero bytes", e0.PrevHash)
	}
	h0 := e0.Hash()
	if !bytes.Equal(e1.PrevHash, h0[:]) {
		t.Errorf("entry1 prev_hash = %x, want hash(entry0) = %x", e1.PrevHash, h0[:])
	}
}

// TestTamperBreaksEntrySignature shows that editing a signed field invalidates
// the entry signature (the per-entry integrity layer).
func TestTamperBreaksEntrySignature(t *testing.T) {
	a := testAuthor(t)
	c := NewChain()
	e, _ := c.AppendNew(a, KindDecision, "", "rolled back to v2.3.1")

	if err := VerifyEntry(e); err != nil {
		t.Fatalf("untampered entry should verify: %v", err)
	}
	tampered := e
	tampered.Body = "rolled forward to v9.9.9"
	if err := VerifyEntry(tampered); err == nil {
		t.Fatal("tampered body still verified — signature does not cover the body")
	}

	// Substituting AuthorKey without matching AuthorID must also fail (the binding
	// check), so an attacker cannot present their own key for someone's entry.
	other := testAuthor(t)
	swapped := e
	swapped.AuthorKey = other.Key
	if err := VerifyEntry(swapped); err == nil {
		t.Fatal("author_key substitution not detected (fingerprint binding missing)")
	}
}

// TestForkRejectedOnAppend shows the chain-position checks: an entry whose
// PrevHash or Seq does not continue the chain is rejected rather than corrupting
// the local copy.
func TestForkRejectedOnAppend(t *testing.T) {
	a := testAuthor(t)
	c := NewChain()
	c.AppendNew(a, KindDecision, "", "first")

	// A second, independently-built chain produces an entry with PrevHash = zeros
	// (it thinks it is the genesis). Appending it onto our 1-entry chain forks.
	other := NewChain()
	forking, _ := other.AppendNew(a, KindNote, "", "i think i am first")
	if err := c.AppendRemote(forking); err == nil {
		t.Fatal("forking entry (wrong prev_hash/seq) was accepted")
	}
	if c.Len() != 1 {
		t.Fatalf("chain mutated by a rejected append: len = %d, want 1", c.Len())
	}
}

// TestEntryKinds covers the three kinds /decide, /action, /mark map to.
func TestEntryKinds(t *testing.T) {
	a := testAuthor(t)
	c := NewChain()
	dec, _ := c.AppendNew(a, KindDecision, "", "decided")
	act, _ := c.AppendNew(a, KindAction, "bob", "do the thing")
	note, _ := c.AppendNew(a, KindNote, "", "alice: a noted message")

	if dec.Kind != "decision" || dec.Actionee != "" {
		t.Errorf("decision = %+v", dec)
	}
	if act.Kind != "action" || act.Actionee != "bob" {
		t.Errorf("action = %+v", act)
	}
	if note.Kind != "note" {
		t.Errorf("note = %+v", note)
	}
	for _, e := range c.Entries() {
		if err := VerifyEntry(e); err != nil {
			t.Errorf("entry %d failed to verify: %v", e.Seq, err)
		}
	}
}
