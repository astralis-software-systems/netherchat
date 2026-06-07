// Package record implements Netherchat's Sealed Record (§1.4): a hash-chained,
// multi-party-signed artifact of the decisions that mattered during an incident.
//
// The design resolves the central tension of ephemeral chat — "how do we do a
// post-mortem if nothing was saved?" — by promoting ONLY explicitly marked
// entries (/decide, /action, /mark) into an append-only chain. Everything else
// still vanishes. The result is defensible signed minutes with zero transcript
// liability (no persistence-based tool can ship this without contradicting its
// own business model).
//
// Two integrity layers, kept deliberately separate and honest about their
// guarantees:
//
//   - Per-entry authorship: each entry carries an Ed25519 signature by its
//     author over canonical bytes (protocol.RecordSigningBytes) that include the
//     previous entry's hash. The signature commits the entry to its position, so
//     editing any entry, or reordering the chain, invalidates a signature.
//   - Chain integrity: PrevHash links each entry to the SHA-256 of the prior
//     entry's canonical bytes. Tampering with one entry changes its hash, which
//     breaks the next entry's PrevHash, cascading to the head.
//
// AuthorID is the SSH fingerprint of the author's key (the human-recognizable,
// pinnable identifier shown by /whois). Because a fingerprint is a one-way hash
// of a public key, verification needs the key itself, so each entry also carries
// AuthorKey; a verifier checks Fingerprint(AuthorKey) == AuthorID before trusting
// a signature, binding the two. Trust is ultimately anchored by a human
// recognizing a fingerprint they have pinned — the crypto only proves "this key
// signed this, and it hashes to that fingerprint."
//
// This package is pure (protocol + stdlib + the client crypto package for the
// fingerprint helper); it holds no private keys and never connects to anything,
// so `netherchat verify` can run it on a record from a machine that was never in
// the room.
package record

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// Entry kinds. These exact strings are part of the signed canonical bytes and the
// record.json format, so they are a stability contract.
const (
	KindDecision = "decision" // /decide — a decision that was made
	KindAction   = "action"   // /action @owner — an action item assigned to someone
	KindNote     = "note"     // /mark — a message promoted into the record
)

// Entry is one link in the record chain (§1.4). It is both the wire payload of an
// OpRecordEntry Message (JSON, sealed under the room key) and an element of the
// sealed record.json. Only Seq/TS/AuthorID/Kind/Actionee/Body/PrevHash are
// covered by Sig (see protocol.RecordSigningBytes); AuthorName, AuthorKey and
// Replayed are unsigned (AuthorName is cosmetic; AuthorKey is bound to AuthorID by
// the fingerprint check; Replayed is provenance for §2.7 replay).
type Entry struct {
	Seq        uint64 `json:"seq"`
	TS         int64  `json:"ts"` // unix seconds
	AuthorID   string `json:"author_id"`   // SHA256:... fingerprint of the author's identity key
	AuthorName string `json:"author_name"` // cosmetic display name (not authenticated)
	AuthorKey  []byte `json:"author_key"`  // Ed25519 public key (base64); must hash to AuthorID
	Kind       string `json:"kind"`        // decision | action | note
	Actionee   string `json:"actionee,omitempty"`
	Body       string `json:"body"`
	PrevHash   []byte `json:"prev_hash"` // SHA-256 of the previous entry's canonical bytes (32 bytes, base64)
	Sig        []byte `json:"sig"`       // Ed25519 over canonical(); 64 bytes, base64

	// Replayed marks an entry that was streamed in from a prior sealed record
	// during a retro (§2.7). It is provenance only — NOT part of the signed bytes
	// or the chain hash — so setting it never affects verification.
	Replayed bool `json:"replayed,omitempty"`
}

// canonical returns the exact bytes Sig covers and Hash digests.
func (e Entry) canonical() []byte {
	return protocol.RecordSigningBytes(e.Seq, e.TS, e.AuthorID, e.Kind, e.Actionee, e.Body, e.PrevHash)
}

// Hash is the SHA-256 of the entry's canonical bytes — the value the NEXT entry
// stores as PrevHash, and (for the last entry) the chain head that sealers sign.
func (e Entry) Hash() [32]byte { return sha256.Sum256(e.canonical()) }

// zeroHash is the PrevHash of the genesis entry: there is no previous entry, so
// the chain is rooted at 32 zero bytes.
func zeroHash() []byte { return make([]byte, 32) }

// VerifyEntry checks an entry in isolation: that AuthorKey is a well-formed
// Ed25519 key, that it hashes to the claimed AuthorID (binding the human-readable
// fingerprint to the verifying key), that Kind is known, and that Sig is a valid
// signature by AuthorKey over the canonical bytes. It does NOT check chain
// position — that is the Chain's / Verify's job.
func VerifyEntry(e Entry) error {
	if len(e.AuthorKey) != ed25519.PublicKeySize {
		return fmt.Errorf("entry %d: author_key is %d bytes, want %d", e.Seq, len(e.AuthorKey), ed25519.PublicKeySize)
	}
	pub := ed25519.PublicKey(e.AuthorKey)
	if fpr := crypto.Fingerprint(pub); fpr != e.AuthorID {
		return fmt.Errorf("entry %d: author_key fingerprint %s does not match author_id %s", e.Seq, fpr, e.AuthorID)
	}
	switch e.Kind {
	case KindDecision, KindAction, KindNote:
	default:
		return fmt.Errorf("entry %d: unknown kind %q", e.Seq, e.Kind)
	}
	if len(e.PrevHash) != sha256.Size {
		return fmt.Errorf("entry %d: prev_hash is %d bytes, want %d", e.Seq, len(e.PrevHash), sha256.Size)
	}
	if !ed25519.Verify(pub, e.canonical(), e.Sig) {
		return fmt.Errorf("entry %d: signature does not verify against author %s", e.Seq, e.AuthorID)
	}
	return nil
}

// Author is the identity a Chain signs new entries with. Sign is the raw Ed25519
// signing function (an *crypto.Identity satisfies it via id.Sign), so an
// ssh-agent identity works without the private key entering this process.
type Author struct {
	ID   string            // SHA256:... fingerprint (must equal Fingerprint(Key))
	Name string            // display name
	Key  ed25519.PublicKey // identity public key
	Sign func([]byte) ([]byte, error)
}

// Chain is an in-memory, append-only sequence of record entries. Each client
// builds its own copy: the author of an entry appends it locally and broadcasts
// it; every other present member appends the same entry on receipt, so the chains
// converge. The zero value is an empty chain.
type Chain struct {
	entries []Entry
}

// NewChain returns an empty chain.
func NewChain() *Chain { return &Chain{} }

// Len reports the number of entries.
func (c *Chain) Len() int { return len(c.entries) }

// Entries returns a copy of the chain's entries (safe for the caller to retain).
func (c *Chain) Entries() []Entry {
	out := make([]Entry, len(c.entries))
	copy(out, c.entries)
	return out
}

// Head returns the chain head: the hash of the last entry, or 32 zero bytes for
// an empty chain. This is what a seal proposes and participants co-sign.
func (c *Chain) Head() []byte {
	if len(c.entries) == 0 {
		return zeroHash()
	}
	h := c.entries[len(c.entries)-1].Hash()
	return h[:]
}

// Reset empties the chain (used on /vanish: an unsealed chain is, like everything
// else in the room, deliberately not kept).
func (c *Chain) Reset() { c.entries = nil }

// AppendNew constructs, signs, and appends a brand-new entry authored locally,
// returning the entry to broadcast. Seq and PrevHash are taken from the current
// chain state so the signature commits to the entry's position.
func (c *Chain) AppendNew(a Author, kind, actionee, body string) (Entry, error) {
	e := Entry{
		Seq:        uint64(len(c.entries)),
		TS:         time.Now().Unix(),
		AuthorID:   a.ID,
		AuthorName: a.Name,
		AuthorKey:  append([]byte(nil), a.Key...),
		Kind:       kind,
		Actionee:   actionee,
		Body:       body,
		PrevHash:   c.Head(),
	}
	sig, err := a.Sign(e.canonical())
	if err != nil {
		return Entry{}, fmt.Errorf("sign record entry: %w", err)
	}
	e.Sig = sig
	c.entries = append(c.entries, e)
	return e, nil
}

// AppendRemote verifies an entry received from another member (or replayed from a
// prior record) and appends it. It enforces both the entry's own signature and
// its chain position (Seq and PrevHash must continue this chain), so a forged,
// out-of-order, or forking entry is rejected rather than silently corrupting the
// local chain.
func (c *Chain) AppendRemote(e Entry) error {
	if err := VerifyEntry(e); err != nil {
		return err
	}
	if e.Seq != uint64(len(c.entries)) {
		return fmt.Errorf("record entry seq %d out of order (expected %d)", e.Seq, len(c.entries))
	}
	if !bytes.Equal(e.PrevHash, c.Head()) {
		return errors.New("record entry prev_hash does not link to the current head (chain fork)")
	}
	c.entries = append(c.entries, e)
	return nil
}
