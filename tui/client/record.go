package client

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
	"github.com/salehkreiner/netherchat/tui/record"
)

// This file holds the client-side Sealed Record machinery (§1.4): building and
// broadcasting chain entries (/decide, /action, /mark) and the multi-party seal
// handshake (/seal). Entries and seal messages travel as ordinary sealed Message
// envelopes — the relay only ever sees ciphertext (see protocol.OpRecordEntry /
// OpSealRequest / OpSealAck).

// Decide records a decision into the room's record chain (§1.4).
func (c *Client) Decide(text string) error { return c.appendRecord(record.KindDecision, "", text) }

// Action records an action item assigned to @handle.
func (c *Client) Action(handle, text string) error {
	handle = strings.TrimPrefix(strings.TrimSpace(handle), "@")
	if handle == "" {
		return errors.New("usage: /action @handle <text>")
	}
	return c.appendRecord(record.KindAction, handle, text)
}

// Mark promotes the most recent message in the room into the record as a note
// (for messages nobody marked at the time). The note is signed by us (only we can
// sign with our key); when the original message was someone else's, their name is
// preserved in the body so attribution is not lost.
func (c *Client) Mark() error {
	c.mu.Lock()
	last := c.lastMsg
	c.mu.Unlock()
	if last.text == "" {
		return errors.New("no recent message to mark")
	}
	body := last.text
	if last.from != "" && last.from != c.name {
		body = last.from + ": " + last.text
	}
	return c.appendRecord(record.KindNote, "", body)
}

// RecordEntries returns this client's current view of the chain (for inspection
// and tests). The slice is a copy.
func (c *Client) RecordEntries() []record.Entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.chain.Entries()
}

// appendRecord builds, signs, broadcasts, and locally echoes a new chain entry.
// The construction (Seq/PrevHash from the current head, then sign) happens under
// the lock so the signature commits to the correct position; the broadcast and
// echo happen after, mirroring the message path.
func (c *Client) appendRecord(kind, actionee, body string) error {
	body = strings.TrimSpace(body)
	if body == "" {
		return errors.New("nothing to record (empty text)")
	}
	c.mu.Lock()
	if c.rk == nil {
		c.mu.Unlock()
		return errors.New("room key not established yet")
	}
	author := record.Author{ID: c.id.Fingerprint(), Name: c.name, Key: c.id.SignPub, Sign: c.id.Sign}
	e, err := c.chain.AppendNew(author, kind, actionee, body)
	c.mu.Unlock()
	if err != nil {
		return err
	}
	b, _ := json.Marshal(e)
	if err := c.sealAndSend(protocol.OpRecordEntry, b); err != nil {
		return err
	}
	c.emitRecordEntry(e, true, nil, nil, nil)
	return nil
}

// emitRecordEntry surfaces a chain entry to the consumer. sig/signBytes/raw carry
// the originating frame's provenance for the Two-Way Bridge (§1.6) and are nil for
// our own echo (we never receive our own frame back).
func (c *Client) emitRecordEntry(e record.Entry, self bool, sig, signBytes, raw []byte) {
	c.emit(EvRecordEntry{
		Seq: e.Seq, Kind: e.Kind, AuthorName: e.AuthorName, AuthorFpr: e.AuthorID,
		Actionee: e.Actionee, Body: e.Body, Self: self, Replayed: e.Replayed, At: time.Unix(e.TS, 0),
		Sig: sig, SignBytes: signBytes, Raw: raw,
	})
}

// onRecordEntry handles a decrypted record entry from another member: verify it
// and that it links onto our chain, append, and echo. A rejected entry (bad
// signature, fork, out of order) is surfaced as an error and dropped, leaving the
// local chain a valid prefix. sig/signBytes/raw are the originating frame's
// provenance, forwarded to the consumer for the Two-Way Bridge (§1.6).
func (c *Client) onRecordEntry(e record.Entry, sig, signBytes, raw []byte) {
	c.mu.Lock()
	err := c.chain.AppendRemote(e)
	c.mu.Unlock()
	if err != nil {
		c.emit(EvError{Err: fmt.Errorf("record entry rejected: %w", err)})
		return
	}
	c.emitRecordEntry(e, false, sig, signBytes, raw)
}

// Seal drives the multi-party seal handshake (§1.4). Its behavior depends on
// context, which is what lets a single /seal command serve both roles:
//
//   - If a seal request from another participant is pending and our chain head
//     matches theirs, we co-sign it (send a SEAL_ACK) — this is the "acks alice's
//     seal request" path from the demo.
//   - Otherwise we initiate: broadcast a SEAL_REQUEST for our head, record our own
//     signature, and collect co-signatures for up to 30s (or until every present
//     member has signed), then finalize and emit EvSealComplete.
func (c *Client) Seal() error { return c.sealWith("") }

// SealAs is /seal with a declared electronic-signature meaning (item 2): our
// co-signature records WHY we sealed (e.g. record.MeaningApproved), under our
// printed name and a UTC timestamp, all bound into the signed seal preimage.
// Meaning is opaque and extensible; the four record.Meaning* values ship as the
// defaults. A plain Seal() is the bare (no-meaning) co-signature.
func (c *Client) SealAs(meaning string) error { return c.sealWith(meaning) }

func (c *Client) sealWith(meaning string) error {
	// When INITIATING a seal (not co-signing a peer's), capture the incident clock's
	// timing into the record as two signed note entries, so MTTR falls out of the
	// timeline automatically (A1). Appended before we read the head below.
	c.mu.Lock()
	initiating := c.pendingSealHead == nil && !c.sealing
	c.mu.Unlock()
	if initiating {
		c.appendClockNotes()
	}

	c.mu.Lock()
	if c.rk == nil {
		c.mu.Unlock()
		return errors.New("room key not established yet")
	}
	head := c.chain.Head()
	n := c.chain.Len()
	if n == 0 {
		c.mu.Unlock()
		return errors.New("nothing to seal yet — mark decisions with /decide, /action, or /mark first")
	}

	if c.pendingSealHead != nil {
		match := bytes.Equal(c.pendingSealHead, head)
		c.mu.Unlock()
		if !match {
			return errors.New("your record differs from the pending seal request (chains diverged); cannot co-sign")
		}
		return c.sendSealAck(head, meaning)
	}
	if c.sealing {
		c.mu.Unlock()
		return errors.New("a seal is already in progress")
	}

	// Initiate: become the sealer. With a declared meaning we sign the v2 preimage
	// (meaning/name/time bound in) and record our own endorsement; without one it is
	// the bare v1 head signature, byte-for-byte as before.
	fpr := c.id.Fingerprint()
	endorse := map[string]record.Endorsement{}
	var sig []byte
	var err error
	if meaning != "" {
		signedAt := time.Now().UTC().Format(time.RFC3339)
		sig, err = c.id.Sign(protocol.SealSigningBytesV2(c.room, meaning, c.name, signedAt, head))
		endorse[fpr] = record.Endorsement{Meaning: meaning, Name: c.name, SignedAt: signedAt}
	} else {
		sig, err = c.id.Sign(protocol.SealSigningBytes(c.room, head))
	}
	if err != nil {
		c.mu.Unlock()
		return fmt.Errorf("sign seal: %w", err)
	}
	c.sealing = true
	c.sealHead = head
	c.sealEntries = c.chain.Entries()
	c.sealSigs = map[string][]byte{fpr: sig}
	c.sealKeys = map[string][]byte{fpr: append([]byte(nil), c.id.SignPub...)}
	c.sealEndorse = endorse
	// A new seal round supersedes any previously finalized seal: its amend window
	// closes now, so a late ack for the old head is surfaced as stale rather than
	// rewriting a record this fresh round is about to replace (retention is bounded
	// by supersession; the rest is bounded by /vanish in clearSealLocked).
	c.lastSeal = nil
	c.sealTimer = time.AfterFunc(sealTimeout, c.finalizeSeal)
	c.mu.Unlock()

	body, _ := json.Marshal(protocol.SealRequestBody{HeadHash: head})
	if err := c.sealAndSend(protocol.OpSealRequest, body); err != nil {
		return err
	}
	c.emit(EvSealRequest{ByName: c.name, Matches: true, NumEntries: n, Self: true})
	c.maybeFinalize() // finalize immediately if we are the only member present
	return nil
}

// sendSealAck co-signs head and broadcasts a SEAL_ACK to the sealer. A non-empty
// meaning attaches a declared electronic-signature meaning (item 2), signed into
// the v2 preimage; empty meaning is a bare v1 co-signature.
func (c *Client) sendSealAck(head []byte, meaning string) error {
	ack := protocol.SealAckBody{HeadHash: head}
	var err error
	if meaning != "" {
		signedAt := time.Now().UTC().Format(time.RFC3339)
		ack.Sig, err = c.id.Sign(protocol.SealSigningBytesV2(c.room, meaning, c.name, signedAt, head))
		ack.Meaning, ack.SignerName, ack.SignedAt = meaning, c.name, signedAt
	} else {
		ack.Sig, err = c.id.Sign(protocol.SealSigningBytes(c.room, head))
	}
	if err != nil {
		return fmt.Errorf("sign seal: %w", err)
	}
	c.mu.Lock()
	c.pendingSealHead = nil
	c.pendingSealName = ""
	c.mu.Unlock()

	body, _ := json.Marshal(ack)
	if err := c.sealAndSend(protocol.OpSealAck, body); err != nil {
		return err
	}
	c.emit(EvSealAck{ByName: c.name, Self: true})
	return nil
}

// onSealRequest handles a decrypted SEAL_REQUEST from another participant.
func (c *Client) onSealRequest(fromName string, head []byte) {
	c.mu.Lock()
	matches := bytes.Equal(head, c.chain.Head())
	n := c.chain.Len()
	c.pendingSealHead = append([]byte(nil), head...)
	c.pendingSealName = fromName
	// If we are concurrently sealing the same head, the requester has implicitly
	// consented, so co-sign for them without waiting for an explicit /seal.
	autoAck := c.sealing && bytes.Equal(head, c.sealHead)
	c.mu.Unlock()

	if autoAck {
		_ = c.sendSealAck(head, "")
	}
	c.emit(EvSealRequest{ByName: fromName, Matches: matches, NumEntries: n, Self: false})
}

// onSealAck handles a decrypted SEAL_ACK. A co-signature for the seal we are
// actively collecting is verified against the sender's identity key and counted
// (reaching every present member finalizes early). A co-signature that arrives
// AFTER we finalized this same head is not dropped: it is verified and AMENDED into
// the retained record, which is re-persisted (§1.4 HYBRID — no verified signature
// is ever lost). A co-signature we can place onto neither (stale/divergent head, or
// a superseded seal) is surfaced as a diagnostic, never dropped in silence — silent
// drops are exactly what hid the loss.
func (c *Client) onSealAck(fromID, fromName string, fromPub ed25519.PublicKey, head, sig []byte, meaning, signerName, signedAt string) {
	c.mu.Lock()
	active := c.sealing && bytes.Equal(head, c.sealHead)
	amend := !active && c.lastSeal != nil && bytes.Equal(head, c.lastSeal.head)
	if !active && !amend {
		c.mu.Unlock()
		c.emit(EvError{Err: fmt.Errorf("ignoring a seal co-signature from %s: no open or recent seal for that head (chain diverged or superseded)", fromName)})
		return
	}

	if active {
		recorded, valid := c.recordCosignatureLocked(c.sealHead, c.sealSigs, c.sealKeys, c.sealEndorse, fromPub, sig, meaning, signerName, signedAt)
		if !valid {
			c.mu.Unlock()
			c.emit(EvError{Err: fmt.Errorf("ignoring an invalid seal co-signature from %s", fromName)})
			return
		}
		count, total := len(c.sealSigs), len(c.order)
		c.mu.Unlock()
		if recorded {
			c.emit(EvSealAck{ByName: fromName, Count: count, Total: total, Self: false})
		}
		c.maybeFinalize()
		return
	}

	// Amend: a verified co-signature for a head we already finalized. Add it to the
	// retained snapshot and re-persist — the signature is never lost (INV-2), and the
	// update is loud: a fresh EvSealComplete{Amended} rewrites the record in place.
	snap := c.lastSeal
	recorded, valid := c.recordCosignatureLocked(snap.head, snap.sigs, snap.keys, snap.endorse, fromPub, sig, meaning, signerName, signedAt)
	if !valid {
		c.mu.Unlock()
		c.emit(EvError{Err: fmt.Errorf("ignoring an invalid seal co-signature from %s", fromName)})
		return
	}
	if !recorded {
		c.mu.Unlock() // idempotent: this signer is already in the record (INV-6)
		return
	}
	rec := c.assembleSealedLocked(snap)
	entries, signers := len(snap.entries), len(snap.sigs)
	c.mu.Unlock()

	c.emit(EvSealComplete{Record: rec, Entries: entries, Signers: signers, Amended: true})
}

// recordCosignatureLocked verifies a co-signature against the seal head (the bare
// v1 preimage, or the meaning-bearing v2 preimage when meaning != "") and, if valid
// and not already held, records it into the given signature/key/endorsement maps.
// The caller holds c.mu and owns the maps — either the active round's fields or a
// retained snapshot's. It returns (recorded, valid): valid is false only when the
// signature does not verify; recorded is false for a valid duplicate — an
// idempotent no-op (INV-6). endorse must be non-nil (it always is: seeded at seal
// initiation and carried into the snapshot at finalize).
func (c *Client) recordCosignatureLocked(head []byte, sigs, keys map[string][]byte, endorse map[string]record.Endorsement, pub ed25519.PublicKey, sig []byte, meaning, signerName, signedAt string) (recorded, valid bool) {
	preimage := protocol.SealSigningBytes(c.room, head)
	if meaning != "" {
		preimage = protocol.SealSigningBytesV2(c.room, meaning, signerName, signedAt, head)
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, preimage, sig) {
		return false, false
	}
	fpr := crypto.Fingerprint(pub)
	if _, have := sigs[fpr]; have {
		return false, true
	}
	sigs[fpr] = append([]byte(nil), sig...)
	keys[fpr] = append([]byte(nil), pub...)
	if meaning != "" {
		endorse[fpr] = record.Endorsement{Meaning: meaning, Name: signerName, SignedAt: signedAt}
	}
	return true, true
}

// maybeFinalize finalizes the seal once every present member has co-signed.
func (c *Client) maybeFinalize() {
	c.mu.Lock()
	done := c.sealing && len(c.sealSigs) >= len(c.order)
	c.mu.Unlock()
	if done {
		c.finalizeSeal()
	}
}

// finalizeSeal assembles the sealed record from the snapshot taken at seal time
// and the collected signatures, then emits EvSealComplete. It is idempotent: the
// first caller (early completion or the 30s timer) wins; the other is a no-op
// (INV-3). The finalized seal is RETAINED (c.lastSeal) so a co-signature that
// arrives after this point is amended into the record rather than lost (§1.4
// HYBRID); see onSealAck.
func (c *Client) finalizeSeal() {
	c.mu.Lock()
	if !c.sealing {
		c.mu.Unlock()
		return
	}
	if c.sealTimer != nil {
		c.sealTimer.Stop()
		c.sealTimer = nil
	}
	// Transition the active round into a retained amendable snapshot: the maps pass
	// to lastSeal and the active-round fields are cleared. A late verified
	// co-signature for this head amends lastSeal (INV-2), it is never dropped.
	snap := &sealSnapshot{
		head:    c.sealHead,
		entries: c.sealEntries,
		sigs:    c.sealSigs,
		keys:    c.sealKeys,
		endorse: c.sealEndorse,
	}
	rec := c.assembleSealedLocked(snap)
	entries, signers := len(snap.entries), len(snap.sigs)
	c.lastSeal = snap
	c.sealing = false
	c.sealHead = nil
	c.sealEntries = nil
	c.sealSigs = nil
	c.sealKeys = nil
	c.sealEndorse = nil
	c.mu.Unlock()

	c.emit(EvSealComplete{Record: rec, Entries: entries, Signers: signers})
}

// assembleSealedLocked builds a SealedRecord from a seal snapshot plus the retained
// artifact-approval proofs. The caller holds c.mu (it reads c.artifactProofs). The
// collected co-signatures — bare and meaning-bearing alike — are re-added through
// the public Sealer, which re-verifies each; a snapshot with no usable signature
// falls back to a direct assembly so a record is always produced. Used by BOTH the
// initial finalize and the amend path, so artifact-proof attachment is identical on
// both (INV-7).
func (c *Client) assembleSealedLocked(snap *sealSnapshot) *record.SealedRecord {
	sealer := record.NewSealer(c.room, c.id.Fingerprint(), snap.entries)
	for fpr, sig := range snap.sigs {
		key := snap.keys[fpr]
		if end, ok := snap.endorse[fpr]; ok {
			_, _ = sealer.AddEndorsement(key, sig, end.Meaning, end.Name, end.SignedAt)
		} else {
			_, _ = sealer.AddCosignature(key, sig)
		}
	}
	// Persist the retained artifact approval proofs so two-person approval is
	// offline-provable (GAP-1/GAP-2). Add only those whose proposal id matches an
	// artifact entry in this seal (avoiding an unanchored proof set, which the
	// verifier rejects); the Sealer re-verifies each proof against the entry's body.
	for _, e := range snap.entries {
		if e.Kind != record.KindArtifact {
			continue
		}
		m, ok := record.ArtifactOf(e)
		if !ok || m.ProposalID == "" {
			continue
		}
		for _, ca := range c.artifactProofs[m.ProposalID] {
			_, _ = sealer.AddArtifactApproval(m.ProposalID, ed25519.PublicKey(ca.key), ca.sig)
		}
	}
	rec, err := sealer.Finalize()
	if err != nil || rec == nil {
		rec = record.NewSealedRecord(c.room, c.id.Fingerprint(), snap.entries, snap.head, snap.sigs, snap.keys)
	}
	return rec
}

// Replay streams the entries of a previously sealed record into the current room
// as record entries marked Replayed (§2.7), so a retro room can walk a past
// incident's signed minutes without re-litigating them. Each entry is sent
// verbatim except for the Replayed flag — which is unsigned provenance, NOT part
// of the canonical signed bytes (see record.Entry) — so receivers verify the
// original authors' signatures exactly as for live entries, and AppendRemote
// re-links the chain from genesis. The flag is what dims the entries in the UI.
//
// Entries go out in chain order over the single ordered relay connection, so a
// receiver whose record chain is empty (a fresh retro room) appends them in
// sequence; replaying into a room that already holds a record chain is rejected
// by the receivers as a fork — the intended guard, not a bug. The replaying
// client does not append to its own chain (it is a courier, not an author).
// Returns the number of entries streamed.
func (c *Client) Replay(entries []record.Entry) (int, error) {
	c.mu.Lock()
	ready := c.rk != nil
	c.mu.Unlock()
	if !ready {
		return 0, errors.New("room key not established yet")
	}
	for i, e := range entries {
		e.Replayed = true
		b, _ := json.Marshal(e)
		if err := c.sealAndSend(protocol.OpRecordEntry, b); err != nil {
			return i, fmt.Errorf("replay entry %d: %w", e.Seq, err)
		}
	}
	return len(entries), nil
}

// clearSealLocked drops any in-progress or pending seal — and closes the amend
// window on any finalized seal (lastSeal), so /vanish and epoch rotation bound how
// long a late co-signature can still rewrite the record. Caller holds c.mu.
func (c *Client) clearSealLocked() {
	if c.sealTimer != nil {
		c.sealTimer.Stop()
		c.sealTimer = nil
	}
	c.sealing = false
	c.sealHead = nil
	c.sealEntries = nil
	c.sealSigs = nil
	c.sealKeys = nil
	c.sealEndorse = nil
	c.lastSeal = nil
	c.pendingSealHead = nil
	c.pendingSealName = ""
}
