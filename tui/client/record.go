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
	c.emitRecordEntry(e, true)
	return nil
}

// emitRecordEntry surfaces a chain entry to the consumer.
func (c *Client) emitRecordEntry(e record.Entry, self bool) {
	c.emit(EvRecordEntry{
		Seq: e.Seq, Kind: e.Kind, AuthorName: e.AuthorName, AuthorFpr: e.AuthorID,
		Actionee: e.Actionee, Body: e.Body, Self: self, Replayed: e.Replayed, At: time.Unix(e.TS, 0),
	})
}

// onRecordEntry handles a decrypted record entry from another member: verify it
// and that it links onto our chain, append, and echo. A rejected entry (bad
// signature, fork, out of order) is surfaced as an error and dropped, leaving the
// local chain a valid prefix.
func (c *Client) onRecordEntry(e record.Entry) {
	c.mu.Lock()
	err := c.chain.AppendRemote(e)
	c.mu.Unlock()
	if err != nil {
		c.emit(EvError{Err: fmt.Errorf("record entry rejected: %w", err)})
		return
	}
	c.emitRecordEntry(e, false)
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
func (c *Client) Seal() error {
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
		return c.sendSealAck(head)
	}
	if c.sealing {
		c.mu.Unlock()
		return errors.New("a seal is already in progress")
	}

	// Initiate: become the sealer.
	sig, err := c.id.Sign(protocol.SealSigningBytes(c.room, head))
	if err != nil {
		c.mu.Unlock()
		return fmt.Errorf("sign seal: %w", err)
	}
	c.sealing = true
	c.sealHead = head
	c.sealEntries = c.chain.Entries()
	c.sealSigs = map[string][]byte{c.id.Fingerprint(): sig}
	c.sealKeys = map[string][]byte{c.id.Fingerprint(): append([]byte(nil), c.id.SignPub...)}
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

// sendSealAck co-signs head and broadcasts a SEAL_ACK to the sealer.
func (c *Client) sendSealAck(head []byte) error {
	sig, err := c.id.Sign(protocol.SealSigningBytes(c.room, head))
	if err != nil {
		return fmt.Errorf("sign seal: %w", err)
	}
	c.mu.Lock()
	c.pendingSealHead = nil
	c.pendingSealName = ""
	c.mu.Unlock()

	body, _ := json.Marshal(protocol.SealAckBody{HeadHash: head, Sig: sig})
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
		_ = c.sendSealAck(head)
	}
	c.emit(EvSealRequest{ByName: fromName, Matches: matches, NumEntries: n, Self: false})
}

// onSealAck handles a decrypted SEAL_ACK. If we are the sealer and the head
// matches ours, the co-signature is verified against the sender's identity key
// and counted; reaching every present member finalizes early.
func (c *Client) onSealAck(fromID, fromName string, fromPub ed25519.PublicKey, head, sig []byte) {
	c.mu.Lock()
	if !c.sealing || !bytes.Equal(head, c.sealHead) {
		c.mu.Unlock()
		return
	}
	if len(fromPub) != ed25519.PublicKeySize ||
		!ed25519.Verify(fromPub, protocol.SealSigningBytes(c.room, c.sealHead), sig) {
		c.mu.Unlock()
		c.emit(EvError{Err: fmt.Errorf("ignoring an invalid seal co-signature from %s", fromName)})
		return
	}
	fpr := crypto.Fingerprint(fromPub)
	c.sealSigs[fpr] = append([]byte(nil), sig...)
	c.sealKeys[fpr] = append([]byte(nil), fromPub...)
	count, total := len(c.sealSigs), len(c.order)
	c.mu.Unlock()

	c.emit(EvSealAck{ByName: fromName, Count: count, Total: total, Self: false})
	c.maybeFinalize()
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
// first caller (early completion or the 30s timer) wins; the other is a no-op.
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
	rec := record.NewSealedRecord(c.room, c.id.Fingerprint(), c.sealEntries, c.sealHead, c.sealSigs, c.sealKeys)
	entries, signers := len(c.sealEntries), len(c.sealSigs)
	c.sealing = false
	c.sealHead = nil
	c.sealEntries = nil
	c.sealSigs = nil
	c.sealKeys = nil
	c.mu.Unlock()

	c.emit(EvSealComplete{Record: rec, Entries: entries, Signers: signers})
}

// clearSealLocked drops any in-progress or pending seal. Caller holds c.mu.
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
	c.pendingSealHead = nil
	c.pendingSealName = ""
}
