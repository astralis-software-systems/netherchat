package client

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// This file holds the client-side Scuttle Receipt machinery (§1.5): when a room
// is scuttled — manually, by the dead-man's switch, or by owner-loss — the
// scuttling client produces a signed receipt proving the room and its keys were
// destroyed, carrying nothing about the content. The receipt is the only
// surviving artifact.
//
// Two paths, because the server tears a scuttled room down within a short grace
// window (hub.scuttleCloseGrace) and there is no time to collect co-signatures
// AFTER the burn notice arrives:
//
//   - /scuttle now (we initiate): we run a co-signature round while the room is
//     still fully alive, THEN trigger the server burn. The receipt can be
//     multi-party.
//   - server-triggered (idle / owner_loss / armed) or a peer's manual scuttle: we
//     receive an ActionScuttle out of the blue and self-sign a receipt before
//     zeroizing. It is single-party but independently verifiable. Multiple
//     present clients may each write their own receipt — that is expected.

// noteFirstEpochLocked records the first epoch at which this client held a room
// key, for the receipt's epoch_range.first. Caller holds c.mu.
func (c *Client) noteFirstEpochLocked(epoch uint64) {
	if !c.firstEpochSet {
		c.firstEpoch = epoch
		c.firstEpochSet = true
	}
}

// receiptCoreLocked builds the hashable receipt content from current room state.
// Caller holds c.mu. It must be called BEFORE the key is ratcheted/zeroized so
// epoch_range.last reflects the epoch that actually existed.
func (c *Client) receiptCoreLocked(reason string) attest.ReceiptCore {
	last := uint64(0)
	if c.rk != nil {
		last = c.rk.Epoch
	}
	return attest.ReceiptCore{
		Version:      attest.ReceiptVersion,
		Room:         c.room,
		EpochRange:   attest.EpochRange{First: c.firstEpoch, Last: last},
		Reason:       reason,
		ScuttledAt:   time.Now().UTC().Format(time.RFC3339),
		ScuttledBy:   c.id.Fingerprint(),
		MemberFprs:   c.memberFprsLocked(),
		KeysZeroized: true,
	}
}

// startReceiptRound builds a receipt, self-signs it, broadcasts a
// SCUTTLE_RECEIPT_REQUEST, and collects co-signatures for up to 30s (or until
// every present member signs). On finalize it emits EvScuttleReceipt and then
// runs onDone (e.g. to trigger the actual burn for /scuttle now). It returns
// false — taking no action — if there is no room key or a receipt was already
// produced. Used only by the initiating path.
func (c *Client) startReceiptRound(reason string, onDone func()) bool {
	c.mu.Lock()
	if c.rk == nil || c.receiptDone || c.receiptRound != nil {
		c.mu.Unlock()
		return false
	}
	core := c.receiptCoreLocked(reason)
	h := core.Hash()
	preimage := protocol.ScuttleReceiptSigningBytes(h[:])
	sig, err := c.id.Sign(preimage)
	if err != nil {
		c.mu.Unlock()
		return false
	}
	c.receiptRound = newCosignRound(preimage, c.id.Fingerprint(), sig, c.id.SignPub)
	c.receiptCore = core
	c.receiptHash = append([]byte(nil), h[:]...)
	c.receiptOnDone = onDone
	c.receiptRound.timer = time.AfterFunc(sealTimeout, c.finalizeReceipt)
	total := len(c.order)
	c.mu.Unlock()

	body, _ := json.Marshal(protocol.ScuttleReceiptRequestBody{
		ReceiptHash: h[:], RoomID: c.room, Reason: reason, TS: time.Now().Unix(),
		EpochFirst: core.EpochRange.First, EpochLast: core.EpochRange.Last,
	})
	_ = c.sealAndSend(protocol.OpScuttleReceiptRequest, body)
	c.maybeFinalizeReceipt(total)
	return true
}

// writeSelfReceiptIfNeeded produces a single-party receipt for a scuttle we did
// not initiate (server-triggered, or a peer's /scuttle now). It is a no-op if we
// already produced one (the /scuttle-now initiator) or hold no key. It MUST run
// before the key is zeroized.
func (c *Client) writeSelfReceiptIfNeeded(reason string) {
	c.mu.Lock()
	if c.receiptDone || c.rk == nil {
		c.mu.Unlock()
		return
	}
	core := c.receiptCoreLocked(reason)
	c.receiptDone = true
	c.mu.Unlock()

	h := core.Hash()
	sig, err := c.id.Sign(protocol.ScuttleReceiptSigningBytes(h[:]))
	if err != nil {
		c.emit(EvError{Err: fmt.Errorf("sign scuttle receipt: %w", err)})
		return
	}
	fpr := c.id.Fingerprint()
	att := attest.NewReceipt(core,
		map[string][]byte{fpr: sig},
		map[string][]byte{fpr: append([]byte(nil), c.id.SignPub...)},
	)
	c.emit(EvScuttleReceipt{Receipt: att})
}

// onScuttleReceiptRequest co-signs a peer's destruction receipt. We sign the
// requester's receipt hash (which commits to the room, epoch range, reason,
// members, timestamp, and scuttler), after a basic check that it is for THIS
// room.
func (c *Client) onScuttleReceiptRequest(fromName, room string, receiptHash []byte) {
	c.mu.Lock()
	ready := c.rk != nil
	c.mu.Unlock()
	if !ready || room != c.room {
		return
	}
	sig, err := c.id.Sign(protocol.ScuttleReceiptSigningBytes(receiptHash))
	if err != nil {
		return
	}
	body, _ := json.Marshal(protocol.ScuttleReceiptAckBody{
		ReceiptHash: receiptHash, SignerFpr: c.id.Fingerprint(), Sig: sig,
	})
	if err := c.sealAndSend(protocol.OpScuttleReceiptAck, body); err != nil {
		return
	}
	c.emit(EvScuttleReceiptAck{ByName: c.name, Self: true})
}

// onScuttleReceiptAck records a verified co-signature when we are the scuttler.
func (c *Client) onScuttleReceiptAck(fromName string, fromPub ed25519.PublicKey, receiptHash, sig []byte) {
	c.mu.Lock()
	if c.receiptRound == nil || !bytes.Equal(receiptHash, c.receiptHash) {
		c.mu.Unlock()
		return
	}
	if len(fromPub) != ed25519.PublicKeySize || !ed25519.Verify(fromPub, c.receiptRound.preimage, sig) {
		c.mu.Unlock()
		c.emit(EvError{Err: fmt.Errorf("ignoring an invalid scuttle-receipt co-signature from %s", fromName)})
		return
	}
	c.receiptRound.add(crypto.Fingerprint(fromPub), fromPub, sig)
	count, total := c.receiptRound.count(), len(c.order)
	c.mu.Unlock()

	c.emit(EvScuttleReceiptAck{ByName: fromName, Count: count, Total: total})
	c.maybeFinalizeReceipt(total)
}

// maybeFinalizeReceipt finalizes once every present member has co-signed.
func (c *Client) maybeFinalizeReceipt(total int) {
	c.mu.Lock()
	done := c.receiptRound != nil && c.receiptRound.count() >= total
	c.mu.Unlock()
	if done {
		c.finalizeReceipt()
	}
}

// finalizeReceipt assembles and emits the receipt exactly once, then runs the
// queued onDone (which, for /scuttle now, triggers the server burn).
func (c *Client) finalizeReceipt() {
	c.mu.Lock()
	if c.receiptRound == nil {
		c.mu.Unlock()
		return
	}
	c.receiptRound.stop()
	att := attest.NewReceipt(c.receiptCore, c.receiptRound.sigs, c.receiptRound.keys)
	onDone := c.receiptOnDone
	c.receiptRound = nil
	c.receiptOnDone = nil
	c.receiptHash = nil
	c.receiptDone = true
	c.mu.Unlock()

	c.emit(EvScuttleReceipt{Receipt: att})
	if onDone != nil {
		onDone()
	}
}

// clearReceiptLocked drops an in-progress receipt round (NOT the receiptDone
// latch — a room scuttles once). Caller holds c.mu.
func (c *Client) clearReceiptLocked() {
	if c.receiptRound != nil {
		c.receiptRound.stop()
		c.receiptRound = nil
		c.receiptOnDone = nil
		c.receiptHash = nil
	}
}
