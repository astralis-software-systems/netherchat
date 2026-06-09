package client

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// This file holds the client-side Signed Roster Attestation machinery (§1.4): a
// portable, co-signed artifact naming the exact set of identities that hold the
// keys for the room at the current epoch. The handshake mirrors /seal — request,
// collect co-signatures, finalize — but signs a membership-set hash rather than a
// record head. All frames travel as ordinary sealed Message envelopes; the relay
// only ever sees ciphertext (protocol.OpRosterRequest / OpRosterAck).

// rosterMeta is the snapshot the attester assembles the artifact from when the
// collection finishes, so later membership changes do not drift the result.
type rosterMeta struct {
	epoch   uint64
	members []attest.RosterMember
	setHash []byte
}

// SignRoster initiates a signed roster attestation (§1.4): it snapshots the
// current membership set, self-signs the set hash, broadcasts a ROSTER_REQUEST,
// and collects co-signatures from present members for up to 30s (or until every
// present member signs), then emits EvRosterComplete with the finished artifact.
//
// verified maps a peer fingerprint to whether this client SAS-verified them; it
// is recorded as informational metadata only — it is NOT part of the signed set
// hash, so it never affects what co-signers attest.
func (c *Client) SignRoster(verified map[string]bool) error {
	c.mu.Lock()
	if c.rk == nil {
		c.mu.Unlock()
		return errors.New("room key not established yet")
	}
	if c.roster != nil {
		c.mu.Unlock()
		return errors.New("a roster attestation is already in progress")
	}
	epoch := c.rk.Epoch
	members := c.rosterMembersLocked(verified)
	setHash := attest.SetHash(fprsOfMembers(members))
	preimage := protocol.RosterSigningBytes(c.room, epoch, setHash)
	sig, err := c.id.Sign(preimage)
	if err != nil {
		c.mu.Unlock()
		return fmt.Errorf("sign roster: %w", err)
	}
	c.roster = newCosignRound(preimage, c.id.Fingerprint(), sig, c.id.SignPub)
	c.rosterMeta = rosterMeta{epoch: epoch, members: members, setHash: setHash}
	c.roster.timer = time.AfterFunc(sealTimeout, c.finalizeRoster)
	total := len(c.order)
	c.mu.Unlock()

	body, _ := json.Marshal(protocol.RosterRequestBody{
		SetHash: setHash, RoomID: c.room, Epoch: epoch,
		ExpiresUnix: time.Now().Add(sealTimeout).Unix(),
	})
	if err := c.sealAndSend(protocol.OpRosterRequest, body); err != nil {
		c.mu.Lock()
		if c.roster != nil {
			c.roster.stop()
			c.roster = nil
		}
		c.mu.Unlock()
		return err
	}
	c.emit(EvRosterRequest{Members: len(members), Self: true})
	c.maybeFinalizeRoster(total)
	return nil
}

// rosterMembersLocked builds the membership set (self + peers) as RosterMembers,
// sorted by fingerprint. Caller holds c.mu.
func (c *Client) rosterMembersLocked(verified map[string]bool) []attest.RosterMember {
	out := make([]attest.RosterMember, 0, len(c.members)+1)
	out = append(out, attest.RosterMember{Name: c.name, Fpr: c.id.Fingerprint()})
	for _, m := range c.members {
		fpr := crypto.Fingerprint(m.signPub)
		out = append(out, attest.RosterMember{Name: m.name, Fpr: fpr, Verified: verified[fpr]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Fpr < out[j].Fpr })
	return out
}

func fprsOfMembers(ms []attest.RosterMember) []string {
	fprs := make([]string, len(ms))
	for i, m := range ms {
		fprs[i] = m.Fpr
	}
	return fprs
}

// memberFprsLocked returns the sorted fingerprints of every member including
// self — the input to the membership-set hash. Caller holds c.mu.
func (c *Client) memberFprsLocked() []string {
	fprs := make([]string, 0, len(c.members)+1)
	fprs = append(fprs, c.id.Fingerprint())
	for _, m := range c.members {
		fprs = append(fprs, crypto.Fingerprint(m.signPub))
	}
	sort.Strings(fprs)
	return fprs
}

// onRosterRequest co-signs a peer's roster request, but only if our independent
// view of the membership set and epoch matches the proposed set hash. An honest
// attestation requires that each co-signer computes the same set — disagreement
// is surfaced, never signed.
func (c *Client) onRosterRequest(fromName string, setHash []byte, epoch uint64) {
	c.mu.Lock()
	if c.rk == nil {
		c.mu.Unlock()
		return
	}
	ourHash := attest.SetHash(c.memberFprsLocked())
	epochOK := c.rk.Epoch == epoch
	c.mu.Unlock()

	if !epochOK || !bytes.Equal(ourHash, setHash) {
		c.emit(EvError{Err: fmt.Errorf("declining @%s roster co-sign: membership set or epoch differs from our view", fromName)})
		return
	}
	sig, err := c.id.Sign(protocol.RosterSigningBytes(c.room, epoch, setHash))
	if err != nil {
		return
	}
	body, _ := json.Marshal(protocol.RosterAckBody{SetHash: setHash, SignerFpr: c.id.Fingerprint(), Sig: sig})
	if err := c.sealAndSend(protocol.OpRosterAck, body); err != nil {
		return
	}
	c.emit(EvRosterAck{ByName: c.name, Self: true})
}

// onRosterAck records a verified co-signature when we are the attester.
func (c *Client) onRosterAck(fromName string, fromPub ed25519.PublicKey, setHash, sig []byte) {
	c.mu.Lock()
	if c.roster == nil || !bytes.Equal(setHash, c.rosterMeta.setHash) {
		c.mu.Unlock()
		return
	}
	if len(fromPub) != ed25519.PublicKeySize || !ed25519.Verify(fromPub, c.roster.preimage, sig) {
		c.mu.Unlock()
		c.emit(EvError{Err: fmt.Errorf("ignoring an invalid roster co-signature from %s", fromName)})
		return
	}
	c.roster.add(crypto.Fingerprint(fromPub), fromPub, sig)
	count, total := c.roster.count(), len(c.order)
	c.mu.Unlock()

	c.emit(EvRosterAck{ByName: fromName, Count: count, Total: total})
	c.maybeFinalizeRoster(total)
}

// maybeFinalizeRoster finalizes once every present member has co-signed.
func (c *Client) maybeFinalizeRoster(total int) {
	c.mu.Lock()
	done := c.roster != nil && c.roster.count() >= total
	c.mu.Unlock()
	if done {
		c.finalizeRoster()
	}
}

// finalizeRoster assembles and emits the roster artifact exactly once: the first
// caller (early completion or the 30s timer) wins; the other is a no-op.
func (c *Client) finalizeRoster() {
	c.mu.Lock()
	if c.roster == nil {
		c.mu.Unlock()
		return
	}
	c.roster.stop()
	att := attest.NewRoster(c.room, c.rosterMeta.epoch, c.id.Fingerprint(), c.rosterMeta.members, c.roster.sigs, c.roster.keys)
	signers, total := c.roster.count(), len(c.rosterMeta.members)
	c.roster = nil
	c.rosterMeta = rosterMeta{}
	c.mu.Unlock()

	c.emit(EvRosterComplete{Attestation: att, Signers: signers, Total: total})
}

// clearRosterLocked drops any in-progress roster round. Caller holds c.mu.
func (c *Client) clearRosterLocked() {
	if c.roster != nil {
		c.roster.stop()
		c.roster = nil
		c.rosterMeta = rosterMeta{}
	}
}
