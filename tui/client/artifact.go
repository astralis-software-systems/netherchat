package client

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
	"github.com/salehkreiner/netherchat/tui/record"
)

// This file holds the client-side Agent-Decision Attestation machinery (NC-W1): an
// agent (or a human acting for one) PROPOSES an artifact it produced; one or more
// named humans APPROVE it under the existing Two-Person Rule; on quorum the artifact
// becomes a signed, hash-chained "artifact" record entry. It rides the same E2E
// Message path as the Two-Person Rule (the relay only ever sees ciphertext) and
// reuses the sealed-record chain — an artifact entry is just a record.Entry with
// Kind == KindArtifact whose Body is the artifact metadata.
//
// THE SECOND LAW IS ENFORCED HERE: the proposer is recorded as proposer_fpr and can
// NEVER count toward its own quorum (addApprover and ApproveArtifact both reject it).
// An agent proposes; a human approves; the agent can never self-approve.
//
// THE BOUNDARY LAW: only the artifact's hex SHA-256 (artifact_hash) ever crosses —
// the artifact content is never in a proposal, an approval, the record, the relay,
// or any log.

// artifactProposalTTL bounds how long a proposal waits for approval before it is
// discarded (NC-W1: 300s). It is a var only so tests can shorten it.
var artifactProposalTTL = 300 * time.Second

// trackedProposal is the in-memory lifecycle of one artifact proposal, held by every
// client that observes it. All access is under Client.mu.
type trackedProposal struct {
	prop      protocol.ArtifactProposalBody
	fromName  string          // proposer display name (for events)
	approvers map[string]bool // distinct human approver fingerprints (NEVER the proposer)
	order     []string        // approver fingerprints in arrival order (for the sealed event)
	approved  bool            // (approver side) we have already sent our approval
	initiator bool            // we created this proposal
	timer     *time.Timer
	resolved  bool // approved-to-quorum | rejected | expired — latched, then dropped
}

// addApprover records a distinct, valid human approver. The PROPOSER is never
// counted (the second law); duplicates by fingerprint do not increment. Returns
// whether the approver was newly counted.
func (tp *trackedProposal) addApprover(fpr string) bool {
	if tp.resolved || fpr == tp.prop.ProposerFpr || tp.approvers[fpr] {
		return false
	}
	tp.approvers[fpr] = true
	tp.order = append(tp.order, fpr)
	return true
}

func (tp *trackedProposal) approverList() []string {
	out := make([]string, len(tp.order))
	copy(out, tp.order)
	return out
}

func (tp *trackedProposal) stop() {
	if tp.timer != nil {
		tp.timer.Stop()
		tp.timer = nil
	}
}

// PendingProposal is a snapshot of one pending proposal, for /pending and the TUI.
type PendingProposal struct {
	ProposalID   string
	Source       string
	ArtifactRef  string
	ArtifactHash string
	Summary      string
	ProposerName string
	ProposerFpr  string
	Approvers    int // distinct human approvers so far
	Quorum       int
	ExpiresUnix  int64
	Initiator    bool
}

// Propose broadcasts an artifact proposal for human approval (NC-W1). source is the
// agent/tool label, ref the artifact's title/reference, hash the hex SHA-256 of the
// artifact CONTENT (never the content). quorum is the number of distinct human
// approvers required (from [action.artifact]; <1 is treated as 1). It returns the
// proposal id. The proposer can never approve its own proposal.
func (c *Client) Propose(source, ref, hash, summary string, quorum int) (string, error) {
	source, ref, hash = strings.TrimSpace(source), strings.TrimSpace(ref), strings.TrimSpace(hash)
	if source == "" || ref == "" || hash == "" {
		return "", errors.New("propose requires a source, an artifact ref, and an artifact hash")
	}
	if quorum < 1 {
		quorum = 1
	}
	c.mu.Lock()
	ready := c.rk != nil
	c.mu.Unlock()
	if !ready {
		return "", errors.New("room key not established yet")
	}

	proposalID := newRequestID()
	body := protocol.ArtifactProposalBody{
		ProposalID:   proposalID,
		Source:       source,
		ArtifactRef:  ref,
		ArtifactHash: hash,
		Summary:      summary,
		ProposerFpr:  c.id.Fingerprint(),
		Quorum:       quorum,
		ProposedAt:   time.Now().UTC().Format(time.RFC3339),
		ExpiresUnix:  time.Now().Add(artifactProposalTTL).Unix(),
		Nonce:        newRequestID(),
	}
	tp := &trackedProposal{prop: body, fromName: c.name, approvers: map[string]bool{}, initiator: true}

	c.mu.Lock()
	c.armProposalTimerLocked(tp)
	c.proposals[proposalID] = tp
	c.mu.Unlock()

	b, _ := json.Marshal(body)
	if err := c.sealAndSend(protocol.OpArtifactProposal, b); err != nil {
		c.mu.Lock()
		if x := c.proposals[proposalID]; x != nil {
			x.stop()
			delete(c.proposals, proposalID)
		}
		c.mu.Unlock()
		return "", err
	}
	c.emit(EvArtifactProposed{
		ProposalID: proposalID, Source: source, ArtifactRef: ref, ArtifactHash: hash, Summary: summary,
		ProposerName: c.name, ProposerFpr: c.id.Fingerprint(), Quorum: quorum, Self: true, At: time.Now(),
	})
	return proposalID, nil
}

// ApproveArtifact signs and broadcasts a human approval of a pending proposal, then
// accounts it locally. proposalID may be a unique prefix. It refuses to approve a
// proposal we authored (the second law: an agent/proposer can never self-approve).
func (c *Client) ApproveArtifact(proposalID string) error {
	c.mu.Lock()
	id, ok := c.resolveProposalIDLocked(proposalID)
	if !ok {
		c.mu.Unlock()
		return fmt.Errorf("no pending artifact proposal matching %q", proposalID)
	}
	tp := c.proposals[id]
	switch {
	case tp.resolved:
		c.mu.Unlock()
		return errors.New("that proposal has already been resolved")
	case tp.prop.ProposerFpr == c.id.Fingerprint():
		c.mu.Unlock()
		return errors.New("you cannot approve your own proposal — a proposer (agent) can never self-approve")
	case tp.approved:
		c.mu.Unlock()
		return errors.New("you have already approved this proposal")
	case tp.prop.ArtifactHash == "":
		c.mu.Unlock()
		return errors.New("refusing to approve: the proposal has no artifact hash")
	}
	prop := tp.prop
	ready := c.rk != nil
	c.mu.Unlock()
	if !ready {
		return errors.New("room key not established yet")
	}

	fpr := c.id.Fingerprint()
	sig, err := c.id.Sign(protocol.ArtifactApprovalSigningBytes(prop.ProposalID, prop.ArtifactHash, fpr, prop.Nonce))
	if err != nil {
		return err
	}
	body, _ := json.Marshal(protocol.ArtifactApprovalBody{
		ProposalID: prop.ProposalID, ArtifactHash: prop.ArtifactHash, ApproverFpr: fpr, Sig: sig,
	})
	if err := c.sealAndSend(protocol.OpArtifactApproval, body); err != nil {
		return err
	}

	// Account our own approval locally and react to it exactly as if it had arrived
	// from a peer (the relay does not echo our own frame back to us).
	c.mu.Lock()
	tp = c.proposals[prop.ProposalID]
	if tp == nil || tp.resolved {
		c.mu.Unlock()
		return nil
	}
	tp.approved = true
	c.mu.Unlock()
	c.countArtifactApproval(prop.ProposalID, c.name, fpr, true)
	return nil
}

// RejectArtifact discards a pending proposal and tells the room. No record entry is
// written. Any present member may reject; proposalID may be a unique prefix.
func (c *Client) RejectArtifact(proposalID, reason string) error {
	c.mu.Lock()
	id, ok := c.resolveProposalIDLocked(proposalID)
	if !ok {
		c.mu.Unlock()
		return fmt.Errorf("no pending artifact proposal matching %q", proposalID)
	}
	tp := c.proposals[id]
	if tp.resolved {
		c.mu.Unlock()
		return errors.New("that proposal has already been resolved")
	}
	ref := tp.prop.ArtifactRef
	tp.resolved = true
	tp.stop()
	delete(c.proposals, id)
	ready := c.rk != nil
	c.mu.Unlock()
	if !ready {
		return errors.New("room key not established yet")
	}

	body, _ := json.Marshal(protocol.ArtifactRejectionBody{ProposalID: id, RejecterFpr: c.id.Fingerprint(), Reason: reason})
	if err := c.sealAndSend(protocol.OpArtifactRejection, body); err != nil {
		return err
	}
	c.emit(EvArtifactRejected{ProposalID: id, ArtifactRef: ref, RejecterName: c.name, RejecterFpr: c.id.Fingerprint(), Reason: reason, Self: true, At: time.Now()})
	return nil
}

// PendingProposals returns a snapshot of unresolved proposals, sorted by id.
func (c *Client) PendingProposals() []PendingProposal {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]PendingProposal, 0, len(c.proposals))
	for _, tp := range c.proposals {
		if tp.resolved {
			continue
		}
		out = append(out, PendingProposal{
			ProposalID: tp.prop.ProposalID, Source: tp.prop.Source, ArtifactRef: tp.prop.ArtifactRef,
			ArtifactHash: tp.prop.ArtifactHash, Summary: tp.prop.Summary,
			ProposerName: tp.fromName, ProposerFpr: tp.prop.ProposerFpr,
			Approvers: len(tp.approvers), Quorum: tp.prop.Quorum, ExpiresUnix: tp.prop.ExpiresUnix,
			Initiator: tp.initiator,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ProposalID < out[j].ProposalID })
	return out
}

// --- inbound frame handlers -------------------------------------------------

// onArtifactProposal records a proposal from another member and surfaces it. The
// proposer_fpr must match the signed Message's sender, so a proposal cannot be
// attributed to anyone but its actual author.
func (c *Client) onArtifactProposal(senderName, senderFpr string, body protocol.ArtifactProposalBody) {
	if body.ProposalID == "" || body.ArtifactHash == "" || body.Quorum < 1 {
		return
	}
	if body.ProposerFpr != senderFpr {
		c.emit(EvError{Err: fmt.Errorf("ignoring artifact proposal from %s: proposer_fpr does not match the signer", senderName)})
		return
	}
	if body.ExpiresUnix > 0 && time.Now().Unix() >= body.ExpiresUnix {
		return // already expired in flight
	}
	c.mu.Lock()
	if _, exists := c.proposals[body.ProposalID]; exists {
		c.mu.Unlock()
		return
	}
	tp := &trackedProposal{prop: body, fromName: senderName, approvers: map[string]bool{}}
	c.armProposalTimerLocked(tp)
	c.proposals[body.ProposalID] = tp
	c.mu.Unlock()

	c.emit(EvArtifactProposed{
		ProposalID: body.ProposalID, Source: body.Source, ArtifactRef: body.ArtifactRef, ArtifactHash: body.ArtifactHash,
		Summary: body.Summary, ProposerName: senderName, ProposerFpr: body.ProposerFpr, Quorum: body.Quorum, At: time.Now(),
	})
}

// onArtifactApproval verifies and counts an approval that arrived from a peer.
func (c *Client) onArtifactApproval(senderName string, senderPub ed25519.PublicKey, body protocol.ArtifactApprovalBody) {
	c.mu.Lock()
	tp := c.proposals[body.ProposalID]
	if tp == nil || tp.resolved {
		c.mu.Unlock()
		return // unknown / already resolved → silently discard
	}
	prop := tp.prop
	c.mu.Unlock()

	if body.ArtifactHash != prop.ArtifactHash {
		c.emit(EvError{Err: fmt.Errorf("rejecting artifact approval from %s: artifact_hash does not match the proposal", senderName)})
		return
	}
	signerFpr := crypto.Fingerprint(senderPub)
	if body.ApproverFpr != signerFpr {
		c.emit(EvError{Err: fmt.Errorf("rejecting artifact approval from %s: approver_fpr does not match the signer", senderName)})
		return
	}
	preimage := protocol.ArtifactApprovalSigningBytes(prop.ProposalID, prop.ArtifactHash, body.ApproverFpr, prop.Nonce)
	if len(senderPub) != ed25519.PublicKeySize || !ed25519.Verify(senderPub, preimage, body.Sig) {
		c.emit(EvError{Err: fmt.Errorf("rejecting artifact approval from %s: invalid signature", senderName)})
		return
	}
	c.countArtifactApproval(body.ProposalID, senderName, signerFpr, false)
}

// onArtifactRejection cancels a pending proposal seen on the wire.
func (c *Client) onArtifactRejection(senderName, senderFpr string, body protocol.ArtifactRejectionBody) {
	c.mu.Lock()
	tp := c.proposals[body.ProposalID]
	if tp == nil || tp.resolved {
		c.mu.Unlock()
		return
	}
	ref := tp.prop.ArtifactRef
	tp.resolved = true
	tp.stop()
	delete(c.proposals, body.ProposalID)
	c.mu.Unlock()
	c.emit(EvArtifactRejected{ProposalID: body.ProposalID, ArtifactRef: ref, RejecterName: senderName, RejecterFpr: senderFpr, Reason: body.Reason, At: time.Now()})
}

// countArtifactApproval applies one verified approval to a tracked proposal — used
// both for approvals that arrive over the wire and for our own (locally accounted)
// one — and drives the quorum/seal transition. The approver that COMPLETES quorum
// (self) writes the signed artifact record entry; every client emits the sealed
// event. It must NOT be called with c.mu held.
func (c *Client) countArtifactApproval(proposalID, approverName, approverFpr string, self bool) {
	c.mu.Lock()
	tp := c.proposals[proposalID]
	if tp == nil || tp.resolved {
		c.mu.Unlock()
		return
	}
	if !tp.addApprover(approverFpr) {
		c.mu.Unlock()
		return // proposer, duplicate, or already resolved
	}
	count := len(tp.approvers)
	needed := tp.prop.Quorum
	reached := count >= needed
	prop := tp.prop
	var approvers []string
	if reached {
		tp.resolved = true
		tp.stop()
		approvers = tp.approverList()
		delete(c.proposals, proposalID)
	}
	c.mu.Unlock()

	c.emit(EvArtifactApproved{
		ProposalID: proposalID, ArtifactRef: prop.ArtifactRef, ArtifactHash: prop.ArtifactHash,
		ApproverName: approverName, ApproverFpr: approverFpr,
		Count: count, Quorum: needed, Self: self, At: time.Now(),
	})
	if !reached {
		return
	}
	// Quorum reached. Exactly one client writes the signed artifact record entry: the
	// approver with the lowest fingerprint among the (now-complete) approver set. This
	// is deterministic and computed identically on every client from the same set, so
	// there is no double-write (chain fork) and no "nobody writes" race — unlike a
	// "whoever completed it" rule, which fails when the completing approval arrives
	// over the wire rather than locally. The writer authors and signs the entry, so
	// its signature proves that approver signed off on this exact artifact hash.
	writer := minFpr(approvers)
	if writer == c.id.Fingerprint() {
		c.writeArtifactEntry(prop, writer)
	}
	c.emit(EvArtifactSealed{
		ProposalID: proposalID, Source: prop.Source, ArtifactRef: prop.ArtifactRef,
		ArtifactHash: prop.ArtifactHash, Approvers: approvers, At: time.Now(),
	})
}

// minFpr returns the lexicographically smallest fingerprint in the set — the
// deterministic designated writer for a completed proposal.
func minFpr(fprs []string) string {
	if len(fprs) == 0 {
		return ""
	}
	m := fprs[0]
	for _, f := range fprs[1:] {
		if f < m {
			m = f
		}
	}
	return m
}

// writeArtifactEntry appends the signed "artifact" record entry that attests the
// approval, and broadcasts it on the normal record-entry path so every member's
// chain converges. AuthorID is the writer (the approving human), which equals
// approver_fpr — so the entry's own signature proves that human approved this exact
// artifact hash.
func (c *Client) writeArtifactEntry(prop protocol.ArtifactProposalBody, approverFpr string) {
	meta := record.ArtifactMeta{
		Source:       prop.Source,
		ArtifactRef:  prop.ArtifactRef,
		ArtifactHash: prop.ArtifactHash,
		ApproverFpr:  approverFpr,
		ProposedAt:   prop.ProposedAt,
		ApprovedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	body, err := record.MarshalArtifactBody(meta)
	if err != nil {
		c.emit(EvError{Err: fmt.Errorf("artifact: marshal record body: %w", err)})
		return
	}
	if err := c.appendRecord(record.KindArtifact, "", body); err != nil {
		c.emit(EvError{Err: fmt.Errorf("artifact: write record entry: %w", err)})
	}
}

// expireProposal fires from the proposal's timer: if it never reached quorum it is
// discarded and reported.
func (c *Client) expireProposal(proposalID string) {
	c.mu.Lock()
	tp := c.proposals[proposalID]
	if tp == nil || tp.resolved {
		c.mu.Unlock()
		return
	}
	tp.resolved = true
	tp.stop()
	ref := tp.prop.ArtifactRef
	delete(c.proposals, proposalID)
	c.mu.Unlock()
	c.emit(EvArtifactExpired{ProposalID: proposalID, ArtifactRef: ref, At: time.Now()})
}

// armProposalTimerLocked starts the expiry timer, honoring expires_unix so observers
// expire in step with the proposer. Caller holds c.mu.
func (c *Client) armProposalTimerLocked(tp *trackedProposal) {
	d := artifactProposalTTL
	if tp.prop.ExpiresUnix > 0 {
		if rem := time.Until(time.Unix(tp.prop.ExpiresUnix, 0)); rem > 0 {
			d = rem
		}
	}
	id := tp.prop.ProposalID
	tp.timer = time.AfterFunc(d, func() { c.expireProposal(id) })
}

// resolveProposalIDLocked resolves a full id or a unique prefix to a tracked,
// unresolved proposal id. Caller holds c.mu.
func (c *Client) resolveProposalIDLocked(prefix string) (string, bool) {
	if tp, ok := c.proposals[prefix]; ok && !tp.resolved {
		return prefix, true
	}
	var match string
	n := 0
	for id, tp := range c.proposals {
		if tp.resolved || !strings.HasPrefix(id, prefix) {
			continue
		}
		match = id
		n++
	}
	return match, n == 1
}

// clearProposalsLocked drops all tracked proposals and stops their timers. Caller
// holds c.mu. Called on /vanish and scuttle: the room state is being reset.
func (c *Client) clearProposalsLocked() {
	for id, tp := range c.proposals {
		tp.stop()
		delete(c.proposals, id)
	}
}
