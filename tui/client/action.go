package client

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
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

// This file holds the client-side Two-Person Rule machinery (§1.3): a privileged
// action (scuttle / break-glass / a signed runbook) can require N-of-M independent
// Ed25519 approvals before it fires. The gate is enforced CLIENT-SIDE over a
// request hash — the relay routes ActionRequest/Approval/Veto as opaque
// ciphertext and can neither read the action nor bypass the gate.
//
// Counting convention (matches the demo's "1/2" pending state and "2/2 executes"):
// the initiator's signed request is endorser #1, and the action fires once the
// number of DISTINCT endorsers — the requester plus quorum-1 approvers — reaches
// `quorum`. So a single actor can never execute a quorum>=2 action: it requires at
// least one OTHER authorized member's independent signature.
//
// Every client tracks every request it observes (not just its own) and reaches the
// quorum threshold independently from the frames it sees, so the gate — and the
// structured tail events — are derived cryptographically on each client rather
// than asserted by any one of them. Only the initiator additionally PERFORMS the
// action (its trackedAction carries the onApprove callback).

// actionRequestTTL bounds how long a privileged-action request waits for quorum
// before it is discarded (§1.3). It is a var (not a const) only so tests can
// shorten it; operationally it is the spec's 60s.
var actionRequestTTL = 60 * time.Second

// trackedAction is the in-memory lifecycle of one privileged-action request, held
// by every client that observes it. All access is under Client.mu.
type trackedAction struct {
	req       protocol.ActionRequestBody
	fromName  string          // requester display name (for events)
	approvers map[string]bool // distinct approver fingerprints (NEVER the requester)
	approved  bool            // (approver side) we have already sent our approval
	initiator bool            // we created this request — only we perform the action
	onApprove func()          // initiator-only: runs once when quorum is reached
	timer     *time.Timer     // expiry timer
	resolved  bool            // executed | vetoed | expired — latched, then dropped
}

// endorsements is the running count shown as the numerator: the requester (always
// 1) plus the distinct approvers collected so far.
func (ta *trackedAction) endorsements() int { return 1 + len(ta.approvers) }

// addApprover records a distinct, valid approver. The requester is never counted
// (the initiator cannot approve their own request); duplicates by fingerprint do
// not increment. Returns whether the approver was newly counted.
func (ta *trackedAction) addApprover(fpr string) bool {
	if ta.resolved || fpr == ta.req.RequesterFpr || ta.approvers[fpr] {
		return false
	}
	ta.approvers[fpr] = true
	return true
}

func (ta *trackedAction) stop() {
	if ta.timer != nil {
		ta.timer.Stop()
		ta.timer = nil
	}
}

// PendingAction is a snapshot of one pending request, for /pending and the TUI's
// pending-approvals panel.
type PendingAction struct {
	RequestID     string
	Action        string
	Params        string
	RequesterName string
	RequesterFpr  string
	Count         int // current endorsements (1 + distinct approvers)
	Needed        int // quorum
	ExpiresUnix   int64
	Initiator     bool // we initiated it
	Approved      bool // we have endorsed it (initiator, or already approved)
}

// actionParamsHash is the hex SHA-256 of the canonical params string. Both the
// initiator (binding the request) and an approver (independently verifying the
// hash matches the displayed params) compute it the same way.
func actionParamsHash(params string) string {
	h := sha256.Sum256([]byte(params))
	return hex.EncodeToString(h[:])
}

// RequestAction initiates a quorum-gated privileged action (§1.3). It sends a
// signed ActionRequest naming the action and a canonical, human-readable params
// string, then collects approvals; when `quorum` distinct endorsers (the requester
// plus quorum-1 approvers) back it, onApprove runs exactly once — that is where the
// caller performs the actual action (scuttle, break-glass, run the runbook). It
// returns the request id. quorum must be >= 2 (quorum 1 is single-actor: the caller
// should perform the action directly without a request).
func (c *Client) RequestAction(action, params string, quorum int, onApprove func()) (string, error) {
	if quorum < 2 {
		return "", errors.New("RequestAction requires quorum >= 2")
	}
	c.mu.Lock()
	ready := c.rk != nil
	c.mu.Unlock()
	if !ready {
		return "", errors.New("room key not established yet")
	}

	requestID := newRequestID() // 16 hex chars
	body := protocol.ActionRequestBody{
		RequestID:    requestID,
		Action:       action,
		ParamsHash:   actionParamsHash(params),
		Params:       params,
		RequesterFpr: c.id.Fingerprint(),
		Room:         c.room,
		QuorumNeeded: quorum,
		ExpiresUnix:  time.Now().Add(actionRequestTTL).Unix(),
		Nonce:        newRequestID(), // independent random hex; bound into every approval
	}
	ta := &trackedAction{req: body, fromName: c.name, approvers: map[string]bool{}, initiator: true, onApprove: onApprove}

	c.mu.Lock()
	c.armActionTimerLocked(ta)
	c.actions[requestID] = ta
	c.mu.Unlock()

	b, _ := json.Marshal(body)
	if err := c.sealAndSend(protocol.OpActionRequest, b); err != nil {
		c.mu.Lock()
		if x := c.actions[requestID]; x != nil {
			x.stop()
			delete(c.actions, requestID)
		}
		c.mu.Unlock()
		return "", err
	}
	c.emit(EvActionRequest{
		RequestID: requestID, Action: action, Params: params, ParamsHash: body.ParamsHash,
		RequesterName: c.name, RequesterFpr: c.id.Fingerprint(),
		QuorumNeeded: quorum, ExpiresUnix: body.ExpiresUnix, Self: true, At: time.Now(),
	})
	return requestID, nil
}

// ApproveAction signs and sends an approval for a pending request, declaring the
// default "approved" meaning (item 2). See ApproveActionAs to declare a different
// meaning (e.g. record.MeaningReviewed).
func (c *Client) ApproveAction(requestID string) error {
	return c.ApproveActionAs(requestID, record.MeaningApproved)
}

// ApproveActionAs signs and sends an approval carrying a declared
// electronic-signature meaning, then accounts our own endorsement locally (the
// relay does not echo our own frame back to us). The meaning, our printed name,
// and a UTC timestamp are bound into the approval signature (item 2), so they
// cannot be altered in flight. requestID may be a unique prefix of the full id.
// It refuses to approve our own request — the initiator is endorser #1 and cannot
// also approve. Meaning is opaque/extensible; the record.Meaning* values are the
// defaults.
func (c *Client) ApproveActionAs(requestID, meaning string) error {
	c.mu.Lock()
	id, ok := c.resolveActionIDLocked(requestID)
	if !ok {
		c.mu.Unlock()
		return fmt.Errorf("no pending action request matching %q", requestID)
	}
	ta := c.actions[id]
	switch {
	case ta.resolved:
		c.mu.Unlock()
		return errors.New("that request has already been resolved")
	case ta.req.RequesterFpr == c.id.Fingerprint():
		c.mu.Unlock()
		return errors.New("you cannot approve your own request — the requester is already endorser #1")
	case ta.approved:
		c.mu.Unlock()
		return errors.New("you have already approved this request")
	case actionParamsHash(ta.req.Params) != ta.req.ParamsHash:
		// The request is internally inconsistent: refuse to sign something whose
		// displayed params do not match the hash we would be endorsing.
		c.mu.Unlock()
		return errors.New("refusing to approve: the request's params_hash does not match its params")
	}
	req := ta.req
	ready := c.rk != nil
	c.mu.Unlock()
	if !ready {
		return errors.New("room key not established yet")
	}

	fpr := c.id.Fingerprint()
	// A declared meaning is signed over the v2 preimage (meaning/name/time bound in);
	// an empty meaning is the bare v1 approval, byte-for-byte as before.
	ab := protocol.ActionApprovalBody{RequestID: req.RequestID, ParamsHash: req.ParamsHash, ApproverFpr: fpr}
	var sig []byte
	var err error
	if meaning != "" {
		signedAt := time.Now().UTC().Format(time.RFC3339)
		sig, err = c.id.Sign(protocol.ActionApprovalSigningBytesV2(req.RequestID, req.ParamsHash, fpr, req.Nonce, meaning, c.name, signedAt))
		ab.Meaning, ab.Name, ab.SignedAt = meaning, c.name, signedAt
	} else {
		sig, err = c.id.Sign(protocol.ActionApprovalSigningBytes(req.RequestID, req.ParamsHash, fpr, req.Nonce))
	}
	if err != nil {
		return err
	}
	ab.Sig = sig
	body, _ := json.Marshal(ab)
	if err := c.sealAndSend(protocol.OpActionApproval, body); err != nil {
		return err
	}

	// Account our own approval locally and react to it exactly as if it had arrived
	// over the wire from a peer.
	c.mu.Lock()
	ta = c.actions[req.RequestID]
	if ta == nil || ta.resolved {
		c.mu.Unlock()
		return nil
	}
	ta.approved = true
	c.mu.Unlock()
	c.countApproval(req.RequestID, c.name, fpr, meaning, true)
	return nil
}

// VetoAction cancels a pending request immediately and tells the room. Any member
// may veto; the action does not fire. requestID may be a unique prefix.
func (c *Client) VetoAction(requestID, reason string) error {
	c.mu.Lock()
	id, ok := c.resolveActionIDLocked(requestID)
	if !ok {
		c.mu.Unlock()
		return fmt.Errorf("no pending action request matching %q", requestID)
	}
	ta := c.actions[id]
	if ta.resolved {
		c.mu.Unlock()
		return errors.New("that request has already been resolved")
	}
	action := ta.req.Action
	ta.resolved = true
	ta.stop()
	delete(c.actions, id)
	ready := c.rk != nil
	c.mu.Unlock()
	if !ready {
		return errors.New("room key not established yet")
	}

	body, _ := json.Marshal(protocol.ActionVetoBody{RequestID: id, VetoerFpr: c.id.Fingerprint(), Reason: reason})
	if err := c.sealAndSend(protocol.OpActionVeto, body); err != nil {
		return err
	}
	c.emit(EvActionVetoed{RequestID: id, Action: action, VetoerName: c.name, VetoerFpr: c.id.Fingerprint(), Reason: reason, Self: true, At: time.Now()})
	return nil
}

// PendingActions returns a snapshot of unresolved requests for /pending and the
// TUI panel, sorted by request id for stable display.
func (c *Client) PendingActions() []PendingAction {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]PendingAction, 0, len(c.actions))
	for _, ta := range c.actions {
		if ta.resolved {
			continue
		}
		out = append(out, PendingAction{
			RequestID: ta.req.RequestID, Action: ta.req.Action, Params: ta.req.Params,
			RequesterName: ta.fromName, RequesterFpr: ta.req.RequesterFpr,
			Count: ta.endorsements(), Needed: ta.req.QuorumNeeded, ExpiresUnix: ta.req.ExpiresUnix,
			Initiator: ta.initiator, Approved: ta.approved || ta.initiator,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RequestID < out[j].RequestID })
	return out
}

// --- inbound frame handlers -------------------------------------------------

// onActionRequest records a request from another member and surfaces it. The
// requester_fpr must match the signed Message's sender, so the request cannot be
// attributed to anyone but its actual author.
func (c *Client) onActionRequest(senderName, senderFpr string, body protocol.ActionRequestBody) {
	if body.RequestID == "" || body.QuorumNeeded < 1 {
		return
	}
	if body.RequesterFpr != senderFpr {
		c.emit(EvError{Err: fmt.Errorf("ignoring action request from %s: requester_fpr does not match the signer", senderName)})
		return
	}
	if body.ExpiresUnix > 0 && time.Now().Unix() >= body.ExpiresUnix {
		return // already expired in flight
	}
	c.mu.Lock()
	if _, exists := c.actions[body.RequestID]; exists {
		c.mu.Unlock()
		return
	}
	ta := &trackedAction{req: body, fromName: senderName, approvers: map[string]bool{}}
	c.armActionTimerLocked(ta)
	c.actions[body.RequestID] = ta
	c.mu.Unlock()

	c.emit(EvActionRequest{
		RequestID: body.RequestID, Action: body.Action, Params: body.Params, ParamsHash: body.ParamsHash,
		RequesterName: senderName, RequesterFpr: body.RequesterFpr,
		QuorumNeeded: body.QuorumNeeded, ExpiresUnix: body.ExpiresUnix, At: time.Now(),
	})
}

// onActionApproval verifies and counts an approval that arrived from a peer.
func (c *Client) onActionApproval(senderName string, senderPub ed25519.PublicKey, body protocol.ActionApprovalBody) {
	c.mu.Lock()
	ta := c.actions[body.RequestID]
	if ta == nil || ta.resolved {
		c.mu.Unlock()
		return // unknown / already executed or vetoed → silently discard
	}
	req := ta.req
	c.mu.Unlock()

	// params_hash must match the exact action this approval claims to endorse.
	if body.ParamsHash != req.ParamsHash {
		c.emit(EvError{Err: fmt.Errorf("rejecting approval from %s: params_hash does not match the request", senderName)})
		return
	}
	signerFpr := crypto.Fingerprint(senderPub)
	if body.ApproverFpr != signerFpr {
		c.emit(EvError{Err: fmt.Errorf("rejecting approval from %s: approver_fpr does not match the signer", senderName)})
		return
	}
	// A meaning-bearing approval signed the v2 preimage (its meaning/name/time are
	// reproduced from the body and bound into what we verify, so they cannot be
	// altered in flight); a bare approval signed v1.
	preimage := protocol.ActionApprovalSigningBytes(req.RequestID, req.ParamsHash, body.ApproverFpr, req.Nonce)
	if body.Meaning != "" {
		preimage = protocol.ActionApprovalSigningBytesV2(req.RequestID, req.ParamsHash, body.ApproverFpr, req.Nonce, body.Meaning, body.Name, body.SignedAt)
	}
	if len(senderPub) != ed25519.PublicKeySize || !ed25519.Verify(senderPub, preimage, body.Sig) {
		c.emit(EvError{Err: fmt.Errorf("rejecting approval from %s: invalid signature", senderName)})
		return
	}
	c.countApproval(body.RequestID, senderName, signerFpr, body.Meaning, false)
}

// countApproval applies one verified approval to a tracked request — used both for
// approvals that arrive over the wire and for our own (locally accounted) one — and
// drives the executed/quorum transition. It must NOT be called with c.mu held.
func (c *Client) countApproval(requestID, approverName, approverFpr, meaning string, self bool) {
	c.mu.Lock()
	ta := c.actions[requestID]
	if ta == nil || ta.resolved {
		c.mu.Unlock()
		return
	}
	if !ta.addApprover(approverFpr) {
		c.mu.Unlock()
		return // requester, duplicate, or already resolved
	}
	endorsements := ta.endorsements()
	action := ta.req.Action
	needed := ta.req.QuorumNeeded
	reached := endorsements >= needed
	var onApprove func()
	var initiator bool
	requesterName, requesterFpr := ta.fromName, ta.req.RequesterFpr
	if reached {
		ta.resolved = true
		ta.stop()
		onApprove, initiator = ta.onApprove, ta.initiator
		delete(c.actions, requestID)
	}
	c.mu.Unlock()

	c.emit(EvActionApproval{
		RequestID: requestID, Action: action, ApproverName: approverName, ApproverFpr: approverFpr,
		Meaning: meaning, Count: endorsements, Needed: needed, Self: self, At: time.Now(),
	})
	if !reached {
		return
	}
	// Perform the action BEFORE announcing it. onApprove runs on this goroutine
	// while a consumer (TUI, test) may be blocked waiting for EvActionExecuted on
	// the event channel; emitting first lets that consumer observe "executed" and
	// read state onApprove is still writing — a data race (caught by `go test
	// -race`). Doing onApprove first means the channel send below happens-after the
	// callback's writes, so a consumer that sees EvActionExecuted is guaranteed the
	// action's side effects are already complete.
	if onApprove != nil { // only the initiator performs the action
		onApprove()
	}
	c.emit(EvActionExecuted{
		RequestID: requestID, Action: action, RequesterName: requesterName, RequesterFpr: requesterFpr,
		Quorum: needed, Self: initiator, At: time.Now(),
	})
}

// onActionVeto cancels a pending request seen on the wire.
func (c *Client) onActionVeto(senderName, senderFpr string, body protocol.ActionVetoBody) {
	c.mu.Lock()
	ta := c.actions[body.RequestID]
	if ta == nil || ta.resolved {
		c.mu.Unlock()
		return
	}
	ta.resolved = true
	ta.stop()
	action := ta.req.Action
	delete(c.actions, body.RequestID)
	c.mu.Unlock()
	c.emit(EvActionVetoed{RequestID: body.RequestID, Action: action, VetoerName: senderName, VetoerFpr: senderFpr, Reason: body.Reason, At: time.Now()})
}

// expireAction fires from the request's timer: if it never reached quorum it is
// discarded and reported.
func (c *Client) expireAction(requestID string) {
	c.mu.Lock()
	ta := c.actions[requestID]
	if ta == nil || ta.resolved {
		c.mu.Unlock()
		return
	}
	ta.resolved = true
	ta.stop()
	endorsements, action, needed := ta.endorsements(), ta.req.Action, ta.req.QuorumNeeded
	delete(c.actions, requestID)
	c.mu.Unlock()
	c.emit(EvActionExpired{RequestID: requestID, Action: action, ApprovalsReceived: endorsements, QuorumNeeded: needed, At: time.Now()})
}

// armActionTimerLocked starts the expiry timer for a tracked request, honoring its
// expires_unix so observers expire in step with the initiator. Caller holds c.mu.
func (c *Client) armActionTimerLocked(ta *trackedAction) {
	d := actionRequestTTL
	if ta.req.ExpiresUnix > 0 {
		if rem := time.Until(time.Unix(ta.req.ExpiresUnix, 0)); rem > 0 {
			d = rem
		}
	}
	id := ta.req.RequestID
	ta.timer = time.AfterFunc(d, func() { c.expireAction(id) })
}

// resolveActionIDLocked resolves a full id or a unique prefix to a tracked,
// unresolved request id. Caller holds c.mu.
func (c *Client) resolveActionIDLocked(prefix string) (string, bool) {
	if ta, ok := c.actions[prefix]; ok && !ta.resolved {
		return prefix, true
	}
	var match string
	n := 0
	for id, ta := range c.actions {
		if ta.resolved || !strings.HasPrefix(id, prefix) {
			continue
		}
		match = id
		n++
	}
	return match, n == 1
}

// clearActionsLocked drops all tracked requests and stops their timers. Caller
// holds c.mu. Called on /vanish and scuttle: the room state is being reset, so any
// in-flight request is moot.
func (c *Client) clearActionsLocked() {
	for id, ta := range c.actions {
		ta.stop()
		delete(c.actions, id)
	}
}
