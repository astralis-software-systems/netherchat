// Package client is the UI-agnostic Netherchat client core. It owns the
// connection, the key-exchange state machine, and all encryption/decryption,
// exposing a stream of high-level Events. Both the Bubble Tea TUI and the
// integration test drive it through the same surface, which keeps the protocol
// logic in one tested place and out of the UI.
//
// This package lives under tui/ so it is permitted to import the client crypto
// package; the server tree cannot.
package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

const (
	readLimitBytes = 1 << 20
	writeTimeout   = 10 * time.Second
)

type memberInfo struct {
	name    string
	signPub ed25519.PublicKey
	kxPub   [32]byte
}

// Client is a single connection to a Netherchat server, scoped to one room.
type Client struct {
	id          *crypto.Identity
	room        string
	name        string
	url         string
	inviteToken string

	ctx    context.Context
	cancel context.CancelFunc
	ws     *websocket.Conn

	events chan Event
	sendCh chan protocol.Envelope
	done   chan struct{}

	mu      sync.Mutex
	selfID  string
	members map[string]memberInfo
	rk      *crypto.RoomKey // current room key; nil until established
	pending []pendingFrame  // E2E frames received before the key arrived
}

// pendingFrame is an encrypted frame (message or exec request/result) buffered
// until the room key is established, then replayed.
type pendingFrame struct {
	op protocol.Op
	m  protocol.Message
}

// DefaultIdentityPath returns the per-user identity file location. Exposed here
// so the cmd layer (which cannot import the internal crypto package) can resolve
// it without touching crypto types.
func DefaultIdentityPath() (string, error) { return crypto.DefaultIdentityPath() }

// New creates a client, resolving the operator's identity via the BYO-key
// cascade (crypto.ResolveIdentity): an explicit identityPath, else ssh-agent,
// else ~/.ssh/id_ed25519(_sk), else the generated key. This is the constructor
// the cmd layer uses, since it never exposes a crypto type across the internal
// boundary.
func New(serverURL, room, name, identityPath string) (*Client, error) {
	id, err := crypto.ResolveIdentity(identityPath)
	if err != nil {
		return nil, fmt.Errorf("load identity: %w", err)
	}
	return NewWithIdentity(serverURL, room, name, id)
}

// NewWithIdentity creates a client from an explicit identity. serverURL may use
// http(s) or ws(s); the /ws path is appended if absent. Used by tests and any
// caller (under tui/) that manages identities directly.
func NewWithIdentity(serverURL, room, name string, id *crypto.Identity) (*Client, error) {
	u, err := wsURL(serverURL)
	if err != nil {
		return nil, err
	}
	return &Client{
		id:      id,
		room:    room,
		name:    name,
		url:     u,
		events:  make(chan Event, 256),
		sendCh:  make(chan protocol.Envelope, 64),
		done:    make(chan struct{}),
		members: make(map[string]memberInfo),
	}, nil
}

// Connect dials the server (using dialCtx for the dial timeout only), sends the
// Hello, and starts the read/write loops. The session lifetime is independent of
// dialCtx; it ends on Close or when the connection drops.
func (c *Client) Connect(dialCtx context.Context) error {
	conn, resp, err := websocket.Dial(dialCtx, c.url, nil)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return fmt.Errorf("dial %s: %w", c.url, err)
	}
	conn.SetReadLimit(readLimitBytes)
	c.ws = conn
	c.ctx, c.cancel = context.WithCancel(context.Background())

	go c.writeLoop()
	c.enqueue(protocol.OpHello, protocol.Hello{
		ProtocolVersion: protocol.Version,
		Room:            c.room,
		DisplayName:     c.name,
		IdentityKey:     c.id.SignPub,
		KXKey:           c.id.KXPub[:],
		InviteToken:     c.inviteToken,
	})
	go c.readLoop()
	return nil
}

// Send encrypts text under the current room key, transmits it, and emits a local
// echo. It errors if the room key is not yet established.
func (c *Client) Send(text string) error {
	if err := c.sealAndSend(protocol.OpMessage, []byte(text)); err != nil {
		return err
	}
	c.emit(EvMessage{FromID: c.SelfID(), FromName: c.name, Text: text, Self: true, Signed: true, At: time.Now()})
	return nil
}

// sealAndSend encrypts plaintext under the current room key, signs it, and sends
// it as the given opcode (a Message envelope). Used for chat messages and for the
// E2E-encrypted edge-exec request/result frames.
func (c *Client) sealAndSend(op protocol.Op, plaintext []byte) error {
	c.mu.Lock()
	rk := c.rk
	selfID := c.selfID
	c.mu.Unlock()
	if rk == nil {
		return errors.New("room key not established yet")
	}
	nonce, ct, sig, err := c.id.SealMessage(*rk, c.room, selfID, plaintext)
	if err != nil {
		return err
	}
	c.enqueue(op, protocol.Message{FromID: selfID, Epoch: rk.Epoch, Nonce: nonce, Ciphertext: ct, Sig: sig})
	return nil
}

// UseInviteToken sets the one-time invite token sent in Hello to join an
// invite-only room. Call before Connect.
func (c *Client) UseInviteToken(token string) { c.inviteToken = token }

// Vanish rotates the room key forward (HKDF ratchet, deleting the old key) and
// asks every other member to do the same and clear local history. Forward
// secrecy: messages from before the vanish can no longer be decrypted by anyone
// who discarded the prior key.
func (c *Client) Vanish() {
	c.ratchetForward()
	c.enqueue(protocol.OpControl, protocol.Control{Action: protocol.ActionVanish, ByName: c.name})
	c.emit(EvControl{Action: protocol.ActionVanish, ByName: c.name, Self: true})
}

// SetTTL broadcasts a client-side message display TTL (in seconds) for the room.
func (c *Client) SetTTL(seconds int) {
	c.enqueue(protocol.OpControl, protocol.Control{Action: protocol.ActionTTL, ByName: c.name, TTLSeconds: seconds})
	c.emit(EvControl{Action: protocol.ActionTTL, ByName: c.name, Self: true, TTLSeconds: seconds})
}

// RequestInvite asks the server to mint a one-time invite token for this room.
func (c *Client) RequestInvite() { c.enqueue(protocol.OpInviteRequest, protocol.InviteRequest{}) }

// BreakGlass asks the server to stand up an ephemeral, invite-only war room with
// a hard TTL and one-time invite links for each named person. The reply arrives
// as EvBreakGlass. The server clamps the TTL and caps the invitee count.
func (c *Client) BreakGlass(invitees []string, ttlSeconds int) {
	c.enqueue(protocol.OpBreakGlass, protocol.BreakGlass{Invitees: invitees, TTLSeconds: ttlSeconds})
}

// RequestExec sends an end-to-end-encrypted, signed exec request naming a runbook
// action for an agent to run, and emits a local echo. It returns the request id
// (to correlate the result), or an error if the room key is not yet established.
// The relay only ever sees ciphertext; it does not run anything.
func (c *Client) RequestExec(cmd string) (string, error) {
	id := newRequestID()
	body, _ := json.Marshal(protocol.ExecRequestBody{ID: id, Cmd: cmd})
	if err := c.sealAndSend(protocol.OpExecRequest, body); err != nil {
		return "", err
	}
	c.emit(EvExecRequest{
		ID: id, Cmd: cmd, FromID: c.SelfID(), FromName: c.name,
		FromFingerprint: c.Fingerprint(), Self: true, Signed: true, At: time.Now(),
	})
	return id, nil
}

// PostExecResult sends an end-to-end-encrypted, signed exec result. Used by
// `netherchat agent` after it runs (or denies) a command on its own host.
func (c *Client) PostExecResult(id, cmd string, allowed bool, exitCode int, output string) error {
	b, _ := json.Marshal(protocol.ExecResultBody{
		ID: id, Cmd: cmd, Allowed: allowed, ExitCode: exitCode, Output: output,
	})
	return c.sealAndSend(protocol.OpExecResult, b)
}

func newRequestID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// ratchetForward advances the room key by one epoch and zeroes the old one.
// Because the ratchet is a deterministic KDF, every member that applies it lands
// on the same next key without any key exchange.
func (c *Client) ratchetForward() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rk == nil {
		return
	}
	if next, err := c.rk.Ratchet(); err == nil {
		c.rk.Zero()
		c.rk = &next
	}
}

// Events returns the stream of client events. Consumers should also select on
// Done(), which closes after EvDisconnected.
func (c *Client) Events() <-chan Event { return c.events }

// Done is closed when the read loop exits (connection ended).
func (c *Client) Done() <-chan struct{} { return c.done }

// SelfID returns the server-assigned member ID (empty until connected).
func (c *Client) SelfID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.selfID
}

// Fingerprint returns this client's identity fingerprint (ssh-keygen format).
func (c *Client) Fingerprint() string { return c.id.Fingerprint() }

// Source returns where this client's identity came from (e.g. "ssh-agent",
// "~/.ssh/id_ed25519", "generated").
func (c *Client) Source() string { return c.id.Source }

// LookupMember returns the SSH fingerprint of the first connected member whose
// display name matches name (case-insensitive). Display names are cosmetic and
// not unique; /whois reports the fingerprint so identity is judged by key, not
// name.
func (c *Client) LookupMember(name string) (id, fingerprint string, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for mid, m := range c.members {
		if strings.EqualFold(m.name, name) {
			return mid, crypto.Fingerprint(m.signPub), true
		}
	}
	return "", "", false
}

// SAS computes the 5-word Short Authentication String for the pairwise session
// with the member named handle, from the shared room key and both parties' public
// keys (§1.2). It returns the words and the peer's fingerprint. ok is false if no
// such member is present or the room key is not established yet.
func (c *Client) SAS(handle string) (words []string, fingerprint string, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rk == nil {
		return nil, "", false
	}
	for _, m := range c.members {
		if strings.EqualFold(m.name, handle) {
			words = crypto.SASWords(c.id.SignPub, c.id.KXPub, m.signPub, m.kxPub, c.rk.Key)
			return words, crypto.Fingerprint(m.signPub), true
		}
	}
	return nil, "", false
}

// Close ends the session and closes the connection.
func (c *Client) Close() error {
	if c.cancel != nil {
		c.cancel()
	}
	if c.ws != nil {
		return c.ws.Close(websocket.StatusNormalClosure, "bye")
	}
	return nil
}

// --- internal ---

func (c *Client) readLoop() {
	defer close(c.done)
	for {
		var env protocol.Envelope
		if err := wsjson.Read(c.ctx, c.ws, &env); err != nil {
			c.emit(EvDisconnected{Err: err})
			return
		}
		c.handle(env)
	}
}

func (c *Client) writeLoop() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case env := <-c.sendCh:
			wctx, cancel := context.WithTimeout(c.ctx, writeTimeout)
			err := wsjson.Write(wctx, c.ws, env)
			cancel()
			if err != nil {
				c.cancel()
				return
			}
		}
	}
}

func (c *Client) handle(env protocol.Envelope) {
	switch env.Type {
	case protocol.OpWelcome:
		c.onWelcome(env)
	case protocol.OpMemberJoined:
		c.onMemberJoined(env)
	case protocol.OpMemberLeft:
		c.onMemberLeft(env)
	case protocol.OpKeyRequest:
		c.onKeyRequest(env)
	case protocol.OpKeyDeliver:
		c.onKeyDeliver(env)
	case protocol.OpMessage, protocol.OpExecRequest, protocol.OpExecResult:
		var m protocol.Message
		if err := env.Decode(&m); err == nil {
			c.handleEncrypted(env.Type, m)
		}
	case protocol.OpServerMessage:
		c.onServerMessage(env)
	case protocol.OpControl:
		c.onControl(env)
	case protocol.OpInviteResult:
		c.onInviteResult(env)
	case protocol.OpBreakGlassResult:
		c.onBreakGlassResult(env)
	case protocol.OpError:
		var e protocol.Error
		if err := env.Decode(&e); err == nil {
			c.emit(EvError{Err: fmt.Errorf("server error [%s]: %s", e.Code, e.Message)})
		}
	}
}

func (c *Client) onWelcome(env protocol.Envelope) {
	var w protocol.Welcome
	if err := env.Decode(&w); err != nil {
		c.emit(EvError{Err: fmt.Errorf("bad welcome: %w", err)})
		return
	}

	c.mu.Lock()
	c.selfID = w.YourID
	members := make([]ConnMember, 0, len(w.Members))
	for _, m := range w.Members {
		c.addMemberLocked(m)
		members = append(members, ConnMember{ID: m.ID, Name: m.DisplayName, Fingerprint: fingerprintOf(m.IdentityKey)})
	}
	var minted *crypto.RoomKey
	if w.YouAreFirst {
		if rk, err := crypto.NewRoomKey(0); err == nil {
			c.rk = &rk
			minted = &rk
		}
	}
	c.mu.Unlock()

	c.emit(EvConnected{
		SelfID:      w.YourID,
		YouAreFirst: w.YouAreFirst,
		Members:     members,
		InviteOnly:  w.Policy.InviteOnly,
		Webhook:     w.Policy.Webhook,
		TTLSeconds:  w.Policy.TTLSeconds,
	})
	if minted != nil {
		c.emit(EvKeyReady{Epoch: minted.Epoch})
		c.replayPending()
	}
}

func (c *Client) onMemberJoined(env protocol.Envelope) {
	var mj protocol.MemberJoined
	if err := env.Decode(&mj); err != nil {
		return
	}
	c.mu.Lock()
	c.addMemberLocked(mj.Member)
	c.mu.Unlock()
	c.emit(EvMemberJoined{ID: mj.Member.ID, Name: mj.Member.DisplayName, Fingerprint: fingerprintOf(mj.Member.IdentityKey)})
}

// fingerprintOf returns the ssh fingerprint of an identity key from the wire, or
// "" if the key is malformed.
func fingerprintOf(identityKey []byte) string {
	signPub, err := crypto.ToSignPub(identityKey)
	if err != nil {
		return ""
	}
	return crypto.Fingerprint(signPub)
}

func (c *Client) onMemberLeft(env protocol.Envelope) {
	var ml protocol.MemberLeft
	if err := env.Decode(&ml); err != nil {
		return
	}
	c.mu.Lock()
	name := c.members[ml.ID].name
	delete(c.members, ml.ID)
	c.mu.Unlock()
	c.emit(EvMemberLeft{ID: ml.ID, Name: name})
}

// onKeyRequest: the server designated us to wrap the current room key for a
// newly joined member.
func (c *Client) onKeyRequest(env protocol.Envelope) {
	var kr protocol.KeyRequest
	if err := env.Decode(&kr); err != nil {
		return
	}
	c.mu.Lock()
	rk := c.rk
	c.mu.Unlock()
	if rk == nil {
		c.emit(EvError{Err: errors.New("asked to distribute room key but we don't hold one")})
		return
	}
	recipientKX, err := crypto.ToKX(kr.ForMember.KXKey)
	if err != nil {
		c.emit(EvError{Err: fmt.Errorf("bad recipient key: %w", err)})
		return
	}
	nonce, wrapped, err := c.id.WrapRoomKey(*rk, recipientKX)
	if err != nil {
		c.emit(EvError{Err: fmt.Errorf("wrap room key: %w", err)})
		return
	}
	c.enqueue(protocol.OpKeyDeliver, protocol.KeyDeliver{
		ToID:       kr.ForMember.ID,
		Epoch:      rk.Epoch,
		Nonce:      nonce,
		WrappedKey: wrapped,
	})
}

// onKeyDeliver: an existing member wrapped the room key for us.
func (c *Client) onKeyDeliver(env protocol.Envelope) {
	var kd protocol.KeyDeliver
	if err := env.Decode(&kd); err != nil {
		return
	}
	c.mu.Lock()
	sender, ok := c.members[kd.FromID]
	c.mu.Unlock()
	if !ok {
		c.emit(EvError{Err: fmt.Errorf("room key from unknown member %s", kd.FromID)})
		return
	}
	rk, err := c.id.UnwrapRoomKey(kd.Epoch, kd.Nonce, kd.WrappedKey, sender.kxPub)
	if err != nil {
		c.emit(EvError{Err: fmt.Errorf("unwrap room key: %w", err)})
		return
	}
	c.mu.Lock()
	c.rk = &rk
	c.mu.Unlock()

	c.emit(EvKeyReady{Epoch: rk.Epoch})
	c.replayPending()
}

// handleEncrypted decrypts and verifies an E2E frame (chat message or exec
// request/result) and emits the corresponding event. Frames that arrive before
// the room key is established are buffered and replayed by replayPending.
func (c *Client) handleEncrypted(op protocol.Op, m protocol.Message) {
	c.mu.Lock()
	rk := c.rk
	if rk == nil {
		c.pending = append(c.pending, pendingFrame{op: op, m: m})
		c.mu.Unlock()
		return
	}
	sender, known := c.members[m.FromID]
	c.mu.Unlock()

	if !known {
		c.emit(EvError{Err: fmt.Errorf("%s from unknown member %s", op, m.FromID)})
		return
	}
	pt, signed, err := crypto.OpenMessage(*rk, sender.signPub, c.room, m.FromID, m.Epoch, m.Nonce, m.Ciphertext, m.Sig)
	if err != nil {
		if errors.Is(err, crypto.ErrBadSignature) {
			// Reject: the body is never surfaced (§3.3).
			c.emit(EvError{Err: fmt.Errorf("message from @%s failed signature verification", sender.name)})
		} else {
			c.emit(EvError{Err: fmt.Errorf("decrypt from %s: %w", sender.name, err)})
		}
		return
	}
	now := time.Now()
	fpr := crypto.Fingerprint(sender.signPub)
	switch op {
	case protocol.OpMessage:
		c.emit(EvMessage{FromID: m.FromID, FromName: sender.name, Text: string(pt), Signed: signed, At: now})
	case protocol.OpExecRequest:
		var body protocol.ExecRequestBody
		if json.Unmarshal(pt, &body) == nil {
			c.emit(EvExecRequest{
				ID: body.ID, Cmd: body.Cmd, FromID: m.FromID, FromName: sender.name,
				FromFingerprint: fpr, Signed: signed, At: now,
			})
		}
	case protocol.OpExecResult:
		var body protocol.ExecResultBody
		if json.Unmarshal(pt, &body) == nil {
			c.emit(EvExecResult{
				ID: body.ID, Cmd: body.Cmd, Allowed: body.Allowed, ExitCode: body.ExitCode,
				Output: body.Output, FromName: sender.name, FromFingerprint: fpr, At: now,
			})
		}
	}
}

// replayPending decrypts and emits any frames buffered before the room key
// arrived. Called once the key is established.
func (c *Client) replayPending() {
	c.mu.Lock()
	pending := c.pending
	c.pending = nil
	c.mu.Unlock()
	for _, f := range pending {
		c.handleEncrypted(f.op, f.m)
	}
}

func (c *Client) onServerMessage(env protocol.Envelope) {
	var sm protocol.ServerMessage
	if err := env.Decode(&sm); err != nil {
		return
	}
	at := time.Now()
	if sm.At > 0 {
		at = time.Unix(sm.At, 0)
	}
	c.emit(EvServerMessage{Kind: sm.Kind, From: sm.From, Text: sm.Text, At: at})
}

func (c *Client) onControl(env protocol.Envelope) {
	var ctrl protocol.Control
	if err := env.Decode(&ctrl); err != nil {
		return
	}
	if ctrl.Action == protocol.ActionVanish {
		// Everyone advances the room key deterministically; no key exchange needed.
		c.ratchetForward()
	}
	c.emit(EvControl{Action: ctrl.Action, ByName: ctrl.ByName, TTLSeconds: ctrl.TTLSeconds})
}

func (c *Client) onInviteResult(env protocol.Envelope) {
	var r protocol.InviteResult
	if err := env.Decode(&r); err != nil {
		return
	}
	var exp time.Time
	if r.Expires > 0 {
		exp = time.Unix(r.Expires, 0)
	}
	c.emit(EvInvite{Room: r.Room, Token: r.Token, Expires: exp})
}

func (c *Client) onBreakGlassResult(env protocol.Envelope) {
	var r protocol.BreakGlassResult
	if err := env.Decode(&r); err != nil {
		return
	}
	var exp time.Time
	if r.Expires > 0 {
		exp = time.Unix(r.Expires, 0)
	}
	invites := make([]BreakGlassInvite, 0, len(r.Invites))
	for _, in := range r.Invites {
		invites = append(invites, BreakGlassInvite{Name: in.Name, Token: in.Token})
	}
	c.emit(EvBreakGlass{
		Room:       r.Room,
		TTLSeconds: r.TTLSeconds,
		Expires:    exp,
		HostToken:  r.HostToken,
		Invites:    invites,
	})
}

// addMemberLocked records a member; caller holds c.mu. Malformed keys are skipped.
func (c *Client) addMemberLocked(m protocol.Member) {
	signPub, err1 := crypto.ToSignPub(m.IdentityKey)
	kxPub, err2 := crypto.ToKX(m.KXKey)
	if err1 != nil || err2 != nil {
		return
	}
	c.members[m.ID] = memberInfo{name: m.DisplayName, signPub: signPub, kxPub: kxPub}
}

func (c *Client) enqueue(op protocol.Op, payload any) {
	env, err := protocol.Encode(op, payload)
	if err != nil {
		c.emit(EvError{Err: err})
		return
	}
	select {
	case c.sendCh <- env:
	case <-c.ctx.Done():
	}
}

func (c *Client) emit(ev Event) {
	select {
	case c.events <- ev:
	case <-c.ctx.Done():
	}
}

// wsURL normalizes a server URL to a ws(s) URL ending in /ws.
func wsURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	case "ws", "wss":
		// already fine
	default:
		return "", fmt.Errorf("unsupported URL scheme %q (use ws://, wss://, http://, or https://)", u.Scheme)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/ws"
	}
	return u.String(), nil
}
