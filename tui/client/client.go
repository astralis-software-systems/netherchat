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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
	"github.com/salehkreiner/netherchat/tui/record"
)

// writeTimeout bounds a single transport write (see RelayTransport.Send).
const writeTimeout = 10 * time.Second

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

	ctx       context.Context
	cancel    context.CancelFunc
	transport Transport              // relay (WebSocket) or direct (P2P TCP / loopback)
	dialOpts  *websocket.DialOptions // nil = direct; set by UseTorProxy for SOCKS5 (Tor)

	events chan Event
	sendCh chan protocol.Envelope
	done   chan struct{}

	mu      sync.Mutex
	selfID  string
	members map[string]memberInfo
	order   []string        // member ids oldest-first, INCLUDING self (for IC + quorum)
	rk      *crypto.RoomKey // current room key; nil until established
	pending []pendingFrame  // E2E frames received before the key arrived

	// Coordination state (§2.2), in memory, reset on /vanish. acks maps a
	// coordination tag to the set of identity fingerprints that have acked it
	// (one ack per identity per tag). ic is the current incident-commander.
	acks map[string]map[string]bool
	ic   icHolder

	// Sealed-record state (§1.4), in memory, reset on /vanish. chain is this
	// client's copy of the append-only record chain; lastMsg is the most recent
	// message (for /mark). The seal* fields hold an in-progress /seal collection
	// when we are the sealer; pendingSeal* remembers an incoming SEAL_REQUEST so a
	// later /seal can co-sign it.
	chain   *record.Chain
	lastMsg lastMessage

	sealing         bool                          // we initiated a seal and are collecting co-signatures
	sealHead        []byte                        // the chain head being sealed
	sealEntries     []record.Entry                // snapshot of the chain at seal time (so later appends don't drift)
	sealSigs        map[string][]byte             // fingerprint -> raw Ed25519 seal signature
	sealKeys        map[string][]byte             // fingerprint -> raw Ed25519 public key
	sealEndorse     map[string]record.Endorsement // fingerprint -> declared meaning (item 2); absent = bare co-signature
	sealTimer       *time.Timer                   // 30s collection window
	pendingSealHead []byte                        // head of the most recent incoming SEAL_REQUEST
	pendingSealName string                        // display name of who proposed it

	// lastSeal retains the most recently finalized seal so a verified co-signature
	// that arrives AFTER finalization is amended into the record instead of being
	// lost (§1.4 HYBRID fix). The eager finalize still fires (a solo sealer never
	// hangs); the racy completion denominator is thereby demoted to a "when to do
	// the first write" hint, and late acks for this head re-persist. Held under
	// c.mu; superseded when a new seal round begins and cleared on /vanish
	// (clearSealLocked). See onSealAck / finalizeSeal in record.go.
	lastSeal *sealSnapshot

	// Roster attestation (§1.4): the in-progress co-sign round when we are the
	// attester, plus the membership snapshot it finalizes from.
	roster     *cosignRound
	rosterMeta rosterMeta

	// Scuttle receipt (§1.5). firstEpoch is the first epoch we held a key, for the
	// receipt's epoch_range.first. receiptRound/Core/Hash hold an in-progress
	// co-sign round (the /scuttle-now initiator); receiptOnDone fires after it
	// finalizes (to trigger the burn); receiptDone latches so a room produces at
	// most one receipt from this client.
	firstEpoch    uint64
	firstEpochSet bool
	receiptRound  *cosignRound
	receiptCore   attest.ReceiptCore
	receiptHash   []byte
	receiptOnDone func()
	receiptDone   bool

	// Ephemeral artifact relay (§2.3). sends holds our outgoing transfers (so
	// FileAck/FileAbort can be routed to the streaming goroutine); recvs holds the
	// transfers we are receiving and reassembling in memory. maxFileBytes is the
	// client-side size cap (a blind relay cannot enforce it).
	fileMu       sync.Mutex
	sends        map[string]*sendState
	recvs        map[string]*recvState
	maxFileBytes int64

	// Two-Person Rule (§1.3): every privileged-action request this client observes
	// (whether we initiated it or not), keyed by request_id, so the quorum gate is
	// enforced identically on every client from the frames it sees. See action.go.
	actions map[string]*trackedAction

	// actionQuorum is this client's OWN copy of the [action.<name>] quorum policy
	// (§1.3), installed once before Connect via SetActionQuorum. The gate on a
	// conditional privileged action (scuttle / break-glass) consults THIS — never a
	// caller-supplied value — so no caller (TUI, headless, relay-less) can weaken or
	// bypass it. This mirrors the artifact gate's core-side, self-counted enforcement.
	// A nil/absent entry means single-actor (quorum 1). See gateAction in action.go.
	actionQuorum map[string]int

	// Agent-Decision Attestation (NC-W1): every artifact proposal this client
	// observes, keyed by proposal_id. Approvals are counted identically on every
	// client (the proposer is never an approver); on quorum the approver that
	// completes it writes the signed "artifact" record entry. See artifact.go.
	proposals map[string]*trackedProposal

	// artifactProofs retains the identity-bound approval signatures collected for each
	// artifact (keyed by proposal_id), so that whichever member later seals can persist
	// them into SealedRecord.ArtifactApprovals — making two-person approval
	// offline-provable (GAP-1/GAP-2). Captured by EVERY observing client (any member
	// may seal), not just the writer; reset on /vanish. See artifact.go.
	artifactProofs map[string][]capturedApproval

	// Status Beacon (§1.2): the per-room token authorizing beacon writes over REST
	// (PUT/DELETE /beacon/<room>). Read-only beacon GETs need no token. See beacon.go.
	beaconToken string

	// Incident clock (A1), in memory only, reset on /vanish. clockStart is the start
	// time (zero = not started); clockStop the resolution time (zero = running);
	// clockNotesAdded latches that the timing notes were injected into a seal. See
	// clock.go.
	clockStart      time.Time
	clockStop       time.Time
	clockNotesAdded bool
}

// sealTimeout bounds how long a sealer waits for co-signatures before finalizing
// with whatever it has collected (§1.4). A var, not a const, so white-box tests
// can shorten the 30s window to exercise the post-timeout amend path (mirrors
// actionRequestTTL). Production never reassigns it.
var sealTimeout = 30 * time.Second

// sealSnapshot is a finalized seal retained so a late verified co-signature can be
// amended into it rather than lost (§1.4 HYBRID). It holds exactly what re-assembly
// needs: the sealed head, the entry snapshot, and the collected
// signature/key/endorsement maps. Artifact-approval proofs are re-attached from
// c.artifactProofs at assembly time (assembleSealedLocked), so they are not
// duplicated here. endorse is always non-nil (seeded at seal initiation), so the
// amend path writes to it without a nil check.
type sealSnapshot struct {
	head    []byte
	entries []record.Entry
	sigs    map[string][]byte
	keys    map[string][]byte
	endorse map[string]record.Endorsement
}

// lastMessage is the most recent chat message seen in the room, remembered so
// /mark can promote it into the record.
type lastMessage struct {
	from string
	text string
}

// icHolder identifies the room's current incident commander. The first member of
// a room implicitly holds it; /handoff transfers it explicitly.
type icHolder struct {
	id, name, fpr string
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

// Identify resolves the BYO-key identity at identityPath (empty = the cascade:
// ssh-agent → ~/.ssh/id_ed25519(_sk) → generated) and returns its fingerprint
// and source WITHOUT opening a connection. Used by `netherchat whoami`.
func Identify(identityPath string) (fingerprint, source string, err error) {
	id, err := crypto.ResolveIdentity(identityPath)
	if err != nil {
		return "", "", err
	}
	return id.Fingerprint(), id.Source, nil
}

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

// NewEphemeral creates a client with a freshly generated, throwaway identity —
// no key file, no ssh-agent. It exists so callers outside the tui/ tree (which
// Go's internal-package rule bars from importing the crypto package) can still
// stand up self-contained clients: `netherchat doctor --paranoid` uses it for the
// canary peers of its blindness self-test (§3.1).
func NewEphemeral(serverURL, room, name string) (*Client, error) {
	id, err := crypto.GenerateIdentity()
	if err != nil {
		return nil, fmt.Errorf("generate identity: %w", err)
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
		acks:    make(map[string]map[string]bool),
		chain:   record.NewChain(),

		sends:          make(map[string]*sendState),
		recvs:          make(map[string]*recvState),
		maxFileBytes:   protocol.DefaultMaxFileBytes,
		actions:        make(map[string]*trackedAction),
		proposals:      make(map[string]*trackedProposal),
		artifactProofs: make(map[string][]capturedApproval),
	}, nil
}

// Connect dials the relay server over WebSocket (using dialCtx for the dial
// timeout only), then runs the protocol over it. The session lifetime is
// independent of dialCtx; it ends on Close or when the connection drops.
func (c *Client) Connect(dialCtx context.Context) error {
	rt, err := DialRelay(dialCtx, c.url, c.dialOpts)
	if err != nil {
		return fmt.Errorf("dial %s: %w", c.url, err)
	}
	return c.ConnectWith(rt)
}

// ConnectWith runs the protocol over an already-established transport. This is the
// Sneakernet entry point (§1.1): a direct peer-to-peer transport (or the host's
// in-process loopback to its own coordinator) is handed in here, and from this
// point on the client behaves identically to the relay path — same Hello/Welcome
// handshake, same encryption, same commands. The transport is now owned by the
// client and is closed by Close.
func (c *Client) ConnectWith(t Transport) error {
	recvCh, err := t.Recv()
	if err != nil {
		return err
	}
	c.transport = t
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
	go c.readLoop(recvCh)
	return nil
}

// Transport returns the transport this client is running over (nil before
// Connect). The TUI reads it to render the mode indicator (relay vs direct) and
// /whoami; /peers inspects it when it is a direct transport.
func (c *Client) Transport() Transport { return c.transport }

// Send encrypts text under the current room key, transmits it, and emits a local
// echo. It errors if the room key is not yet established.
func (c *Client) Send(text string) error {
	if err := c.sealAndSend(protocol.OpMessage, []byte(text)); err != nil {
		return err
	}
	c.rememberMessage(c.name, text)
	c.emit(EvMessage{FromID: c.SelfID(), FromName: c.name, Text: text, Self: true, Signed: true, At: time.Now()})
	return nil
}

// rememberMessage records the most recent message so /mark can promote it.
func (c *Client) rememberMessage(from, text string) {
	c.mu.Lock()
	c.lastMsg = lastMessage{from: from, text: text}
	c.mu.Unlock()
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

// SetActionQuorum installs this client's [action.<name>] quorum policy (§1.3),
// consulted by the client-owned gate on scuttle / break-glass (gateAction). Call
// before Connect, like UseInviteToken; the map is copied. An absent entry means
// single-actor (quorum 1). The caller resolves the policy from netherchat.toml (the
// cmd layer's actionQuorums). Owning the policy here — rather than taking it as a
// per-call parameter — is what makes the conditional (quorum > 1) gate unbypassable.
func (c *Client) SetActionQuorum(policy map[string]int) {
	if len(policy) == 0 {
		c.actionQuorum = nil
		return
	}
	m := make(map[string]int, len(policy))
	for k, v := range policy {
		m[k] = v
	}
	c.actionQuorum = m
}

// quorumFor returns the client-owned quorum for an action: the configured value when
// present (including 0, which disables it), else 1 (single-actor). This is the gate's
// authority — deliberately not a per-call argument, so no caller can weaken it.
func (c *Client) quorumFor(action string) int {
	if q, ok := c.actionQuorum[action]; ok {
		return q
	}
	return 1
}

// canGateQuorum reports whether this client can actually run a quorum-approval round
// for a privileged action: true over the relay (which fans OpActionRequest/Approval
// out to the whole room), false over a relay-less/direct transport, where there is no
// approval path a second party could answer through (§3.2 — the relay-less REPL has no
// approve command, so a gated request could never be met). A nil transport (not yet
// connected) is treated as not gateable. gateAction uses this to fail closed —
// refusing — rather than burning unilaterally when a quorum >= 2 was configured.
func (c *Client) canGateQuorum() bool {
	t := c.transport
	return t != nil && t.PeerID() == ""
}

// Vanish rotates the room key forward (HKDF ratchet, deleting the old key) and
// asks every other member to do the same and clear local history. Forward
// secrecy: messages from before the vanish can no longer be decrypted by anyone
// who discarded the prior key.
func (c *Client) Vanish() {
	c.ratchetForward()
	c.mu.Lock()
	c.resetCoordinationLocked()
	c.mu.Unlock()
	c.enqueue(protocol.OpControl, protocol.Control{Action: protocol.ActionVanish, ByName: c.name})
	c.emit(EvControl{Action: protocol.ActionVanish, ByName: c.name, Self: true})
}

// SetTTL broadcasts a client-side message display TTL (in seconds) for the room.
func (c *Client) SetTTL(seconds int) {
	c.enqueue(protocol.OpControl, protocol.Control{Action: protocol.ActionTTL, ByName: c.name, TTLSeconds: seconds})
	c.emit(EvControl{Action: protocol.ActionTTL, ByName: c.name, Self: true, TTLSeconds: seconds})
}

// ScuttleNow scuttles the room immediately (§1.6 — /scuttle now), subject to this
// client's own two-person rule (§1.3). When [action.scuttle] quorum > 1 the burn is
// GATED: it opens a signed ActionRequest and fires only once a second authorized
// member independently approves (via the shared RequestAction engine); an unapproved
// request expires after 60s with the room intact. quorum <= 1 (or unset) keeps the
// instant, single-actor emergency behavior; quorum 0 disables the command; a relay-
// less quorum >= 2 fails closed (see gateAction). The gate lives HERE, in the core, so
// EVERY caller — TUI, headless, relay-less — inherits it, and the raw burn
// (scuttleBurn) is unexported and unreachable un-gated. Returns an error to surface
// "disabled" / "refused" / "could not open the request"; a nil error means the burn
// fired (quorum <= 1) or an approval gate was opened (quorum > 1).
func (c *Client) ScuttleNow() error {
	return c.gateAction(protocol.ActionScuttleAction, scuttleNowParams(c.room), c.scuttleBurn)
}

// scuttleBurn performs the actual destruction with NO quorum check — the raw
// primitive the gate runs once quorum is met (and directly at quorum <= 1). Before
// asking the server to burn the room it collects co-signatures for the scuttle
// receipt (§1.5) while the room is still alive — the server tears a scuttled room down
// within a short grace window, so there is no time to collect them afterward. When the
// receipt finalizes we trigger the actual (server-orchestrated) burn; the ActionScuttle
// broadcast then comes back to everyone and the ratchet happens uniformly via
// onControl. If we cannot produce a receipt (no key yet), we just burn.
func (c *Client) scuttleBurn() {
	triggerBurn := func() {
		c.enqueue(protocol.OpControl, protocol.Control{Action: protocol.ActionScuttle, ByName: c.name})
	}
	if !c.startReceiptRound(protocol.ScuttleManual, triggerBurn) {
		triggerBurn()
	}
}

// ScuttleArm arms a visible countdown (§1.6 — /scuttle arm <dur>) after which the
// room auto-scuttles, subject to the same client-owned two-person rule as ScuttleNow.
// The gate is on the request to ARM; the countdown's own elapse burns server-side and
// is not re-gated (it is a server-originated scuttle by then, D4). Returns an error on
// disabled / refused / could-not-open, exactly like ScuttleNow.
func (c *Client) ScuttleArm(seconds int) error {
	return c.gateAction(protocol.ActionScuttleAction, scuttleArmParams(c.room, seconds), func() { c.armCountdown(seconds) })
}

// armCountdown is the raw arm primitive (no quorum check): it asks the server to
// broadcast the countdown notice to all participants and own the authoritative timer.
func (c *Client) armCountdown(seconds int) {
	c.enqueue(protocol.OpControl, protocol.Control{Action: protocol.ActionScuttleArm, ByName: c.name, TTLSeconds: seconds})
}

// Epoch returns the current room-key epoch (0 before the key is established). It
// advances by one on every /vanish or scuttle ratchet, so a test can confirm the
// dead-man's-switch ratchet ran.
func (c *Client) Epoch() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rk == nil {
		return 0
	}
	return c.rk.Epoch
}

// RequestInvite asks the server to mint a one-time invite token for this room.
func (c *Client) RequestInvite() { c.enqueue(protocol.OpInviteRequest, protocol.InviteRequest{}) }

// BreakGlass stands up an ephemeral, invite-only war room (§1.3), subject to the same
// client-owned two-person rule as scuttle: [action.break_glass] quorum > 1 gates the
// stand-up behind a second authorized approval; quorum <= 1 creates it immediately;
// quorum 0 disables it. break-glass is a relay-only feature, so the relay-less fail-
// closed branch is inert here in practice. Returns an error on disabled / refused /
// could-not-open; the war room's reply arrives as EvBreakGlass.
func (c *Client) BreakGlass(invitees []string, ttlSeconds int) error {
	return c.gateAction(protocol.ActionBreakGlass, breakGlassParams(invitees, ttlSeconds), func() { c.breakGlassSend(invitees, ttlSeconds) })
}

// breakGlassSend is the raw break-glass primitive (no quorum check): it asks the
// server to stand up the war room. The server clamps the TTL and caps the invitee
// count; the reply arrives as EvBreakGlass.
func (c *Client) breakGlassSend(invitees []string, ttlSeconds int) {
	c.enqueue(protocol.OpBreakGlass, protocol.BreakGlass{Invitees: invitees, TTLSeconds: ttlSeconds})
}

// Ack sends an end-to-end-encrypted, signed coordination ack for tag, records
// our own ack locally, and emits a local echo carrying the running quorum. An
// ack is a typed coordination primitive (one ack per identity per tag), NOT a
// reaction. It errors if the room key is not yet established.
func (c *Client) Ack(tag string) error {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return errors.New("ack needs a tag")
	}
	body, _ := json.Marshal(protocol.AckBody{Tag: tag})
	if err := c.sealAndSend(protocol.OpAck, body); err != nil {
		return err
	}
	quorum := c.recordAck(tag, c.Fingerprint())
	c.emit(EvAck{Tag: tag, Actor: c.name, Fpr: c.Fingerprint(), Quorum: quorum, Self: true, At: time.Now()})
	return nil
}

// Handoff transfers the incident-commander token to the member named handle. It
// sends a signed, E2E handoff frame, updates local IC state, and emits a local
// echo. It errors if no such member is present or the room key is not ready.
func (c *Client) Handoff(handle string) error {
	handle = strings.TrimPrefix(strings.TrimSpace(handle), "@")
	toID, toFpr, ok := c.LookupMember(handle)
	if !ok {
		return fmt.Errorf("no member named @%s in this room", handle)
	}
	body, _ := json.Marshal(protocol.HandoffBody{ToID: toID, ToName: handle})
	if err := c.sealAndSend(protocol.OpHandoff, body); err != nil {
		return err
	}
	c.setIC(toID, handle, toFpr)
	c.emit(EvHandoff{
		FromName: c.name, FromFpr: c.Fingerprint(),
		ToName: handle, ToFpr: toFpr, Self: true, At: time.Now(),
	})
	return nil
}

// AckState returns the current per-tag quorum counts as tag -> "<acked>/<members>".
func (c *Client) AckState() map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]string, len(c.acks))
	for tag := range c.acks {
		out[tag] = c.quorumLocked(tag)
	}
	return out
}

// ICHolder returns the display name and fingerprint of the current incident
// commander, and whether that is us. ok is false before the holder is known.
func (c *Client) ICHolder() (name, fpr string, isSelf, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ic.id == "" {
		return "", "", false, false
	}
	return c.ic.name, c.ic.fpr, c.ic.id == c.selfID, true
}

// recordAck records that fpr acked tag and returns the resulting quorum string.
func (c *Client) recordAck(tag, fpr string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	set := c.acks[tag]
	if set == nil {
		set = make(map[string]bool)
		c.acks[tag] = set
	}
	set[fpr] = true
	return c.quorumLocked(tag)
}

// quorumLocked formats "<distinct acks>/<current members>" for tag. The
// denominator is the number of members in this client's current view (including
// self); caller holds c.mu.
func (c *Client) quorumLocked(tag string) string {
	total := len(c.order)
	if total == 0 {
		total = 1 // we are always at least one member
	}
	return strconv.Itoa(len(c.acks[tag])) + "/" + strconv.Itoa(total)
}

// setIC sets the current incident commander.
func (c *Client) setIC(id, name, fpr string) {
	c.mu.Lock()
	c.ic = icHolder{id: id, name: name, fpr: fpr}
	c.mu.Unlock()
}

// resetCoordinationLocked clears ack quorum state and recomputes the IC to the
// oldest current member — the initial condition. It also drops the unsealed
// record chain and any in-progress seal: like everything else in the room, an
// unsealed chain is deliberately not kept past a /vanish (§1.4 — seal before you
// vanish, or it is gone). Called on /vanish (key rotation resets coordination
// state, §2.2). Caller holds c.mu.
func (c *Client) resetCoordinationLocked() {
	c.acks = make(map[string]map[string]bool)
	c.ic = c.oldestHolderLocked()
	c.chain.Reset()
	c.lastMsg = lastMessage{}
	c.clearSealLocked()
	c.clearRosterLocked()
	c.clearReceiptLocked()
	c.clearActionsLocked()
	c.clearProposalsLocked()
	c.clearClockLocked()
}

// oldestHolderLocked returns the IC holder implied by join order: the oldest
// current member. Caller holds c.mu.
func (c *Client) oldestHolderLocked() icHolder {
	if len(c.order) == 0 {
		return icHolder{}
	}
	id := c.order[0]
	if id == c.selfID {
		return icHolder{id: id, name: c.name, fpr: c.id.Fingerprint()}
	}
	m := c.members[id]
	return icHolder{id: id, name: m.name, fpr: crypto.Fingerprint(m.signPub)}
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

// Members returns this client's current view of the room membership (every member
// it knows about except itself), each with its display name and identity
// fingerprint. /peers renders it; it is transport-agnostic, so it works the same in
// relay and Sneakernet (direct) mode.
func (c *Client) Members() []ConnMember {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]ConnMember, 0, len(c.members))
	for id, m := range c.members {
		out = append(out, ConnMember{ID: id, Name: m.name, Fingerprint: crypto.Fingerprint(m.signPub)})
	}
	return out
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

// Close ends the session and closes the transport.
func (c *Client) Close() error {
	if c.cancel != nil {
		c.cancel()
	}
	if c.transport != nil {
		return c.transport.Close()
	}
	return nil
}

// --- internal ---

func (c *Client) readLoop(recvCh <-chan []byte) {
	defer close(c.done)
	for b := range recvCh {
		var env protocol.Envelope
		if err := json.Unmarshal(b, &env); err != nil {
			continue // a frame we cannot even parse is dropped, not fatal
		}
		c.handle(env)
	}
	// The Recv channel closed: the connection ended. Surface the underlying reason
	// when the transport tracked it, else a generic close.
	err := error(nil)
	if et, ok := c.transport.(errTransport); ok {
		err = et.lastErr()
	}
	if err == nil {
		err = errors.New("connection closed")
	}
	c.emit(EvDisconnected{Err: err})
}

func (c *Client) writeLoop() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case env := <-c.sendCh:
			b, err := json.Marshal(env)
			if err != nil {
				continue // an envelope we cannot marshal is a programming bug; skip it
			}
			if err := c.transport.Send(b); err != nil {
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
	case protocol.OpMessage, protocol.OpExecRequest, protocol.OpExecResult, protocol.OpAck, protocol.OpHandoff,
		protocol.OpRecordEntry, protocol.OpSealRequest, protocol.OpSealAck,
		protocol.OpRosterRequest, protocol.OpRosterAck,
		protocol.OpScuttleReceiptRequest, protocol.OpScuttleReceiptAck,
		protocol.OpActionRequest, protocol.OpActionApproval, protocol.OpActionVeto,
		protocol.OpArtifactProposal, protocol.OpArtifactApproval, protocol.OpArtifactRejection,
		protocol.OpStreamUpdate, protocol.OpStreamEnd:
		var m protocol.Message
		if err := env.Decode(&m); err == nil {
			c.handleEncrypted(env.Type, m)
		}
	case protocol.OpFileOffer:
		var fo protocol.FileOffer
		if err := env.Decode(&fo); err == nil {
			c.onFileOffer(fo)
		}
	case protocol.OpFileChunk:
		var fc protocol.FileChunk
		if err := env.Decode(&fc); err == nil {
			c.onFileChunk(fc)
		}
	case protocol.OpFileAck:
		var fa protocol.FileAck
		if err := env.Decode(&fa); err == nil {
			c.onFileAck(fa)
		}
	case protocol.OpFileAbort:
		var fa protocol.FileAbort
		if err := env.Decode(&fa); err == nil {
			c.onFileAbort(fa)
		}
	case protocol.OpRouteFired:
		c.onRouteFired(env)
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
	// Welcome lists existing members oldest-first; we joined last. Recording the
	// order (with self appended) lets us name the oldest member as the initial
	// incident commander and size the ack quorum denominator.
	c.order = c.order[:0]
	for _, m := range w.Members {
		c.addMemberLocked(m)
		c.order = append(c.order, m.ID)
		members = append(members, ConnMember{ID: m.ID, Name: m.DisplayName, Fingerprint: fingerprintOf(m.IdentityKey)})
	}
	c.order = append(c.order, w.YourID)
	c.ic = c.oldestHolderLocked() // first member of the room implicitly holds IC
	var minted *crypto.RoomKey
	if w.YouAreFirst {
		if rk, err := crypto.NewRoomKey(0); err == nil {
			c.rk = &rk
			minted = &rk
			c.noteFirstEpochLocked(rk.Epoch)
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
	c.order = append(c.order, mj.Member.ID)
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
	for i, id := range c.order {
		if id == ml.ID {
			c.order = append(c.order[:i], c.order[i+1:]...)
			break
		}
	}
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
	c.noteFirstEpochLocked(rk.Epoch)
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
		// Incident-clock markers (A1) ride as ordinary E2E messages; recognize them
		// to sync the clock and surface a typed event instead of a chat line.
		if c.recognizeClock(sender.name, fpr, string(pt), now) {
			return
		}
		c.rememberMessage(sender.name, string(pt))
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
	case protocol.OpAck:
		var body protocol.AckBody
		if json.Unmarshal(pt, &body) == nil && body.Tag != "" {
			quorum := c.recordAck(body.Tag, fpr)
			// Carry the original frame signature and the bytes it covers so the
			// Two-Way Bridge (§1.6) can forward verifiable provenance.
			signBytes := protocol.SigningBytes(c.room, m.FromID, m.Epoch, m.Nonce, m.Ciphertext)
			c.emit(EvAck{
				Tag: body.Tag, Actor: sender.name, Fpr: fpr, Quorum: quorum, At: now,
				Sig: m.Sig, SignBytes: signBytes, Raw: append([]byte(nil), pt...),
			})
		}
	case protocol.OpHandoff:
		var body protocol.HandoffBody
		if json.Unmarshal(pt, &body) == nil && body.ToID != "" {
			toName, toFpr := c.resolveTarget(body.ToID, body.ToName)
			c.setIC(body.ToID, toName, toFpr)
			c.emit(EvHandoff{FromName: sender.name, FromFpr: fpr, ToName: toName, ToFpr: toFpr, At: now})
		}
	case protocol.OpRecordEntry:
		var e record.Entry
		if json.Unmarshal(pt, &e) == nil {
			// Pass the frame signature and the bytes it covers so the Two-Way
			// Bridge (§1.6) can forward verifiable provenance for decision/action.
			signBytes := protocol.SigningBytes(c.room, m.FromID, m.Epoch, m.Nonce, m.Ciphertext)
			c.onRecordEntry(e, m.Sig, signBytes, pt)
		}
	case protocol.OpSealRequest:
		var body protocol.SealRequestBody
		if json.Unmarshal(pt, &body) == nil {
			c.onSealRequest(sender.name, body.HeadHash)
		}
	case protocol.OpSealAck:
		var body protocol.SealAckBody
		if json.Unmarshal(pt, &body) == nil {
			c.onSealAck(m.FromID, sender.name, sender.signPub, body.HeadHash, body.Sig, body.Meaning, body.SignerName, body.SignedAt)
		}
	case protocol.OpRosterRequest:
		var body protocol.RosterRequestBody
		if json.Unmarshal(pt, &body) == nil {
			c.onRosterRequest(sender.name, body.SetHash, body.Epoch)
		}
	case protocol.OpRosterAck:
		var body protocol.RosterAckBody
		if json.Unmarshal(pt, &body) == nil {
			c.onRosterAck(sender.name, sender.signPub, body.SetHash, body.Sig)
		}
	case protocol.OpScuttleReceiptRequest:
		var body protocol.ScuttleReceiptRequestBody
		if json.Unmarshal(pt, &body) == nil {
			c.onScuttleReceiptRequest(sender.name, body.RoomID, body.ReceiptHash)
		}
	case protocol.OpScuttleReceiptAck:
		var body protocol.ScuttleReceiptAckBody
		if json.Unmarshal(pt, &body) == nil {
			c.onScuttleReceiptAck(sender.name, sender.signPub, body.ReceiptHash, body.Sig)
		}
	case protocol.OpActionRequest:
		var body protocol.ActionRequestBody
		if json.Unmarshal(pt, &body) == nil {
			c.onActionRequest(sender.name, fpr, body)
		}
	case protocol.OpActionApproval:
		var body protocol.ActionApprovalBody
		if json.Unmarshal(pt, &body) == nil {
			c.onActionApproval(sender.name, sender.signPub, body)
		}
	case protocol.OpActionVeto:
		var body protocol.ActionVetoBody
		if json.Unmarshal(pt, &body) == nil {
			c.onActionVeto(sender.name, fpr, body)
		}
	case protocol.OpArtifactProposal:
		var body protocol.ArtifactProposalBody
		if json.Unmarshal(pt, &body) == nil {
			c.onArtifactProposal(sender.name, fpr, body)
		}
	case protocol.OpArtifactApproval:
		var body protocol.ArtifactApprovalBody
		if json.Unmarshal(pt, &body) == nil {
			c.onArtifactApproval(sender.name, sender.signPub, body)
		}
	case protocol.OpArtifactRejection:
		var body protocol.ArtifactRejectionBody
		if json.Unmarshal(pt, &body) == nil {
			c.onArtifactRejection(sender.name, fpr, body)
		}
	case protocol.OpStreamUpdate:
		var body protocol.StreamUpdateBody
		if json.Unmarshal(pt, &body) == nil && body.StreamID != "" {
			c.emit(EvStreamUpdate{
				StreamID: body.StreamID, Name: body.Name, From: sender.name, Fpr: fpr,
				Lines: body.Lines, Seq: body.Seq, At: now,
			})
		}
	case protocol.OpStreamEnd:
		var body protocol.StreamEndBody
		if json.Unmarshal(pt, &body) == nil && body.StreamID != "" {
			c.emit(EvStreamEnd{StreamID: body.StreamID, Reason: body.Reason, From: sender.name})
		}
	}
}

// resolveTarget resolves a member id to a display name and fingerprint from the
// directory (or self), falling back to fallbackName when the member is unknown.
func (c *Client) resolveTarget(id, fallbackName string) (name, fpr string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if id == c.selfID {
		return c.name, c.id.Fingerprint()
	}
	if m, ok := c.members[id]; ok {
		name = m.name
		if name == "" {
			name = fallbackName
		}
		return name, crypto.Fingerprint(m.signPub)
	}
	return fallbackName, ""
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
	if ctrl.Action == protocol.ActionScuttle {
		// A scuttle is destruction: emit a signed receipt — proof there is no record
		// (§1.5) — BEFORE the key is zeroized. If we initiated /scuttle now we
		// already produced one (with co-signatures collected while the room was
		// live); for a server-triggered scuttle (idle / owner_loss / armed) or a
		// peer's manual scuttle, we self-sign one here. Each present client may write
		// its own receipt — that is expected, and each is independently verifiable.
		c.writeSelfReceiptIfNeeded(ctrl.Reason)
	}
	if ctrl.Action == protocol.ActionVanish || ctrl.Action == protocol.ActionScuttle {
		// Both /vanish and the dead-man's switch (§1.6) advance the room key
		// deterministically and destroy the old one — forward secrecy with no key
		// exchange — and reset coordination state (§2.2). A scuttle additionally
		// means the room is gone; the UI renders the attestation off this event.
		c.ratchetForward()
		c.mu.Lock()
		c.resetCoordinationLocked()
		c.mu.Unlock()
	}
	c.emit(EvControl{Action: ctrl.Action, ByName: ctrl.ByName, TTLSeconds: ctrl.TTLSeconds, Reason: ctrl.Reason})
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

func (c *Client) onRouteFired(env protocol.Envelope) {
	var rf protocol.RouteFired
	if err := env.Decode(&rf); err != nil {
		return
	}
	at := time.Now()
	if rf.At > 0 {
		at = time.Unix(rf.At, 0)
	}
	c.emit(EvRouteFired{
		Room:        rf.Room,
		TriggerRule: rf.TriggerRule,
		Invitees:    rf.Invitees,
		TTLSeconds:  rf.TTLSeconds,
		At:          at,
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
