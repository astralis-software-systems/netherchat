// Package ws is the WebSocket transport for the Netherchat server. It accepts
// connections, performs the Hello/Welcome handshake, registers members with the
// hub, and relays opaque envelopes. It does NOT import the client crypto package
// (and Go's internal-package rule would forbid it): every payload it forwards is
// ciphertext or a sealed key blob it cannot open.
package ws

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/server/internal/ephemeral"
	"github.com/salehkreiner/netherchat/server/internal/hub"
	"github.com/salehkreiner/netherchat/server/internal/invite"
	"github.com/salehkreiner/netherchat/server/internal/scuttle"
	"github.com/salehkreiner/netherchat/server/internal/store"
	"golang.org/x/time/rate"
)

const (
	readLimitBytes = 1 << 20 // 1 MiB per message — generous for ciphertext + wrapped keys
	sendBuffer     = 64      // per-connection outbound queue depth
	writeTimeout   = 10 * time.Second
	inviteTTL      = 24 * time.Hour
)

// Server relays WebSocket connections through a hub.
type Server struct {
	hub       *hub.Hub
	cfg       config.Config
	invites   *invite.Store
	ephemeral *ephemeral.Registry
	scuttle   *scuttle.Manager
	transfers *transferTracker // per-room concurrent artifact-transfer limit (§2.3)
	store     store.Store      // optional history persistence; nil when disabled
	log       *slog.Logger

	// frameTap, when set, receives a copy of every raw inbound relay frame BEFORE
	// the relay decodes or processes it — the exact bytes that arrived over the
	// wire. It is nil in production (zero cost); `netherchat doctor --paranoid`
	// (§3.1) sets it to prove the relay sees only ciphertext. A tap can never grant
	// the relay the ability to read content; it only observes the same opaque bytes.
	frameTap func([]byte)
}

// SetFrameTap installs a diagnostic tap (see Server.frameTap). Call before serving.
func (s *Server) SetFrameTap(tap func([]byte)) { s.frameTap = tap }

// NewServer constructs a transport bound to the given hub, config, invite store,
// ephemeral-room registry, scuttle manager (dead-man's switch), and optional
// message store (nil to disable persistence).
func NewServer(h *hub.Hub, cfg config.Config, invites *invite.Store, eph *ephemeral.Registry, sc *scuttle.Manager, st store.Store, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		hub: h, cfg: cfg, invites: invites, ephemeral: eph, scuttle: sc,
		transfers: newTransferTracker(cfg.Limits.MaxConcurrentTransfers),
		store:     st, log: log,
	}
}

// HandleWS is the http.HandlerFunc for the WebSocket endpoint.
func (s *Server) HandleWS(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// TUI clients send no Origin header, so default same-origin enforcement
		// is fine for them. The v2 web client will get an explicit allowlist via
		// config; we do not blanket-allow cross-origin here.
	})
	if err != nil {
		s.log.Debug("websocket accept failed", "err", err)
		return
	}
	c.SetReadLimit(readLimitBytes)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	defer c.CloseNow()

	s.serve(ctx, c)
}

// serve runs the lifecycle of one connection.
func (s *Server) serve(ctx context.Context, c *websocket.Conn) {
	// 1. The first frame must be a Hello.
	var first protocol.Envelope
	if err := wsjson.Read(ctx, c, &first); err != nil {
		return
	}
	if first.Type != protocol.OpHello {
		_ = sendNow(ctx, c, protocol.OpError, protocol.Error{Code: "expected_hello", Message: "first frame must be hello"})
		return
	}
	var hello protocol.Hello
	if err := first.Decode(&hello); err != nil {
		_ = sendNow(ctx, c, protocol.OpError, protocol.Error{Code: "bad_hello", Message: "malformed hello"})
		return
	}
	if hello.ProtocolVersion < protocol.MinVersion || hello.ProtocolVersion > protocol.Version {
		_ = sendNow(ctx, c, protocol.OpError, protocol.Error{Code: "version_mismatch", Message: "unsupported protocol version"})
		return
	}
	if hello.Room == "" {
		_ = sendNow(ctx, c, protocol.OpError, protocol.Error{Code: "no_room", Message: "room is required"})
		return
	}

	// 2. Resolve the effective room policy. A dynamically-created break-glass war
	// room overrides static config: it is always invite-only, never exec/webhook,
	// and carries a hard remaining TTL.
	pol := s.roomPolicy(hello.Room)

	// Enforce invite-only policy before admitting the connection. The token is
	// one-time: redeeming it here consumes it.
	if pol.InviteOnly {
		// A valid one-time token always admits. Otherwise the first member into
		// an empty room bootstraps it (and can then /invite others); once the
		// room is established, newcomers need a token.
		redeemed := hello.InviteToken != "" && s.invites.Redeem(hello.InviteToken, hello.Room)
		if !redeemed && !s.hub.IsEmpty(hello.Room) {
			_ = sendNow(ctx, c, protocol.OpError, protocol.Error{Code: "invite_required", Message: "this room is invite-only; a valid invite token is required"})
			return
		}
	}

	// 3. Set up the connection's outbound pump.
	out := make(chan protocol.Envelope, sendBuffer)
	cn := &conn{ws: c, out: out, log: s.log}
	go cn.writePump(ctx)

	id := newID()
	member := &hub.Member{
		Info: protocol.Member{
			ID:          id,
			DisplayName: hello.DisplayName,
			IdentityKey: hello.IdentityKey,
			KXKey:       hello.KXKey,
		},
		Send:  cn.send,
		Close: func() { _ = c.Close(websocket.StatusNormalClosure, "closed by server") },
	}

	// 4. Join the room and complete the handshake.
	res := s.hub.Join(hello.Room, member)
	// The first joiner founds the room: start its dead-man's-switch janitor (§1.6)
	// and remember that THIS connection is the owner, so its departure can trigger
	// owner_loss_burn. Ownership is the founder, not "whoever is oldest now" — once
	// the founder is gone the room has already scuttled (or chose not to).
	iAmOwner := res.YouAreFirst
	if s.scuttle != nil && res.YouAreFirst {
		s.scuttle.Start(hello.Room)
	}
	cn.send(mustEncode(protocol.OpWelcome, protocol.Welcome{
		ProtocolVersion: protocol.Version,
		YourID:          id,
		Room:            hello.Room,
		Members:         res.Existing,
		YouAreFirst:     res.YouAreFirst,
		Policy: protocol.RoomPolicy{
			InviteOnly: pol.InviteOnly,
			Webhook:    pol.Webhook,
			TTLSeconds: pol.TTLSeconds,
		},
	}))
	// Replay recent history (ciphertext) to the newcomer. The client buffers
	// these until its room key arrives, then decrypts what the current key
	// covers. See store package docs for the (honest) limits.
	if s.store != nil {
		if hist, err := s.store.History(hello.Room, s.cfg.Persistence.History); err == nil {
			for _, env := range hist {
				cn.send(env)
			}
		}
	}
	s.hub.Broadcast(hello.Room, id, mustEncode(protocol.OpMemberJoined, protocol.MemberJoined{Member: member.Info}))
	if res.Distributor != nil {
		// Ask the oldest existing member to wrap the current room key for the newcomer.
		res.Distributor.Send(mustEncode(protocol.OpKeyRequest, protocol.KeyRequest{ForMember: member.Info}))
	}
	s.log.Info("member joined", "room", hello.Room, "id", id, "name", hello.DisplayName, "first", res.YouAreFirst)

	// 5. Relay loop, with a per-connection token-bucket rate limit on
	// user-originated content frames.
	limiter := rate.NewLimiter(rate.Limit(s.cfg.Limits.MessagesPerSecond), s.cfg.Limits.Burst)
	for {
		// Read the raw frame so the diagnostic tap (if any) sees the exact bytes on
		// the wire before any decoding — the basis of the doctor blindness proof.
		_, raw, err := c.Read(ctx)
		if err != nil {
			break
		}
		if s.frameTap != nil {
			s.frameTap(raw)
		}
		var env protocol.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			continue
		}
		if env.Type == protocol.OpMessage && !limiter.Allow() {
			cn.send(mustEncode(protocol.OpError, protocol.Error{Code: "rate_limited", Message: "slow down"}))
			continue
		}
		s.relay(hello.Room, id, env)
	}

	// 6. Departure.
	empty := s.hub.Leave(hello.Room, id)
	s.hub.Broadcast(hello.Room, id, mustEncode(protocol.OpMemberLeft, protocol.MemberLeft{ID: id}))
	// A sender that drops mid-transfer aborts its transfers so receivers stop
	// waiting and discard their buffers (§2.3).
	for _, tid := range s.transfers.abortBy(hello.Room, id) {
		s.hub.Broadcast(hello.Room, id, mustEncode(protocol.OpFileAbort, protocol.FileAbort{
			TransferID: tid, Reason: "sender disconnected",
		}))
	}
	s.log.Info("member left", "room", hello.Room, "id", id, "room_empty", empty)
	if s.scuttle != nil {
		switch {
		case empty:
			s.scuttle.Stop(hello.Room) // nothing left to watch
		case iAmOwner:
			s.scuttle.OwnerLeft(hello.Room) // founder gone, room non-empty → maybe burn
		}
	}
}

// relay forwards a client frame to its destination(s). The server stamps the
// authoritative sender ID so a client cannot spoof another member's identity in
// the routing layer (signature verification by recipients enforces the rest).
func (s *Server) relay(room, fromID string, env protocol.Envelope) {
	s.hub.Touch(room)

	switch env.Type {
	case protocol.OpMessage:
		var m protocol.Message
		if err := env.Decode(&m); err != nil {
			return
		}
		m.FromID = fromID
		out := mustEncode(protocol.OpMessage, m)
		s.hub.Broadcast(room, fromID, out)
		if s.store != nil {
			_ = s.store.Append(room, out)
		}

	case protocol.OpKeyDeliver:
		var kd protocol.KeyDeliver
		if err := env.Decode(&kd); err != nil {
			return
		}
		kd.FromID = fromID
		if !s.hub.SendTo(room, kd.ToID, mustEncode(protocol.OpKeyDeliver, kd)) {
			s.log.Debug("key_deliver target not found", "room", room, "to", kd.ToID)
		}

	case protocol.OpControl:
		// Control actions carry no secrets. Most (vanish, ttl) are pure relay; the
		// scuttle actions (§1.6) are orchestrated by the server because closing the
		// room is server-authoritative.
		var ctrl protocol.Control
		if err := env.Decode(&ctrl); err != nil {
			return
		}
		ctrl.By = fromID
		switch ctrl.Action {
		case protocol.ActionScuttle:
			// /scuttle now: a participant burns the room immediately. Scuttle itself
			// broadcasts the ActionScuttle notice (with reason) to everyone, so we do
			// not relay the request frame.
			s.hub.Scuttle(room, protocol.ScuttleManual)
		case protocol.ActionScuttleArm:
			// /scuttle arm <dur>: show the countdown to all participants now, and
			// schedule the burn. The countdown is informational; the server timer is
			// authoritative.
			s.hub.Broadcast(room, "", mustEncode(protocol.OpControl, ctrl))
			if s.scuttle != nil {
				s.scuttle.Arm(room, time.Duration(ctrl.TTLSeconds)*time.Second)
			}
		default:
			s.hub.Broadcast(room, fromID, mustEncode(protocol.OpControl, ctrl))
		}

	case protocol.OpInviteRequest:
		token, exp := s.invites.Generate(room, inviteTTL)
		var expUnix int64
		if !exp.IsZero() {
			expUnix = exp.Unix()
		}
		s.hub.SendTo(room, fromID, mustEncode(protocol.OpInviteResult, protocol.InviteResult{
			Room: room, Token: token, Expires: expUnix,
		}))

	case protocol.OpExecRequest, protocol.OpExecResult, protocol.OpAck, protocol.OpHandoff,
		protocol.OpRecordEntry, protocol.OpSealRequest, protocol.OpSealAck,
		protocol.OpRosterRequest, protocol.OpRosterAck,
		protocol.OpScuttleReceiptRequest, protocol.OpScuttleReceiptAck,
		protocol.OpActionRequest, protocol.OpActionApproval, protocol.OpActionVeto:
		// Edge exec, coordination primitives (ack/handoff), sealed-record frames
		// (record entries, seal requests/acks), roster-attestation frames (roster
		// requests/acks, §1.4), and Two-Person Rule frames (action request/approval/
		// veto, §1.3): the relay treats all of these exactly like chat messages —
		// opaque E2E envelopes (sealed under the room key, Ed25519-signed) it fans out
		// to the room verbatim. It never sees the command, the ack tag, the handoff
		// target, the recorded decision, the head being sealed, the membership set, or
		// the gated action and its parameters, and never runs, counts, chains, signs,
		// or gates anything; the record chain, quorum, IC token, roster attestation,
		// and the privileged-action quorum are all computed client-side from the
		// signed payloads — the relay cannot bypass or be coerced to bypass the gate
		// (FEATURE_ROADMAP_FREE.md §0.1, §1.4, §2.2; FEATURE_ROADMAP_V2.md §1.3, §1.4).
		var m protocol.Message
		if err := env.Decode(&m); err != nil {
			return
		}
		m.FromID = fromID
		s.hub.Broadcast(room, fromID, mustEncode(env.Type, m))

	case protocol.OpFileOffer:
		// Ephemeral artifact relay (§2.3). The relay fans the offer out like a
		// message; it sees only the content-free transfer id (to bound concurrency)
		// and an opaque sealed Message — never the filename, size, or hash.
		var fo protocol.FileOffer
		if err := env.Decode(&fo); err != nil {
			return
		}
		if !s.transfers.tryStart(room, fo.TransferID, fromID) {
			s.hub.SendTo(room, fromID, mustEncode(protocol.OpError, protocol.Error{
				Code: "transfer_limit", Message: "too many concurrent transfers in this room",
			}))
			return
		}
		fo.Sealed.FromID = fromID // stamp the authenticated sender on the sealed message
		s.hub.Broadcast(room, fromID, mustEncode(protocol.OpFileOffer, fo))

	case protocol.OpFileChunk:
		// Forward and forget — the relay never buffers a chunk. It enforces the
		// per-chunk size (bounding per-frame memory) and frees the transfer's slot
		// when it forwards the final chunk. The chunk itself is opaque ciphertext.
		var fc protocol.FileChunk
		if err := env.Decode(&fc); err != nil {
			return
		}
		if len(fc.Data) > protocol.MaxChunkWire {
			s.hub.SendTo(room, fromID, mustEncode(protocol.OpError, protocol.Error{
				Code: "chunk_too_large", Message: "artifact chunk exceeds the size limit",
			}))
			return
		}
		s.hub.Broadcast(room, fromID, mustEncode(protocol.OpFileChunk, fc))
		if fc.Total > 0 && fc.Index == fc.Total-1 {
			s.transfers.finish(room, fc.TransferID) // streaming done; free the slot
		}

	case protocol.OpFileAck:
		var fa protocol.FileAck
		if err := env.Decode(&fa); err != nil {
			return
		}
		s.hub.Broadcast(room, fromID, mustEncode(protocol.OpFileAck, fa))

	case protocol.OpFileAbort:
		var fa protocol.FileAbort
		if err := env.Decode(&fa); err != nil {
			return
		}
		s.hub.Broadcast(room, fromID, mustEncode(protocol.OpFileAbort, fa))
		s.transfers.finish(room, fa.TransferID)

	case protocol.OpBreakGlass:
		var bg protocol.BreakGlass
		if err := env.Decode(&bg); err != nil {
			return
		}
		s.handleBreakGlass(room, fromID, bg)

	default:
		s.log.Debug("ignoring unknown opcode", "type", env.Type)
	}
}

// handleBreakGlass stands up an ephemeral, invite-only war room with a hard TTL
// and mints one-time tokens: one per named invitee, plus a host token for the
// creator so they never lose the bootstrap slot to an invitee who clicks first.
// The result is routed back to the requesting connection; the creator then joins
// the new room. The room and all its tokens expire together at the deadline.
func (s *Server) handleBreakGlass(fromRoom, fromID string, bg protocol.BreakGlass) {
	ttl := ephemeral.ClampTTL(time.Duration(bg.TTLSeconds) * time.Second)
	room := s.ephemeral.Create(ttl, fromID)

	// Tokens live exactly as long as the room.
	hostToken, _ := s.invites.Generate(room.Name, ttl)
	invitees := bg.Invitees
	if len(invitees) > ephemeral.MaxInvitees {
		invitees = invitees[:ephemeral.MaxInvitees]
	}
	invites := make([]protocol.BreakGlassInvite, 0, len(invitees))
	for _, name := range invitees {
		token, _ := s.invites.Generate(room.Name, ttl)
		invites = append(invites, protocol.BreakGlassInvite{Name: name, Token: token})
	}

	s.log.Info("break-glass war room created", "room", room.Name, "by", fromID,
		"invitees", len(invites), "ttl", ttl.String())

	s.hub.SendTo(fromRoom, fromID, mustEncode(protocol.OpBreakGlassResult, protocol.BreakGlassResult{
		Room:       room.Name,
		TTLSeconds: int(ttl.Seconds()),
		Expires:    room.Deadline.Unix(),
		HostToken:  hostToken,
		Invites:    invites,
	}))
}

// effectivePolicy is the room policy actually enforced for a connection, after
// overlaying any ephemeral (break-glass) room on top of static config.
type effectivePolicy struct {
	InviteOnly bool
	Webhook    bool
	TTLSeconds int
}

// roomPolicy resolves the effective policy for a room. Ephemeral war rooms are
// always invite-only with a hard remaining TTL and no webhook surface; all other
// rooms use their static netherchat.toml policy.
func (s *Server) roomPolicy(room string) effectivePolicy {
	cfg := s.cfg.Room(room)
	pol := effectivePolicy{
		InviteOnly: cfg.InviteOnly,
		Webhook:    cfg.Webhook,
		TTLSeconds: int(cfg.TTL.Std().Seconds()),
	}
	if s.ephemeral != nil {
		if er, ok := s.ephemeral.Get(room); ok {
			pol.InviteOnly = true
			pol.Webhook = false
			pol.TTLSeconds = 0
			if rem := int(time.Until(er.Deadline).Seconds()); rem > 0 {
				pol.TTLSeconds = rem
			}
		}
	}
	return pol
}

// conn owns the write side of a single WebSocket. All writes go through the
// single writePump goroutine, so the underlying connection is never written
// concurrently.
type conn struct {
	ws  *websocket.Conn
	out chan protocol.Envelope
	log *slog.Logger
}

// send enqueues an envelope without blocking. If the outbound buffer is full the
// consumer is too slow; we drop the frame and log it rather than stalling the
// whole hub. (Slow-consumer disconnection is a post-M1 refinement.)
func (cn *conn) send(env protocol.Envelope) {
	select {
	case cn.out <- env:
	default:
		cn.log.Warn("dropping frame: outbound buffer full", "type", env.Type)
	}
}

func (cn *conn) writePump(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case env := <-cn.out:
			wctx, cancel := context.WithTimeout(ctx, writeTimeout)
			err := wsjson.Write(wctx, cn.ws, env)
			cancel()
			if err != nil {
				return
			}
		}
	}
}

// sendNow writes a single envelope synchronously (used for early errors before
// the write pump exists).
func sendNow(ctx context.Context, c *websocket.Conn, op protocol.Op, payload any) error {
	env, err := protocol.Encode(op, payload)
	if err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	return wsjson.Write(wctx, c, env)
}

// mustEncode encodes an envelope; the payloads here are plain structs that
// cannot fail to marshal, so an error indicates a programming bug.
func mustEncode(op protocol.Op, payload any) protocol.Envelope {
	env, err := protocol.Encode(op, payload)
	if err != nil {
		panic("protocol.Encode: " + err.Error())
	}
	return env
}

// newID returns a short random connection-scoped member ID.
func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
