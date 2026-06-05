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
	"log/slog"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/server/internal/hub"
	"github.com/salehkreiner/netherchat/server/internal/invite"
	"github.com/salehkreiner/netherchat/server/internal/store"
	"golang.org/x/time/rate"
)

const (
	readLimitBytes = 1 << 20 // 1 MiB per message — generous for ciphertext + wrapped keys
	sendBuffer     = 64      // per-connection outbound queue depth
	writeTimeout   = 10 * time.Second
	inviteTTL      = 24 * time.Hour
	execTimeout    = 10 * time.Second
	execOutputCap  = 8 << 10 // 8 KiB of command output
)

// Server relays WebSocket connections through a hub.
type Server struct {
	hub     *hub.Hub
	cfg     config.Config
	invites *invite.Store
	store   store.Store // optional history persistence; nil when disabled
	log     *slog.Logger
}

// NewServer constructs a transport bound to the given hub, config, invite store
// and optional message store (nil to disable persistence).
func NewServer(h *hub.Hub, cfg config.Config, invites *invite.Store, st store.Store, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{hub: h, cfg: cfg, invites: invites, store: st, log: log}
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
	if hello.ProtocolVersion != protocol.Version {
		_ = sendNow(ctx, c, protocol.OpError, protocol.Error{Code: "version_mismatch", Message: "unsupported protocol version"})
		return
	}
	if hello.Room == "" {
		_ = sendNow(ctx, c, protocol.OpError, protocol.Error{Code: "no_room", Message: "room is required"})
		return
	}

	// 2. Enforce invite-only policy before admitting the connection. The token is
	// one-time: redeeming it here consumes it.
	policy := s.cfg.Room(hello.Room)
	if policy.InviteOnly {
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
	cn.send(mustEncode(protocol.OpWelcome, protocol.Welcome{
		ProtocolVersion: protocol.Version,
		YourID:          id,
		Room:            hello.Room,
		Members:         res.Existing,
		YouAreFirst:     res.YouAreFirst,
		Policy: protocol.RoomPolicy{
			InviteOnly:  policy.InviteOnly,
			ExecEnabled: policy.ExecEnabled && s.cfg.Exec.Enabled,
			Webhook:     policy.Webhook,
			TTLSeconds:  int(policy.TTL.Std().Seconds()),
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
		var env protocol.Envelope
		if err := wsjson.Read(ctx, c, &env); err != nil {
			break
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
	s.log.Info("member left", "room", hello.Room, "id", id, "room_empty", empty)
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
		// Control actions (vanish, ttl) carry no secrets; relay to the room.
		var ctrl protocol.Control
		if err := env.Decode(&ctrl); err != nil {
			return
		}
		ctrl.By = fromID
		s.hub.Broadcast(room, fromID, mustEncode(protocol.OpControl, ctrl))

	case protocol.OpInviteRequest:
		token, exp := s.invites.Generate(room, inviteTTL)
		var expUnix int64
		if !exp.IsZero() {
			expUnix = exp.Unix()
		}
		s.hub.SendTo(room, fromID, mustEncode(protocol.OpInviteResult, protocol.InviteResult{
			Room: room, Token: token, Expires: expUnix,
		}))

	case protocol.OpExecRequest:
		var er protocol.ExecRequest
		if err := env.Decode(&er); err != nil {
			return
		}
		go s.runExec(room, fromID, er.Command)

	default:
		s.log.Debug("ignoring unknown opcode", "type", env.Type)
	}
}

// runExec runs an allow-listed command on behalf of a member. The requested
// command must EXACTLY match an entry in [exec].allow and the room must have
// exec_enabled; there is no shell and arguments are not interpreted. Every
// attempt is audit-logged.
func (s *Server) runExec(room, fromID, command string) {
	allowed := s.cfg.ExecAllowed(room, command)
	s.log.Info("exec request", "room", room, "by", fromID, "command", command, "allowed", allowed)

	result := protocol.ExecResult{Command: command, Allowed: allowed}
	if !allowed {
		result.Err = "command not permitted (must be listed in [exec].allow and the room must set exec_enabled)"
		s.hub.SendTo(room, fromID, mustEncode(protocol.OpExecResult, result))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()
	parts := strings.Fields(command)
	out, err := exec.CommandContext(ctx, parts[0], parts[1:]...).CombinedOutput()
	if len(out) > execOutputCap {
		out = append(out[:execOutputCap:execOutputCap], []byte("\n…(truncated)")...)
	}
	result.Output = string(out)
	if err != nil {
		result.Err = err.Error()
	}
	s.hub.SendTo(room, fromID, mustEncode(protocol.OpExecResult, result))

	// Share the run with the rest of the room for ops transparency.
	s.hub.Broadcast(room, fromID, mustEncode(protocol.OpServerMessage, protocol.ServerMessage{
		Kind: "exec",
		From: "exec",
		Text: "$ " + command + "\n" + result.Output,
		At:   time.Now().Unix(),
	}))
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
