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
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/server/internal/hub"
)

const (
	readLimitBytes = 1 << 20 // 1 MiB per message — generous for ciphertext + wrapped keys
	sendBuffer     = 64      // per-connection outbound queue depth
	writeTimeout   = 10 * time.Second
)

// Server relays WebSocket connections through a hub.
type Server struct {
	hub *hub.Hub
	log *slog.Logger
}

// NewServer constructs a transport bound to the given hub.
func NewServer(h *hub.Hub, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{hub: h, log: log}
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

	// 2. Set up the connection's outbound pump.
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
		Send: cn.send,
	}

	// 3. Join the room and complete the handshake.
	res := s.hub.Join(hello.Room, member)
	cn.send(mustEncode(protocol.OpWelcome, protocol.Welcome{
		ProtocolVersion: protocol.Version,
		YourID:          id,
		Room:            hello.Room,
		Members:         res.Existing,
		YouAreFirst:     res.YouAreFirst,
	}))
	s.hub.Broadcast(hello.Room, id, mustEncode(protocol.OpMemberJoined, protocol.MemberJoined{Member: member.Info}))
	if res.Distributor != nil {
		// Ask the oldest existing member to wrap the current room key for the newcomer.
		res.Distributor.Send(mustEncode(protocol.OpKeyRequest, protocol.KeyRequest{ForMember: member.Info}))
	}
	s.log.Info("member joined", "room", hello.Room, "id", id, "name", hello.DisplayName, "first", res.YouAreFirst)

	// 4. Relay loop.
	for {
		var env protocol.Envelope
		if err := wsjson.Read(ctx, c, &env); err != nil {
			break
		}
		s.relay(hello.Room, id, env)
	}

	// 5. Departure.
	empty := s.hub.Leave(hello.Room, id)
	s.hub.Broadcast(hello.Room, id, mustEncode(protocol.OpMemberLeft, protocol.MemberLeft{ID: id}))
	s.log.Info("member left", "room", hello.Room, "id", id, "room_empty", empty)
}

// relay forwards a client frame to its destination(s). The server stamps the
// authoritative sender ID so a client cannot spoof another member's identity in
// the routing layer (signature verification by recipients enforces the rest).
func (s *Server) relay(room, fromID string, env protocol.Envelope) {
	switch env.Type {
	case protocol.OpMessage:
		var m protocol.Message
		if err := env.Decode(&m); err != nil {
			return
		}
		m.FromID = fromID
		s.hub.Broadcast(room, fromID, mustEncode(protocol.OpMessage, m))

	case protocol.OpKeyDeliver:
		var kd protocol.KeyDeliver
		if err := env.Decode(&kd); err != nil {
			return
		}
		kd.FromID = fromID
		if !s.hub.SendTo(room, kd.ToID, mustEncode(protocol.OpKeyDeliver, kd)) {
			s.log.Debug("key_deliver target not found", "room", room, "to", kd.ToID)
		}

	default:
		// Unknown opcodes are ignored in M1.
		s.log.Debug("ignoring unknown opcode", "type", env.Type)
	}
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
