package sneakernet

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// coScuttleGrace is the delay between broadcasting a scuttle and tearing the
// connections down, so the control flushes to every peer (each runs its key
// ratchet on receipt) before the sockets close. Mirrors the relay's grace.
const coScuttleGrace = 300 * time.Millisecond

// Coordinator is the relay's coordination role, run from inside a participating
// peer (§1.1). The peer that LISTENS (the offerer in manual mode, the advertiser
// in LAN mode) runs one; joiners dial in. It reuses the exact membership and
// key-distribution choreography the relay uses — first member mints the key, the
// oldest member wraps it for each newcomer, frames are stamped with the
// authenticated sender and fanned out — but holds no key material and reads no
// plaintext: every payload it routes is opaque ciphertext, identical to the relay.
//
// For two peers this is a fully direct connection (the joiner ↔ the host). For
// more than two, the host relays between members — still no external
// infrastructure, and the host is a full room member who holds the key anyway, not
// a separate trusted server. Works well for small groups; for larger groups use
// the relay.
type Coordinator struct {
	room string
	id   *crypto.Identity
	log  *slog.Logger

	mu      sync.Mutex
	members map[string]*coMember
	order   []string // join order; index 0 is the oldest present member (the key distributor)

	listener net.Listener
	stopOnce sync.Once
}

type coMember struct {
	info  protocol.Member
	send  func(protocol.Envelope)
	close func()
}

// NewCoordinator creates a coordinator for room, identified by id (used to sign
// the auth handshake so joiners can verify they reached the right host).
func NewCoordinator(room string, id *crypto.Identity, log *slog.Logger) *Coordinator {
	if log == nil {
		log = slog.Default()
	}
	return &Coordinator{room: room, id: id, log: log, members: make(map[string]*coMember)}
}

// Loopback connects the host's OWN client to this coordinator over an in-process
// pipe (no network, no auth — a process trivially trusts itself). The returned
// transport is handed to the host client's ConnectWith; because the host connects
// first, it becomes the first member and mints the room key. The peer fingerprint
// is the host's own.
func (co *Coordinator) Loopback() *DirectTransport {
	clientSide, coordSide := net.Pipe()
	go co.serveMember(newFrameConn(coordSide), co.id.SignPub)
	return newDirectTransport(newFrameConn(clientSide), co.id.Fingerprint())
}

// Listen starts accepting direct peer connections on addr (host:port; ":0" or
// "127.0.0.1:0" picks a free port). It returns the bound address. Each accepted
// connection is authenticated (mutual Ed25519) before it is admitted to the room.
func (co *Coordinator) Listen(addr string) (string, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	co.mu.Lock()
	co.listener = ln
	co.mu.Unlock()
	go co.acceptLoop(ln)
	return ln.Addr().String(), nil
}

func (co *Coordinator) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go co.acceptConn(conn)
	}
}

// acceptConn authenticates an inbound peer, then serves it. The accepter admits
// any peer that proves control of its key (expectFpr == "") and surfaces the
// verified fingerprint — discovery is never trust (mDNS tells you someone is
// there; the keys tell you who they are). Operators verify or [[trust]]-pin out of
// band; the human typed /pair after seeing the fingerprint.
func (co *Coordinator) acceptConn(conn net.Conn) {
	fc := newFrameConn(conn)
	peerPub, err := performAuth(fc, co.id.SignPub, co.id, "")
	if err != nil {
		co.log.Warn("direct: rejected unauthenticated peer", "remote", fc.remoteAddr(), "err", err)
		_ = fc.close()
		return
	}
	co.log.Info("direct: peer authenticated", "remote", fc.remoteAddr(), "fpr", crypto.Fingerprint(peerPub))
	co.serveMember(fc, peerPub)
}

// serveMember runs one member's lifecycle: read its Hello, register it, complete
// the Welcome/MemberJoined/KeyRequest handshake, relay its frames, and on exit
// broadcast its departure. peerPub is the identity verified by the auth handshake
// (or the host's own key, for the loopback).
func (co *Coordinator) serveMember(fc *frameConn, peerPub ed25519.PublicKey) {
	hb, err := fc.readFrame()
	if err != nil {
		_ = fc.close()
		return
	}
	var env protocol.Envelope
	if json.Unmarshal(hb, &env) != nil || env.Type != protocol.OpHello {
		_ = fc.close()
		return
	}
	var hello protocol.Hello
	if env.Decode(&hello) != nil {
		_ = fc.close()
		return
	}
	// The Hello must use the SAME identity key that authenticated the connection —
	// a peer cannot authenticate as itself and then claim another member's key.
	if !bytes.Equal(hello.IdentityKey, peerPub) {
		_ = writeEnvelope(fc, protocol.OpError, protocol.Error{Code: "identity_mismatch", Message: "hello key does not match the authenticated connection"})
		_ = fc.close()
		return
	}
	if hello.Room != "" && hello.Room != co.room {
		_ = writeEnvelope(fc, protocol.OpError, protocol.Error{Code: "wrong_room", Message: "this peer hosts a different room"})
		_ = fc.close()
		return
	}

	id := newID()
	out := make(chan protocol.Envelope, 64)
	done := make(chan struct{})
	var closeOnce sync.Once
	closeConn := func() { closeOnce.Do(func() { close(done); _ = fc.close() }) }
	send := func(e protocol.Envelope) {
		select {
		case out <- e:
		case <-done:
		default:
			co.log.Warn("direct: dropping frame to a slow peer", "type", e.Type)
		}
	}
	go func() { // per-member write pump: the only writer to fc after the handshake
		for {
			select {
			case <-done:
				return
			case e := <-out:
				b, _ := json.Marshal(e)
				if fc.writeFrame(b) != nil {
					closeConn()
					return
				}
			}
		}
	}()

	m := &coMember{
		info:  protocol.Member{ID: id, DisplayName: hello.DisplayName, IdentityKey: hello.IdentityKey, KXKey: hello.KXKey},
		send:  send,
		close: closeConn,
	}
	existing, youAreFirst, distributor := co.join(m)

	send(mustEncode(protocol.OpWelcome, protocol.Welcome{
		ProtocolVersion: protocol.Version,
		YourID:          id,
		Room:            co.room,
		Members:         existing,
		YouAreFirst:     youAreFirst,
	}))
	co.broadcast(id, mustEncode(protocol.OpMemberJoined, protocol.MemberJoined{Member: m.info}))
	if distributor != nil {
		// Ask the oldest present member to wrap the current room key for the newcomer
		// (nacl/box to its X25519 key) — the coordinator never sees the key.
		distributor.send(mustEncode(protocol.OpKeyRequest, protocol.KeyRequest{ForMember: m.info}))
	}
	co.log.Info("direct: member joined", "room", co.room, "id", id, "name", hello.DisplayName, "first", youAreFirst)

	for {
		b, err := fc.readFrame()
		if err != nil {
			break
		}
		var e protocol.Envelope
		if json.Unmarshal(b, &e) != nil {
			continue
		}
		co.route(id, e)
	}

	empty := co.leave(id)
	co.broadcast(id, mustEncode(protocol.OpMemberLeft, protocol.MemberLeft{ID: id}))
	closeConn()
	co.log.Info("direct: member left", "room", co.room, "id", id, "empty", empty)
}

// route forwards an authenticated member's frame, stamping the sender so a peer
// cannot spoof another's identity in the routing layer (recipients verify the
// Ed25519 signature for the rest). It is the direct-mode analogue of the relay's
// fan-out, minus the relay-only features (invites, webhooks, break-glass).
func (co *Coordinator) route(fromID string, env protocol.Envelope) {
	switch env.Type {
	case protocol.OpKeyDeliver:
		var kd protocol.KeyDeliver
		if env.Decode(&kd) != nil {
			return
		}
		kd.FromID = fromID
		co.sendTo(kd.ToID, mustEncode(protocol.OpKeyDeliver, kd))

	case protocol.OpControl:
		var ctrl protocol.Control
		if env.Decode(&ctrl) != nil {
			return
		}
		ctrl.By = fromID
		if ctrl.Action == protocol.ActionScuttle {
			co.scuttle() // /scuttle now: burn the room (the broadcast carries the reason)
			return
		}
		co.broadcast(fromID, mustEncode(protocol.OpControl, ctrl)) // vanish / ttl / scuttle_arm

	case protocol.OpMessage, protocol.OpExecRequest, protocol.OpExecResult, protocol.OpAck, protocol.OpHandoff,
		protocol.OpRecordEntry, protocol.OpSealRequest, protocol.OpSealAck,
		protocol.OpRosterRequest, protocol.OpRosterAck,
		protocol.OpScuttleReceiptRequest, protocol.OpScuttleReceiptAck,
		protocol.OpActionRequest, protocol.OpActionApproval, protocol.OpActionVeto:
		// Opaque, sealed, Ed25519-signed Message envelopes: stamp the authenticated
		// sender and fan out — identical to the relay, content never inspected.
		var m protocol.Message
		if env.Decode(&m) != nil {
			return
		}
		m.FromID = fromID
		co.broadcast(fromID, mustEncode(env.Type, m))

	case protocol.OpFileOffer, protocol.OpFileChunk, protocol.OpFileAck, protocol.OpFileAbort:
		// Artifact transfer (§2.3): forward verbatim to the rest of the room. The
		// relay's concurrency cap is a DoS protection that matters less among a
		// handful of authenticated peers; the transfer is signature-verified end to end.
		co.broadcast(fromID, env)

	default:
		// invite_request / break_glass and other relay-only opcodes have no meaning
		// without a server; ignore them in direct mode.
	}
}

func (co *Coordinator) join(m *coMember) (existing []protocol.Member, youAreFirst bool, distributor *coMember) {
	co.mu.Lock()
	defer co.mu.Unlock()
	youAreFirst = len(co.members) == 0
	for _, id := range co.order {
		if em := co.members[id]; em != nil {
			existing = append(existing, em.info)
			if distributor == nil {
				distributor = em
			}
		}
	}
	co.members[m.info.ID] = m
	co.order = append(co.order, m.info.ID)
	return existing, youAreFirst, distributor
}

func (co *Coordinator) leave(id string) (empty bool) {
	co.mu.Lock()
	defer co.mu.Unlock()
	delete(co.members, id)
	for i, x := range co.order {
		if x == id {
			co.order = append(co.order[:i], co.order[i+1:]...)
			break
		}
	}
	return len(co.members) == 0
}

func (co *Coordinator) broadcast(exceptID string, env protocol.Envelope) {
	co.mu.Lock()
	sends := make([]func(protocol.Envelope), 0, len(co.members))
	for id, m := range co.members {
		if id == exceptID {
			continue
		}
		sends = append(sends, m.send)
	}
	co.mu.Unlock()
	for _, s := range sends {
		s(env)
	}
}

func (co *Coordinator) sendTo(id string, env protocol.Envelope) {
	co.mu.Lock()
	m := co.members[id]
	co.mu.Unlock()
	if m != nil {
		m.send(env)
	}
}

func (co *Coordinator) scuttle() {
	notice := mustEncode(protocol.OpControl, protocol.Control{Action: protocol.ActionScuttle, Reason: protocol.ScuttleManual})
	co.broadcast("", notice) // everyone, including the initiator (mirrors hub.Scuttle)
	co.log.Info("direct: room scuttled", "room", co.room)
	time.AfterFunc(coScuttleGrace, func() { _ = co.Close() })
}

// MemberCount returns the number of members currently in the room (including the
// host). Used by /whoami to report "direct (N peers)".
func (co *Coordinator) MemberCount() int {
	co.mu.Lock()
	defer co.mu.Unlock()
	return len(co.members)
}

// Close tears down the coordinator: it stops the listener and closes every member
// connection. Safe to call more than once.
func (co *Coordinator) Close() error {
	co.stopOnce.Do(func() {
		co.mu.Lock()
		ln := co.listener
		members := make([]*coMember, 0, len(co.members))
		for _, m := range co.members {
			members = append(members, m)
		}
		co.mu.Unlock()
		if ln != nil {
			_ = ln.Close()
		}
		for _, m := range members {
			m.close()
		}
	})
	return nil
}

func mustEncode(op protocol.Op, payload any) protocol.Envelope {
	env, err := protocol.Encode(op, payload)
	if err != nil {
		panic("protocol.Encode: " + err.Error())
	}
	return env
}

func writeEnvelope(fc *frameConn, op protocol.Op, payload any) error {
	b, err := json.Marshal(mustEncode(op, payload))
	if err != nil {
		return err
	}
	return fc.writeFrame(b)
}

func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
