// Package sneakernet implements Sneakernet Mode (§1.1): a relay-LESS, peer-to-peer
// war room. When the relay cannot be trusted or reached, two or more clients form
// a room with no server at all — same BYO-key identity, same NaCl group crypto,
// same epoch forward secrecy, same sealed records — over a direct connection
// instead of the WebSocket relay.
//
// This is possible only because the relay was already blind: it routed ciphertext
// and never held key material, so removing it changes nothing above the transport
// layer. The client (tui/client) speaks its Hello/Welcome protocol over a
// client.Transport; here we provide a DIRECT transport (length-prefixed TCP,
// authenticated by Ed25519) and a self-contained Coordinator that plays the
// relay's coordination role from inside a participating peer.
//
// Scope (honest, per §1.1): LAN auto-discovery (mDNS) and manual blob exchange
// only. There is deliberately NO STUN/TURN/NAT traversal — that needs a rendezvous
// server, which re-introduces infrastructure and a trusted third party, the very
// things Sneakernet removes. Sneakernet is the FALLBACK for when the relay is
// unavailable or suspect, not a replacement for normal operation.
package sneakernet

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
)

// maxFrameBytes caps one direct-transport frame (ciphertext + wrapped keys),
// mirroring the relay's per-message read limit. A larger length prefix is a
// malformed/hostile peer and the connection is dropped.
const maxFrameBytes = 1 << 20

// frameConn carries length-prefixed envelope frames over a stream connection:
//
//	[4-byte big-endian length][payload]
//
// This is the ONLY wire difference from the relay (which speaks WebSocket framing);
// the payload — a JSON protocol.Envelope — is byte-for-byte identical. Writes are
// serialized by wmu so the coordinator's fan-out (many goroutines) never interleaves
// a frame.
type frameConn struct {
	conn net.Conn
	wmu  sync.Mutex
}

func newFrameConn(conn net.Conn) *frameConn { return &frameConn{conn: conn} }

// writeFrame writes one length-prefixed frame atomically.
func (fc *frameConn) writeFrame(b []byte) error {
	if len(b) > maxFrameBytes {
		return fmt.Errorf("frame too large: %d bytes", len(b))
	}
	fc.wmu.Lock()
	defer fc.wmu.Unlock()
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := fc.conn.Write(hdr[:]); err != nil {
		return err
	}
	_, err := fc.conn.Write(b)
	return err
}

// readFrame reads one length-prefixed frame, rejecting an oversized prefix before
// allocating.
func (fc *frameConn) readFrame() ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(fc.conn, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxFrameBytes {
		return nil, fmt.Errorf("inbound frame too large: %d bytes", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(fc.conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (fc *frameConn) close() error { return fc.conn.Close() }

func (fc *frameConn) remoteAddr() string {
	if a := fc.conn.RemoteAddr(); a != nil {
		return a.String()
	}
	return "direct"
}
