package client

import (
	"context"
	"sync"

	"github.com/coder/websocket"
)

// Transport is the byte pipe the client core speaks its protocol over. It moves
// opaque envelope bytes; it knows nothing about encryption, rooms, or membership.
// This is the seam that makes Sneakernet Mode (§1.1) possible: the WebSocket relay
// is one implementation (RelayTransport); a direct peer-to-peer TCP connection is
// another (sneakernet.DirectTransport). Everything above the transport —
// encryption, the command set, the TUI — is identical regardless of which one is
// in use.
type Transport interface {
	// Send transmits one already-marshaled envelope. It is called only from the
	// client's single write loop, so implementations need not be re-entrant.
	Send(envelope []byte) error
	// Recv returns the stream of inbound envelope bytes. It is called once; the
	// channel is closed when the connection ends.
	Recv() (<-chan []byte, error)
	// Close terminates the connection (and so closes the Recv channel).
	Close() error
	// PeerID is the fingerprint of the remote peer for a direct connection, or ""
	// for the relay (which is not a single identified peer).
	PeerID() string
	// RemoteAddr is a human label for where this transport connects (a ws:// URL
	// for the relay, a host:port for a direct peer).
	RemoteAddr() string
}

// errTransport lets the client surface the underlying reason a transport's Recv
// channel closed (vs. a generic "connection closed"). Optional — transports that
// do not implement it just report the generic reason.
type errTransport interface{ lastErr() error }

// readLimitBytesRelay caps a single inbound relay frame (ciphertext + wrapped
// keys); it mirrors the server's own read limit.
const readLimitBytesRelay = 1 << 20

// RelayTransport is the original WebSocket relay path, unchanged in behavior:
// envelopes are JSON text frames to/from the blind relay server.
type RelayTransport struct {
	ws     *websocket.Conn
	url    string
	recvCh chan []byte
	ctx    context.Context
	cancel context.CancelFunc

	mu  sync.Mutex
	err error
}

// DialRelay opens a WebSocket connection to the relay at url, honoring dialOpts
// (used by the Tor SOCKS5 path). dialCtx bounds the dial only; the session lives
// until Close or a transport error.
func DialRelay(dialCtx context.Context, url string, dialOpts *websocket.DialOptions) (*RelayTransport, error) {
	conn, resp, err := websocket.Dial(dialCtx, url, dialOpts)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	conn.SetReadLimit(readLimitBytesRelay)
	rt := &RelayTransport{ws: conn, url: url, recvCh: make(chan []byte, 64)}
	rt.ctx, rt.cancel = context.WithCancel(context.Background())
	go rt.readPump()
	return rt, nil
}

func (rt *RelayTransport) readPump() {
	defer close(rt.recvCh)
	for {
		_, b, err := rt.ws.Read(rt.ctx)
		if err != nil {
			rt.setErr(err)
			return
		}
		select {
		case rt.recvCh <- b:
		case <-rt.ctx.Done():
			return
		}
	}
}

func (rt *RelayTransport) Send(envelope []byte) error {
	wctx, cancel := context.WithTimeout(rt.ctx, writeTimeout)
	defer cancel()
	return rt.ws.Write(wctx, websocket.MessageText, envelope)
}

func (rt *RelayTransport) Recv() (<-chan []byte, error) { return rt.recvCh, nil }

func (rt *RelayTransport) Close() error {
	rt.cancel()
	return rt.ws.Close(websocket.StatusNormalClosure, "bye")
}

func (rt *RelayTransport) PeerID() string     { return "" }
func (rt *RelayTransport) RemoteAddr() string { return rt.url }

func (rt *RelayTransport) setErr(err error) {
	rt.mu.Lock()
	if rt.err == nil {
		rt.err = err
	}
	rt.mu.Unlock()
}

func (rt *RelayTransport) lastErr() error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.err
}
