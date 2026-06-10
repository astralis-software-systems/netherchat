package sneakernet

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// DirectTransport is a relay-LESS client.Transport: a length-prefixed TCP (or
// in-process loopback) connection to a single peer, authenticated by Ed25519. It
// satisfies tui/client.Transport, so a client.Client runs over it exactly as it
// runs over the WebSocket relay — same Hello/Welcome, same encryption, same
// commands. The only differences a caller sees are PeerID (the peer's fingerprint)
// and that no server is involved.
type DirectTransport struct {
	fc      *frameConn
	peerFpr string
	recvCh  chan []byte
	done    chan struct{}

	closeOnce sync.Once
	mu        sync.Mutex
	err       error
}

func newDirectTransport(fc *frameConn, peerFpr string) *DirectTransport {
	dt := &DirectTransport{
		fc:      fc,
		peerFpr: peerFpr,
		recvCh:  make(chan []byte, 64),
		done:    make(chan struct{}),
	}
	go dt.readPump()
	return dt
}

// Dial opens a direct TCP connection to addr and runs the mutual Ed25519
// handshake, requiring the peer to present expectFpr (the host fingerprint learned
// from the offer blob or mDNS). On success it returns a ready transport the caller
// hands to client.ConnectWith. On any auth failure the connection is closed and an
// error returned — an unauthenticated or wrong-identity peer never reaches the
// message layer.
func Dial(ctx context.Context, addr string, id *crypto.Identity, expectFpr string) (*DirectTransport, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	fc := newFrameConn(conn)
	peerPub, err := performAuth(fc, id.SignPub, id, expectFpr)
	if err != nil {
		_ = fc.close()
		return nil, fmt.Errorf("authenticate peer at %s: %w", addr, err)
	}
	return newDirectTransport(fc, crypto.Fingerprint(peerPub)), nil
}

func (dt *DirectTransport) readPump() {
	defer close(dt.recvCh)
	for {
		b, err := dt.fc.readFrame()
		if err != nil {
			dt.setErr(err)
			return
		}
		select {
		case dt.recvCh <- b:
		case <-dt.done:
			return
		}
	}
}

func (dt *DirectTransport) Send(envelope []byte) error { return dt.fc.writeFrame(envelope) }

func (dt *DirectTransport) Recv() (<-chan []byte, error) { return dt.recvCh, nil }

func (dt *DirectTransport) Close() error {
	var err error
	dt.closeOnce.Do(func() {
		close(dt.done)
		err = dt.fc.close()
	})
	return err
}

func (dt *DirectTransport) PeerID() string     { return dt.peerFpr }
func (dt *DirectTransport) RemoteAddr() string { return dt.fc.remoteAddr() }

func (dt *DirectTransport) setErr(err error) {
	dt.mu.Lock()
	if dt.err == nil {
		dt.err = err
	}
	dt.mu.Unlock()
}

func (dt *DirectTransport) lastErr() error {
	dt.mu.Lock()
	defer dt.mu.Unlock()
	return dt.err
}
