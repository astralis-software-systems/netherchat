package client

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"github.com/coder/websocket"
	"golang.org/x/net/proxy"
)

// DefaultTorProxy is the SOCKS5 address a stock tor daemon / Tor Browser listens
// on. Override with --tor-proxy when using Tor Browser's bundled tor (127.0.0.1:9150).
const DefaultTorProxy = "127.0.0.1:9050"

// UseTorProxy routes this client's WebSocket dial through a local Tor SOCKS5
// proxy (§1.5), so it can reach a relay's v3 .onion address with no public IP,
// DNS, or TLS. proxyAddr is host:port (e.g. 127.0.0.1:9050); empty uses
// DefaultTorProxy. The .onion hostname is handed to the proxy unresolved — tor
// does the rendezvous — so no DNS leaks locally. Call before Connect.
//
// Reaching the expected .onion is itself relay authentication: a v3 address is
// the relay's public key, so connecting to the right address proves you reached
// the right relay, with no CA (see docs/encryption.md).
func (c *Client) UseTorProxy(proxyAddr string) error {
	if proxyAddr == "" {
		proxyAddr = DefaultTorProxy
	}
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		return fmt.Errorf("configure tor SOCKS5 proxy %s: %w", proxyAddr, err)
	}
	ctxDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return fmt.Errorf("tor SOCKS5 dialer does not support contexts")
	}
	c.dialOpts = &websocket.DialOptions{
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				// Route every connection (the WS upgrade handshake) through Tor.
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return ctxDialer.DialContext(ctx, network, addr)
				},
			},
		},
	}
	return nil
}
