package client

import (
	"testing"

	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// TestUseTorProxyConfiguresDial proves UseTorProxy installs SOCKS5 dial options
// (so Connect routes through Tor) and defaults the proxy address when omitted. It
// does not require a running proxy: proxy.SOCKS5 is lazy, validated at dial time.
func TestUseTorProxyConfiguresDial(t *testing.T) {
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	c, err := NewWithIdentity("ws://abc123.onion:80", "ops", "alice", id)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if c.dialOpts != nil {
		t.Fatal("a fresh client must dial directly (nil dial options)")
	}

	// Empty address → DefaultTorProxy.
	if err := c.UseTorProxy(""); err != nil {
		t.Fatalf("UseTorProxy(default): %v", err)
	}
	if c.dialOpts == nil || c.dialOpts.HTTPClient == nil || c.dialOpts.HTTPClient.Transport == nil {
		t.Fatal("UseTorProxy did not install SOCKS5 dial options")
	}

	// Explicit address (e.g. Tor Browser's bundled tor) is accepted too.
	if err := c.UseTorProxy("127.0.0.1:9150"); err != nil {
		t.Fatalf("UseTorProxy(explicit): %v", err)
	}
}

// TestDefaultTorProxy pins the standard tor daemon SOCKS port.
func TestDefaultTorProxy(t *testing.T) {
	if DefaultTorProxy != "127.0.0.1:9050" {
		t.Fatalf("DefaultTorProxy = %q, want 127.0.0.1:9050", DefaultTorProxy)
	}
}
