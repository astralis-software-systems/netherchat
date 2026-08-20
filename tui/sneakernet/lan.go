package sneakernet

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// lanBrowseWindow is how long RunLAN looks for existing peers before deciding to
// host or offering the discovered candidates for pairing.
const lanBrowseWindow = 4 * time.Second

// RunLAN is the LAN auto-discovery side of Sneakernet (§1.1). It advertises this
// peer on the local network and browses for others in the same room. Discovery is
// never trust: a found peer is a CANDIDATE, shown with its fingerprint; the
// operator types /pair <fingerprint> to connect, and only the Ed25519 handshake
// then proves the peer really holds that key ("mDNS tells you someone is there;
// your keys tell you who they are"). If no peer is found, this peer hosts and waits
// for someone to /pair it.
func RunLAN(opts Options) error {
	opts.fill()
	id, err := crypto.ResolveIdentity(opts.IdentityPath)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	co := NewCoordinator(opts.Room, id, opts.Log)
	addr, err := co.Listen(fmt.Sprintf(":%d", opts.Port))
	if err != nil {
		return fmt.Errorf("listen for direct peers: %w", err)
	}
	defer co.Close()
	_, portStr, _ := net.SplitHostPort(addr)

	if adv, aerr := Advertise(id, opts.Room, atoiSafe(portStr)); aerr != nil {
		fmt.Fprintf(opts.Out, "LAN advertise failed (%v). On a network without multicast, use: netherchat pair --manual\n", aerr)
	} else {
		defer adv.Close()
	}
	fmt.Fprintf(opts.Out, "You are %s (%s) in #%s, listening on :%s, advertising on the LAN.\n",
		opts.Name, id.Fingerprint(), opts.Room, portStr)

	bctx, bcancel := context.WithTimeout(context.Background(), lanBrowseWindow)
	peers, _ := Browse(bctx, opts.Room, lanBrowseWindow)
	bcancel()

	if len(peers) == 0 {
		fmt.Fprintln(opts.Out, "No peers found on the LAN yet — hosting and waiting. A peer running `pair --lan` in this room can /pair you.")
		return hostHere(co, id, opts)
	}

	fmt.Fprintln(opts.Out, "Found on the LAN (verify the fingerprint out of band before pairing — discovery is not trust):")
	for _, p := range peers {
		fmt.Fprintf(opts.Out, "  %s  at %s\n", p.Fpr, p.Addr)
	}
	fmt.Fprintln(opts.Out, "Type /pair <fingerprint-prefix> to connect, /host to wait for peers, or /quit.")

	if opts.In == nil {
		return hostHere(co, id, opts) // non-interactive: host and wait
	}
	sc := bufio.NewScanner(opts.In)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || line == "/host":
			return hostHere(co, id, opts)
		case line == "/quit":
			return nil
		case strings.HasPrefix(line, "/pair"):
			target := strings.TrimSpace(strings.TrimPrefix(line, "/pair"))
			p, ok := matchPeer(peers, target)
			if !ok {
				fmt.Fprintf(opts.Out, "! no discovered peer matches %q (try a longer fingerprint prefix)\n", target)
				continue
			}
			co.Close() // we are joining, not hosting
			return joinPeer(p, id, opts)
		default:
			fmt.Fprintln(opts.Out, "! type /pair <fingerprint>, /host, or /quit")
		}
	}
	return sc.Err()
}

// hostHere connects the host's own client over the loopback (first member, mints
// the key) and runs the session, accepting peers that /pair in.
func hostHere(co *Coordinator, id *crypto.Identity, opts Options) error {
	c, err := newSessionClient(opts, id)
	if err != nil {
		return err
	}
	if err := c.ConnectWith(co.Loopback()); err != nil {
		return err
	}
	defer closeSession(c, opts.Out)
	if err := waitKeyReady(c, 10*time.Second); err != nil {
		return err
	}
	fmt.Fprintln(opts.Out, "Hosting (direct, no relay). Type messages or /help; /quit to leave.")
	return runSession(c, co, opts)
}

// joinPeer dials a discovered peer, enforcing its advertised fingerprint via the
// Ed25519 handshake, then runs the session.
func joinPeer(p Peer, id *crypto.Identity, opts Options) error {
	fmt.Fprintf(opts.Out, "Pairing with %s at %s…\n", p.Fpr, p.Addr)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	dt, err := Dial(ctx, p.Addr, id, p.Fpr)
	cancel()
	if err != nil {
		return fmt.Errorf("pair with %s: %w", p.Fpr, err)
	}
	c, err := newSessionClient(opts, id)
	if err != nil {
		return err
	}
	if err := c.ConnectWith(dt); err != nil {
		return err
	}
	defer closeSession(c, opts.Out)
	if err := waitKeyReady(c, 10*time.Second); err != nil {
		return err
	}
	fmt.Fprintf(opts.Out, "Connected to %s — direct, no relay. Type messages or /help; /quit to leave.\n", dt.PeerID())
	return runSession(c, nil, opts)
}

// matchPeer finds the discovered peer whose fingerprint contains target (a prefix
// of the base64 body is enough for the common case).
func matchPeer(peers []Peer, target string) (Peer, bool) {
	target = strings.TrimPrefix(target, "SHA256:")
	if target == "" {
		return Peer{}, false
	}
	for _, p := range peers {
		body := strings.TrimPrefix(p.Fpr, "SHA256:")
		if strings.HasPrefix(body, target) || strings.Contains(p.Fpr, target) {
			return p, true
		}
	}
	return Peer{}, false
}
