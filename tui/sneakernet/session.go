package sneakernet

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
	"github.com/salehkreiner/netherchat/tui/qr"
)

// directPlaceholderURL is the server URL handed to client.NewWithIdentity in
// Sneakernet mode. It is never dialed — the client runs over a direct transport
// via ConnectWith — but the constructor validates the scheme, so it must parse as
// a ws URL. RemoteAddr comes from the direct transport, not this value.
const directPlaceholderURL = "ws://sneakernet.local"

// Options configure a relay-less pairing session.
type Options struct {
	Room         string
	Name         string
	IdentityPath string // empty = the BYO-key cascade (ssh-agent → ~/.ssh → generated)
	Port         int    // direct listener port; 0 = a free port
	LAN          bool   // advertise/discover on the LAN via mDNS
	QR           bool   // render the offer blob as a scannable terminal QR (§2.4)
	In           io.Reader
	Out          io.Writer
	Log          *slog.Logger
}

func (o *Options) fill() {
	if o.In == nil {
		o.In = nil // caller must set for interactive use; tests inject a buffer
	}
	if o.Out == nil {
		o.Out = io.Discard
	}
	if o.Log == nil {
		o.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if o.Room == "" {
		o.Room = "ops"
	}
	if o.Name == "" {
		o.Name = "anon"
	}
}

// RunHost is the offerer/advertiser side of Sneakernet (§1.1): it stands up a
// coordinator + TCP listener, connects its own client over the in-process loopback
// (becoming the first member and minting the room key), prints a signed offer blob
// for manual pairing (and advertises on the LAN when opts.LAN), then runs the
// interactive session. No relay process is involved at any point.
func RunHost(opts Options) error {
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
	addrs := localAddrs(portStr)

	c, err := client.NewWithIdentity(directPlaceholderURL, opts.Room, opts.Name, id)
	if err != nil {
		return err
	}
	if err := c.ConnectWith(co.Loopback()); err != nil {
		return err
	}
	defer c.Close()
	if err := waitKeyReady(c, 10*time.Second); err != nil {
		return err
	}

	blob, err := NewBlob(id, opts.Room, addrs)
	if err != nil {
		return err
	}
	fmt.Fprintf(opts.Out, "You are hosting room #%s as %s\n  %s\n  listening on %s\n\n",
		opts.Room, opts.Name, id.Fingerprint(), strings.Join(addrs, ", "))
	fmt.Fprintf(opts.Out, "Your offer (share this with your peer; valid %s):\n%s\n\n", BlobTTL, blob.Armor("offer"))
	if opts.QR {
		if code, ok := qr.Render(blob.Compact(), qr.TerminalWidth()); ok {
			fmt.Fprintf(opts.Out, "Or scan to pair in person:\n%s\n\n", code)
		} else {
			fmt.Fprintln(opts.Out, "(terminal too narrow for a QR — share the offer text above)")
		}
	}

	if opts.LAN {
		if adv, aerr := Advertise(id, opts.Room, atoiSafe(portStr)); aerr == nil {
			defer adv.Close()
			fmt.Fprintf(opts.Out, "Advertising on the LAN (mDNS). Peers in #%s can discover you and /pair.\n", opts.Room)
		} else {
			fmt.Fprintf(opts.Out, "LAN advertise unavailable (%v); manual offer still works.\n", aerr)
		}
	}
	fmt.Fprintln(opts.Out, "Waiting for a peer. Type messages or /help; /quit to leave.")
	return runSession(c, co, opts)
}

// RunJoin is the answerer side: it reads a peer's offer (from opts.In, until the
// END marker), verifies it, prints an answer blob for the host to confirm who
// joined, dials the host (enforcing the offer's fingerprint via the Ed25519
// handshake), then runs the interactive session. No relay is involved.
func RunJoin(opts Options) error {
	opts.fill()
	id, err := crypto.ResolveIdentity(opts.IdentityPath)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	fmt.Fprintln(opts.Out, "Paste the offer from your peer, then a blank line:")
	offer, err := readBlob(opts.In)
	if err != nil {
		return fmt.Errorf("read offer: %w", err)
	}
	fmt.Fprintf(opts.Out, "Offer is from %s for room #%s.\n", offer.Fpr, offer.Room)
	if offer.Room != "" {
		opts.Room = offer.Room
	}

	answer, err := NewBlob(id, opts.Room, nil)
	if err == nil {
		fmt.Fprintf(opts.Out, "\nYour answer (share with the host so they can confirm your identity):\n%s\n\n", answer.Armor("answer"))
	}

	c, err := client.NewWithIdentity(directPlaceholderURL, opts.Room, opts.Name, id)
	if err != nil {
		return err
	}
	dt, err := dialAny(offer.Addrs, id, offer.Fpr)
	if err != nil {
		return fmt.Errorf("connect to host (it must be reachable at one of %v): %w", offer.Addrs, err)
	}
	if err := c.ConnectWith(dt); err != nil {
		return err
	}
	defer c.Close()
	if err := waitKeyReady(c, 10*time.Second); err != nil {
		return err
	}
	fmt.Fprintf(opts.Out, "Connected to host %s — direct, no relay. Type messages or /help; /quit to leave.\n", dt.PeerID())
	return runSession(c, nil, opts)
}

// dialAny tries each candidate address until one authenticates as expectFpr.
func dialAny(addrs []string, id *crypto.Identity, expectFpr string) (*DirectTransport, error) {
	if len(addrs) == 0 {
		return nil, fmt.Errorf("offer carried no addresses")
	}
	var lastErr error
	for _, a := range addrs {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		dt, err := Dial(ctx, a, id, expectFpr)
		cancel()
		if err == nil {
			return dt, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// runSession is the interactive loop shared by host and joiner: it prints inbound
// events and turns stdin lines into messages or slash commands. co is the host's
// coordinator (nil on the joiner) — it is consulted only for the peer count.
func runSession(c *client.Client, co *Coordinator, opts Options) error {
	go func() {
		for {
			select {
			case ev := <-c.Events():
				printEvent(opts.Out, ev)
			case <-c.Done():
				fmt.Fprintln(opts.Out, "* connection closed")
				return
			}
		}
	}()

	if opts.In == nil {
		<-c.Done()
		return nil
	}
	sc := bufio.NewScanner(opts.In)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r\n")
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "/") {
			if quit := handleCommand(c, co, opts, line); quit {
				return nil
			}
			continue
		}
		if err := c.Send(line); err != nil {
			fmt.Fprintf(opts.Out, "! %v\n", err)
		}
	}
	return sc.Err()
}

// handleCommand runs a slash command in the relay-less session. It deliberately
// supports the same vocabulary as the TUI for the features §1.1 requires to work
// over direct transport (seal, vanish, ack, decide, roster, scuttle, whoami,
// peers). Returns true when the session should end.
func handleCommand(c *client.Client, co *Coordinator, opts Options, line string) bool {
	cmd, rest, _ := strings.Cut(strings.TrimPrefix(line, "/"), " ")
	rest = strings.TrimSpace(rest)
	switch cmd {
	case "quit", "q", "exit":
		return true
	case "help", "h":
		fmt.Fprintln(opts.Out, "commands: /whoami /peers /decide <text> /ack <tag> /vanish /seal /scuttle /quit")
	case "whoami":
		printWhoami(c, co, opts)
	case "peers":
		printPeers(c, opts.Out)
	case "decide":
		report(opts.Out, c.Decide(rest))
	case "ack":
		report(opts.Out, c.Ack(rest))
	case "vanish":
		c.Vanish()
	case "seal":
		report(opts.Out, c.Seal())
	case "scuttle":
		c.ScuttleNow()
	default:
		fmt.Fprintf(opts.Out, "! unknown command /%s (try /help)\n", cmd)
	}
	return false
}

func printWhoami(c *client.Client, co *Coordinator, opts Options) {
	fmt.Fprintf(opts.Out, "you:        %s (%s)\n", opts.Name, c.Fingerprint())
	fmt.Fprintf(opts.Out, "transport:  %s\n", TransportLabel(c, co))
	fmt.Fprintf(opts.Out, "encryption: end-to-end (XChaCha20-Poly1305 under the room key)\n")
}

func printPeers(c *client.Client, out io.Writer) {
	peers := c.Members()
	if len(peers) == 0 {
		fmt.Fprintln(out, "no other peers connected")
		return
	}
	for _, p := range peers {
		fmt.Fprintf(out, "  %s  %s\n", p.Name, p.Fingerprint)
	}
}

// TransportLabel renders the /whoami transport line: "direct (N peers)" in
// Sneakernet mode, else the relay URL.
func TransportLabel(c *client.Client, co *Coordinator) string {
	t := c.Transport()
	if t == nil {
		return "(not connected)"
	}
	if co != nil {
		n := co.MemberCount() - 1 // exclude self
		return fmt.Sprintf("direct (%s, no relay)", plural(n, "peer"))
	}
	if t.PeerID() != "" {
		return fmt.Sprintf("direct (1 peer %s, no relay)", t.PeerID())
	}
	return "relay (" + t.RemoteAddr() + ")"
}

func printEvent(out io.Writer, ev client.Event) {
	switch e := ev.(type) {
	case client.EvMessage:
		if e.Self {
			return // our own echo; the user already typed it
		}
		fmt.Fprintf(out, "<%s> %s\n", e.FromName, e.Text)
	case client.EvMemberJoined:
		fmt.Fprintf(out, "* %s joined (%s)\n", e.Name, e.Fingerprint)
	case client.EvMemberLeft:
		fmt.Fprintf(out, "* %s left\n", e.Name)
	case client.EvAck:
		fmt.Fprintf(out, "* %s acked %q (%s)\n", e.Actor, e.Tag, e.Quorum)
	case client.EvRecordEntry:
		fmt.Fprintf(out, "* [%s] %s: %s\n", e.Kind, e.AuthorName, e.Body)
	case client.EvSealComplete:
		fmt.Fprintf(out, "* record sealed: %d entries, %d signer(s)\n", e.Entries, e.Signers)
	case client.EvControl:
		fmt.Fprintf(out, "* control: %s by %s\n", e.Action, e.ByName)
	case client.EvScuttleReceipt:
		fmt.Fprintln(out, "* room scuttled — receipt produced (proof of destruction)")
	case client.EvError:
		fmt.Fprintf(out, "! %v\n", e.Err)
	}
}

func report(out io.Writer, err error) {
	if err != nil {
		fmt.Fprintf(out, "! %v\n", err)
	}
}

func waitKeyReady(c *client.Client, timeout time.Duration) error {
	deadline := time.After(timeout)
	for {
		select {
		case ev := <-c.Events():
			if _, ok := ev.(client.EvKeyReady); ok {
				return nil
			}
			if d, ok := ev.(client.EvDisconnected); ok {
				return fmt.Errorf("disconnected before key exchange: %v", d.Err)
			}
		case <-c.Done():
			return fmt.Errorf("connection closed before key exchange")
		case <-deadline:
			return fmt.Errorf("timed out waiting for the room key")
		}
	}
}

// localAddrs returns this host's non-loopback IPv4 addresses joined with port, so a
// peer can reach the listener. Loopback is included last as a fallback for
// same-machine demos.
func localAddrs(port string) []string {
	var addrs []string
	if ifaces, err := net.Interfaces(); err == nil {
		for _, ifc := range ifaces {
			if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
				continue
			}
			adrs, _ := ifc.Addrs()
			for _, a := range adrs {
				ipn, ok := a.(*net.IPNet)
				if !ok {
					continue
				}
				ip4 := ipn.IP.To4()
				if ip4 == nil {
					continue
				}
				addrs = append(addrs, net.JoinHostPort(ip4.String(), port))
			}
		}
	}
	addrs = append(addrs, net.JoinHostPort("127.0.0.1", port))
	return addrs
}

// readBlob reads lines from r until it has a complete armored blob (a line
// starting with "----END"), then parses+verifies it.
func readBlob(r io.Reader) (*Blob, error) {
	sc := bufio.NewScanner(r)
	var sb strings.Builder
	started := false
	for sc.Scan() {
		ln := sc.Text()
		sb.WriteString(ln)
		sb.WriteByte('\n')
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "----BEGIN") {
			started = true
		}
		if started && strings.HasPrefix(t, "----END") {
			break
		}
		if !started && t == "" && sb.Len() > 1 {
			// allow a bare base64 paste terminated by a blank line
			break
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return ParseBlob(sb.String())
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

func atoiSafe(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}
