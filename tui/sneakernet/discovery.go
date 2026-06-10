package sneakernet

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/grandcat/zeroconf"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

const (
	mdnsService = "_netherchat._tcp"
	mdnsDomain  = "local."
)

// Advertiser is a running LAN advertisement; Close withdraws it.
type Advertiser struct{ srv *zeroconf.Server }

// Close stops advertising on the LAN.
func (a *Advertiser) Close() {
	if a != nil && a.srv != nil {
		a.srv.Shutdown()
	}
}

// Advertise publishes this peer on the LAN via mDNS (service _netherchat._tcp) so
// other clients watching the same room can discover it (§1.1). The TXT records
// carry the fingerprint, room, and version.
//
// Discovery is NEVER trust. A browser learns an address and a CLAIMED fingerprint;
// the identity is proven only by the Ed25519 auth handshake when the peer is
// /pair-ed, and verified out of band or against a [[trust]] pin. "mDNS tells you
// someone is there; your keys tell you who they are."
func Advertise(id *crypto.Identity, room string, port int) (*Advertiser, error) {
	instance := "netherchat-" + shortName(id.Fingerprint())
	txt := []string{
		"fpr=" + id.Fingerprint(),
		"room=" + room,
		"ver=1",
	}
	srv, err := zeroconf.Register(instance, mdnsService, mdnsDomain, port, txt, nil)
	if err != nil {
		return nil, err
	}
	return &Advertiser{srv: srv}, nil
}

// Peer is a CANDIDATE discovered on the LAN — never automatically trusted. Fpr and
// Room come from the advertisement's TXT records; Addr is a reachable host:port.
type Peer struct {
	Fpr  string
	Room string
	Addr string
}

// Browse discovers Netherchat peers advertising room on the LAN for up to timeout
// (an empty room matches any). mDNS is best-effort: on a network without working
// multicast it simply returns no peers rather than an error — the manual blob path
// is the fallback there.
func Browse(ctx context.Context, room string, timeout time.Duration) ([]Peer, error) {
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		return nil, err
	}
	entries := make(chan *zeroconf.ServiceEntry, 16)
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := resolver.Browse(cctx, mdnsService, mdnsDomain, entries); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var peers []Peer
	for e := range entries { // ranges until the browse context expires
		p, ok := peerFromEntry(e)
		if !ok {
			continue
		}
		if room != "" && p.Room != room {
			continue
		}
		if seen[p.Fpr] {
			continue
		}
		seen[p.Fpr] = true
		peers = append(peers, p)
	}
	return peers, nil
}

func peerFromEntry(e *zeroconf.ServiceEntry) (Peer, bool) {
	var p Peer
	for _, kv := range e.Text {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		switch k {
		case "fpr":
			p.Fpr = v
		case "room":
			p.Room = v
		}
	}
	if p.Fpr == "" || e.Port == 0 {
		return Peer{}, false
	}
	var host string
	switch {
	case len(e.AddrIPv4) > 0:
		host = e.AddrIPv4[0].String()
	case len(e.AddrIPv6) > 0:
		host = e.AddrIPv6[0].String()
	default:
		return Peer{}, false
	}
	p.Addr = net.JoinHostPort(host, strconv.Itoa(e.Port))
	return p, true
}

// shortName derives a DNS-SD-instance-safe label from a fingerprint.
func shortName(fpr string) string {
	s := strings.TrimPrefix(fpr, "SHA256:")
	if len(s) > 8 {
		s = s[:8]
	}
	return strings.NewReplacer("+", "-", "/", "_", "=", "").Replace(s)
}
