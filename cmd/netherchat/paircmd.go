package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/salehkreiner/netherchat/tui/sneakernet"
)

// pairCmd implements `netherchat pair` (§1.1 — Sneakernet Mode): form a relay-LESS
// war room with no server at all. --lan discovers peers on the local network via
// mDNS; --manual exchanges a signed, copy-pasteable offer/answer blob (for VPNs or
// any directly-reachable network). The same BYO-key identity, NaCl group crypto,
// epoch forward secrecy, and sealed records apply — only the transport changes.
//
// Honest scope: there is NO NAT traversal. Peers must share a LAN or be directly
// reachable by the addresses in the offer (a VPN, the same network, or a
// port-forward). General internet P2P needs a STUN/TURN rendezvous server, which
// re-introduces the infrastructure and trusted third party Sneakernet exists to
// avoid. For teams on different networks, use the relay (the default mode).
func pairCmd(args []string) {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	lan := fs.Bool("lan", false, "discover and pair peers on the LAN via mDNS")
	manual := fs.Bool("manual", false, "pair by exchanging a signed offer/answer blob")
	join := fs.Bool("join", false, "manual mode: join by pasting a peer's offer (default is to host/offer)")
	room := fs.String("room", "ops", "room name")
	name := fs.String("name", defaultName(), "display name")
	identity := fs.String("identity", "", "identity key (default: ssh-agent → ~/.ssh/id_ed25519 → generated)")
	port := fs.Int("port", 0, "direct listener port (0 = a free port)")
	qrFlag := fs.Bool("qr", false, "manual mode: also render the offer blob as a scannable QR (§2.4)")
	configPath := fs.String("config", "", "netherchat.toml for [action.*] quorum policy (default: ./netherchat.toml if present)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netherchat pair (--lan | --manual [--join]) [--room <name>] [--name <you>] [--identity <path>] [--port N] [--config <toml>]")
		fmt.Fprintln(os.Stderr, "\nForm a relay-LESS war room (§1.1) — no server at all, same E2E crypto.")
		fmt.Fprintln(os.Stderr, "  --lan            discover peers on the local network and /pair one")
		fmt.Fprintln(os.Stderr, "  --manual         print a signed offer; your peer pastes it and connects")
		fmt.Fprintln(os.Stderr, "  --manual --join  paste a peer's offer to connect to them")
		fmt.Fprintln(os.Stderr, "\nNo NAT traversal: peers must share a LAN or be directly reachable (e.g. a VPN).")
		fmt.Fprintln(os.Stderr, "Relay-less scuttle is single-actor: a configured [action.scuttle] quorum >= 2 is REFUSED")
		fmt.Fprintln(os.Stderr, "(no relay to route an approval through). Use the relay for a two-person-gated scuttle.")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	// Load the client-side [action.*] quorum policy with the same fail-closed
	// provenance as `connect` (§1.3/D5/D6): a broken --config is fatal, absence is
	// legitimate single-actor mode, and either way the active policy is announced so a
	// silent degradation is visible.
	cfg, source, cerr := loadClientConfig(*configPath)
	if cerr != nil {
		fatal(cerr)
	}
	fmt.Fprintln(os.Stderr, configProvenanceLine(cfg, source))

	// [direct] supplies the CLIENT-side Sneakernet defaults (§1.1) the flags do not
	// carry. LAN is OR-ed, never AND-ed: --lan selects the discovery mode outright, so
	// lan_discovery only ADDS mDNS advertising to a --manual host that would otherwise
	// only print an offer blob. A config value must never switch off a mode the
	// operator asked for on the command line.
	opts := sneakernet.Options{
		Room:         strings.TrimPrefix(*room, "#"),
		Name:         *name,
		IdentityPath: *identity,
		Port:         directPort(*port, cfg.Direct.Port),
		LAN:          directLAN(*lan, cfg.Direct.LANDiscovery),
		QR:           *qrFlag,
		ActionQuorum: actionQuorums(cfg),
		In:           os.Stdin,
		Out:          os.Stdout,
	}

	var err error
	switch {
	case *lan:
		err = sneakernet.RunLAN(opts)
	case *manual && *join:
		err = sneakernet.RunJoin(opts)
	case *manual:
		err = sneakernet.RunHost(opts)
	default:
		fs.Usage()
		os.Exit(2)
	}
	if err != nil {
		fatal(err)
	}
}

// directPort resolves the direct-listener port from the --port flag and the
// [direct] port default in netherchat.toml. The flag wins when given; 0 (the flag
// default) falls through to the config, and 0 at both levels means "a free port".
//
// Flag-over-config, not config-over-flag: a value the operator typed on this
// invocation is always more specific than a file default.
func directPort(flagPort, cfgPort int) int {
	if flagPort != 0 {
		return flagPort
	}
	return cfgPort
}

// directLAN resolves mDNS advertising from the --lan flag and the [direct]
// lan_discovery default. It is a UNION, deliberately: --lan selects the discovery
// mode outright, while lan_discovery only adds an advertisement to a --manual host
// that would otherwise just print an offer blob. Config can turn advertising on; it
// can never turn off what the operator asked for on the command line.
func directLAN(flagLAN, cfgLAN bool) bool {
	return flagLAN || cfgLAN
}
