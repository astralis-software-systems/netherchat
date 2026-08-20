package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/salehkreiner/netherchat/server/config"
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
	// Load the client-side [action.*] quorum policy with the same fail-closed
	// provenance as `connect` (§1.3/D5/D6): a broken --config is fatal, absence is
	// legitimate single-actor mode, and either way the active policy is announced so a
	// silent degradation is visible. Parsed here rather than inside pairOptions so a
	// test can drive the flags without a file on disk.
	cfgPath := configFlagIn(args)
	cfg, source, cerr := loadClientConfig(cfgPath)
	if cerr != nil {
		fatal(cerr)
	}
	fmt.Fprintln(os.Stderr, configProvenanceLine(cfg, source))

	opts, mode, err := pairOptions(args, cfg)
	if err != nil {
		fatal(err)
	}
	opts.In, opts.Out = os.Stdin, os.Stdout

	switch mode {
	case pairModeLAN:
		err = sneakernet.RunLAN(opts)
	case pairModeJoin:
		err = sneakernet.RunJoin(opts)
	case pairModeHost:
		err = sneakernet.RunHost(opts)
	default:
		pairUsage(newPairFlagSet(nil))
		os.Exit(2)
	}
	if err != nil {
		fatal(err)
	}
}

// The three things `pair` can be asked to do, plus the absence of an ask.
const (
	pairModeNone = ""
	pairModeLAN  = "lan"
	pairModeJoin = "join"
	pairModeHost = "host"
)

// pairFlags is one parsed command line.
type pairFlags struct {
	lan, manual, join, qr                         bool
	room, name, identity, attestation, configPath string
	port                                          int
}

func newPairFlagSet(f *pairFlags) *flag.FlagSet {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	if f == nil {
		f = &pairFlags{}
	}
	fs.BoolVar(&f.lan, "lan", false, "discover and pair peers on the LAN via mDNS")
	fs.BoolVar(&f.manual, "manual", false, "pair by exchanging a signed offer/answer blob")
	fs.BoolVar(&f.join, "join", false, "manual mode: join by pasting a peer's offer (default is to host/offer)")
	fs.StringVar(&f.room, "room", "ops", "room name")
	fs.StringVar(&f.name, "name", defaultName(), "display name")
	fs.StringVar(&f.identity, "identity", "", "identity key (default: ssh-agent → ~/.ssh/id_ed25519 → generated)")
	fs.IntVar(&f.port, "port", 0, "direct listener port (0 = a free port)")
	fs.BoolVar(&f.qr, "qr", false, "manual mode: also render the offer blob as a scannable QR (§2.4)")
	fs.StringVar(&f.attestation, "attestation", "", "your identity attestation (identity.json), carried to your peer with your presence")
	fs.StringVar(&f.configPath, "config", "", "netherchat.toml for [action.*] quorum policy (default: ./netherchat.toml if present)")
	fs.Usage = func() { pairUsage(fs) }
	return fs
}

func pairUsage(fs *flag.FlagSet) {
	fmt.Fprintln(os.Stderr, "usage: netherchat pair (--lan | --manual [--join]) [--room <name>] [--name <you>] [--identity <path>] [--attestation <identity.json>] [--port N] [--config <toml>]")
	fmt.Fprintln(os.Stderr, "\nForm a relay-LESS war room (§1.1) — no server at all, same E2E crypto.")
	fmt.Fprintln(os.Stderr, "  --lan            discover peers on the local network and /pair one")
	fmt.Fprintln(os.Stderr, "  --manual         print a signed offer; your peer pastes it and connects")
	fmt.Fprintln(os.Stderr, "  --manual --join  paste a peer's offer to connect to them")
	fmt.Fprintln(os.Stderr, "\nNo NAT traversal: peers must share a LAN or be directly reachable (e.g. a VPN).")
	fmt.Fprintln(os.Stderr, "Relay-less scuttle is single-actor: a configured [action.scuttle] quorum >= 2 is REFUSED")
	fmt.Fprintln(os.Stderr, "(no relay to route an approval through). Use the relay for a two-person-gated scuttle.")
	fs.PrintDefaults()
}

// configFlagIn finds --config without consuming the flag set, so the config can
// be loaded before the options that depend on it are built.
func configFlagIn(args []string) string {
	fs := flag.NewFlagSet("pair-config", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var f pairFlags
	fs.BoolVar(&f.lan, "lan", false, "")
	fs.BoolVar(&f.manual, "manual", false, "")
	fs.BoolVar(&f.join, "join", false, "")
	fs.StringVar(&f.room, "room", "", "")
	fs.StringVar(&f.name, "name", "", "")
	fs.StringVar(&f.identity, "identity", "", "")
	fs.IntVar(&f.port, "port", 0, "")
	fs.BoolVar(&f.qr, "qr", false, "")
	fs.StringVar(&f.attestation, "attestation", "", "")
	fs.StringVar(&f.configPath, "config", "", "")
	_ = fs.Parse(args)
	return f.configPath
}

// pairOptions turns a command line and a loaded config into the options the
// Sneakernet session runs on, plus which of the three modes was asked for.
//
// It exists as its own function because the flag is the surface a user touches
// and a test has to start there. --attestation went in during Phase 3b, and the
// gap it closed is the shape roadmap §8 warns about from the other direction:
// the wire had carried a credential since this phase and the artifact ops since
// 3a, and `pair` had no flag to put one on either — so relay-less mode was
// credential-free by omission at the top of the stack while every layer below it
// was ready.
func pairOptions(args []string, cfg config.Config) (sneakernet.Options, string, error) {
	var f pairFlags
	fs := newPairFlagSet(&f)
	_ = fs.Parse(args)

	// [direct] supplies the CLIENT-side Sneakernet defaults (§1.1) the flags do not
	// carry. LAN is OR-ed, never AND-ed: --lan selects the discovery mode outright, so
	// lan_discovery only ADDS mDNS advertising to a --manual host that would otherwise
	// only print an offer blob. A config value must never switch off a mode the
	// operator asked for on the command line.
	opts := sneakernet.Options{
		Room:         strings.TrimPrefix(f.room, "#"),
		Name:         f.name,
		IdentityPath: f.identity,
		Port:         directPort(f.port, cfg.Direct.Port),
		LAN:          directLAN(f.lan, cfg.Direct.LANDiscovery),
		QR:           f.qr,
		ActionQuorum: actionQuorums(cfg),
	}

	// Fail the pair rather than forming a room quietly without it, matching
	// `connect`: an operator who named an attestation asked for it, and a broken
	// one is a mistake to correct rather than a state to join in.
	if f.attestation != "" {
		a, err := readAttestation(f.attestation)
		if err != nil {
			return sneakernet.Options{}, pairModeNone, fmt.Errorf("--attestation: %w", err)
		}
		opts.Credential = a
	}

	switch {
	case f.lan:
		return opts, pairModeLAN, nil
	case f.manual && f.join:
		return opts, pairModeJoin, nil
	case f.manual:
		return opts, pairModeHost, nil
	default:
		return opts, pairModeNone, nil
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
