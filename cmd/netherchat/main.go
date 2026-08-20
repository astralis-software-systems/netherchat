// Command netherchat is the Netherchat terminal client.
//
//	netherchat connect [ws://host:port] [--room general] [--name alice]
//	netherchat send    <room> "message"        # or pipe stdin
//	netherchat tail    <room>                   # stream decrypted messages
//
// All end-to-end encryption happens here, client-side. The server this connects
// to is a blind relay that never sees plaintext.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/eventlog"
	"github.com/salehkreiner/netherchat/tui/ui/app"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "connect":
		connectCmd(os.Args[2:])
	case "send":
		sendCmd(os.Args[2:])
	case "tail":
		tailCmd(os.Args[2:])
	case "stream":
		streamCmd(os.Args[2:])
	case "beacon-link":
		beaconLinkCmd(os.Args[2:])
	case "agent":
		agentCmd(os.Args[2:])
	case "propose":
		proposeCmd(os.Args[2:])
	case "attest":
		attestCmd(os.Args[2:])
	case "approve-artifact":
		approveArtifactCmd(os.Args[2:])
	case "bridge":
		bridgeCmd(os.Args[2:])
	case "pair":
		pairCmd(os.Args[2:])
	case "engagement":
		engagementCmd(os.Args[2:])
	case "duress":
		duressCmd(os.Args[2:])
	case "status":
		statusCmd(os.Args[2:])
	case "whoami":
		whoamiCmd(os.Args[2:])
	case "verify":
		verifyCmd(os.Args[2:])
	case "report":
		reportCmd(os.Args[2:])
	case "replay":
		replayCmd(os.Args[2:])
	case "rooms":
		roomsCmd(os.Args[2:])
	case "doctor":
		doctorCmd(os.Args[2:])
	case "schema":
		fmt.Print(eventlog.SchemaJSON())
	case "version", "--version", "-v":
		versionCmd(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "netherchat: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func connectCmd(args []string) {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	room := fs.String("room", "general", "room to join")
	name := fs.String("name", defaultName(), "display name")
	identity := fs.String("identity", "", "identity key: an OpenSSH/age key file (default: ssh-agent → ~/.ssh/id_ed25519 → generated)")
	notify := fs.String("notify", "", "shell command to run on each new message (env: NETHERCHAT_ROOM/FROM/TEXT)")
	invite := fs.String("invite", "", "one-time invite token for an invite-only room")
	webURL := fs.String("web-url", "", "base URL of the browser join client for /break-glass links (default: derived from the server URL)")
	configPath := fs.String("config", "", "netherchat.toml for trust pinning and [action.*] quorum policy (default: ./netherchat.toml if present)")
	// A credential about your own key, not a trust anchor: it names who an issuer
	// says you are and which roles you may act under, and it carries no key anyone
	// verifies against. Netherchat has no issuer flag and reads no issuer file.
	attestation := fs.String("attestation", "", "your identity attestation (identity.json), so an artifact approval carries the credential you act under")
	useTor := fs.Bool("tor", false, "dial the relay through a local Tor SOCKS5 proxy (for ws://<addr>.onion relays)")
	torProxy := fs.String("tor-proxy", client.DefaultTorProxy, "Tor SOCKS5 proxy address (Tor Browser uses 127.0.0.1:9150)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netherchat connect [ws://host:port] [--room <name>] [--name <you>] [--identity <path>] [--attestation <identity.json>] [--invite <token>] [--tor [--tor-proxy 127.0.0.1:9050]] [--web-url <url>] [--config <toml>] [--notify <cmd>]")
		fs.PrintDefaults()
	}
	// The server URL is an optional leading positional; peel it off before parsing
	// the flags, or Go's flag parser stops at it and silently ignores --room/--name
	// (so they fall back to defaults — the same reason sendCmd peels its positional
	// room first). This is what made --name lose to defaultName() ($USER).
	var url string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		url, args = args[0], args[1:]
	}
	_ = fs.Parse(args)
	if url == "" {
		url = "ws://localhost:3000"
	}
	torDial := ""
	if *useTor {
		torDial = *torProxy
		if torDial == "" {
			torDial = client.DefaultTorProxy
		}
	}
	cfg, source, cerr := loadClientConfig(*configPath)
	if cerr != nil {
		fatal(cerr) // fail closed: a requested/present config that will not load is an error
	}
	// Same fail-closed posture as the config above, for the same reason: an
	// operator who named an attestation asked for it, and a broken one is a
	// mistake rather than a reason to run quietly without it.
	var credential *attest.IdentityAttestation
	if *attestation != "" {
		a, aerr := readAttestation(*attestation)
		if aerr != nil {
			fatal(aerr)
		}
		credential = a
	}
	fmt.Fprintln(os.Stderr, configProvenanceLine(cfg, source))
	if err := app.Run(url, *name, *identity, *room, *notify, *invite, *webURL, torDial, trustOf(cfg), actionQuorums(cfg), beaconTokens(cfg), cfg.Notify.On, cfg.Macros, credential); err != nil {
		fatal(err)
	}
}

// beaconTokens extracts each room's beacon write token from netherchat.toml so the
// TUI can authorize /beacon set|clear (§1.2). A dedicated beacon_token wins;
// otherwise the room's webhook_token is reused, mirroring the server's BeaconAuth.
func beaconTokens(cfg config.Config) map[string]string {
	out := make(map[string]string, len(cfg.Rooms))
	for name, rc := range cfg.Rooms {
		if tok, ok := rc.BeaconAuth(); ok {
			out[name] = tok
		}
	}
	return out
}

// loadClientConfig resolves the CLIENT-side config — [[trust]] pins (/whois) and
// [action.*] quorum policy (the Two-Person Rule, §1.3) — with FAIL-CLOSED provenance
// (§1.5/D5/D6). explicit is the --config flag value ("" if unset). It returns the
// config, the source it came from ("" = built-in defaults, no file), and an error the
// caller MUST treat as fatal.
//
// The old behavior — warn on a bad config, then silently fall back to single-actor
// defaults — is exactly how a configured quorum silently disabled itself. So:
//   - a config that is explicitly requested (--config) but cannot be read → error
//     (fatal): the operator asked for it and it is broken.
//   - ./netherchat.toml present but unparseable → error (fatal): a present-but-broken
//     config is a mistake, not a reason to run security theater at quorum 1.
//   - genuine absence (no --config and no ./netherchat.toml) → defaults, no error: a
//     user who never configured a quorum is legitimately in single-actor mode. The
//     caller surfaces this loudly (configProvenanceLine) instead of failing.
func loadClientConfig(explicit string) (config.Config, string, error) {
	path := explicit
	if path == "" {
		if _, err := os.Stat("netherchat.toml"); err == nil {
			path = "netherchat.toml"
		}
	}
	if path == "" {
		return config.Default(), "", nil
	}
	cfg, err := config.Load(path)
	if err != nil {
		return config.Default(), path, fmt.Errorf("could not read config %s: %w", path, err)
	}
	return cfg, path, nil
}

// configProvenanceLine renders the startup line stating which config is active and
// the governance policy it resolves, so a silent degradation to single-actor defaults
// is visible rather than inferred (D6). source is loadClientConfig's second return
// ("" = built-in defaults).
func configProvenanceLine(cfg config.Config, source string) string {
	if source == "" {
		return "netherchat: config: none found — running single-actor defaults; [action.*] two-person rules are OFF"
	}
	return fmt.Sprintf("netherchat: config: loaded from %s — governance: %s", source, governanceSummary(cfg))
}

// governanceSummary lists the [action.*] two-person rules that are actually engaged
// (quorum > 1) or disabled (quorum 0); "single-actor" when none is configured above 1.
func governanceSummary(cfg config.Config) string {
	var on []string
	for _, a := range []struct {
		label, key string
	}{
		{"scuttle", protocol.ActionScuttleAction},
		{"break-glass", protocol.ActionBreakGlass},
		{"runbook", protocol.ActionRunbook},
		{"artifact", protocol.ActionArtifact},
	} {
		switch q := cfg.ActionQuorum(a.key); {
		case q == 0:
			on = append(on, a.label+" disabled")
		case q > 1:
			on = append(on, fmt.Sprintf("%s quorum %d", a.label, q))
		}
	}
	if len(on) == 0 {
		return "single-actor (no [action.*] quorum > 1 configured)"
	}
	return strings.Join(on, ", ")
}

// trustOf maps the config's [[trust]] pins into the app's TrustEntry type.
func trustOf(cfg config.Config) []app.TrustEntry {
	out := make([]app.TrustEntry, 0, len(cfg.Trust))
	for _, t := range cfg.Trust {
		out = append(out, app.TrustEntry{Handle: t.Handle, Fpr: t.Fpr, KeysURL: t.KeysURL})
	}
	return out
}

// actionQuorums extracts the per-action quorum policy the TUI gates on (§1.3).
func actionQuorums(cfg config.Config) map[string]int {
	return map[string]int{
		protocol.ActionScuttleAction: cfg.ActionQuorum(protocol.ActionScuttleAction),
		protocol.ActionBreakGlass:    cfg.ActionQuorum(protocol.ActionBreakGlass),
		protocol.ActionRunbook:       cfg.ActionQuorum(protocol.ActionRunbook),
		protocol.ActionArtifact:      cfg.ActionQuorum(protocol.ActionArtifact),
	}
}

func defaultName() string {
	for _, env := range []string{"USER", "USERNAME"} {
		if v := os.Getenv(env); v != "" {
			return v
		}
	}
	return "anon"
}

// dialErr connects a client core for the non-interactive modes, returning an
// error rather than exiting — callers that support --json render the error as
// JSON. An empty identity path means "use the BYO-key cascade".
func dialErr(url, room, name, identity, invite string, timeout time.Duration) (*client.Client, error) {
	c, err := client.New(url, room, name, identity)
	if err != nil {
		return nil, err
	}
	if invite != "" {
		c.UseInviteToken(invite)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		return nil, fmt.Errorf("connect to %s: %w", url, err)
	}
	return c, nil
}

// dial is the plain-text wrapper: it exits on error. On failure it also prints a
// self-explaining hint (self-host, or go relay-less) to stderr. The hint lives here,
// in the plain-text path only — dialErr stays clean so --json/machine-readable
// callers are unaffected. Same error line and exit code as fatal(), plus the hint.
func dial(url, room, name, identity, invite string, timeout time.Duration) *client.Client {
	c, err := dialErr(url, room, name, identity, invite, timeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "netherchat: "+err.Error())
		fmt.Fprintln(os.Stderr, "netherchat: no relay reachable — self-host one (docs/self-hosting.md) or go relay-less: netherchat pair --lan")
		os.Exit(1)
	}
	return c
}

func usage() {
	fmt.Fprintln(os.Stderr, `netherchat — messaging that lives below the surface

usage:
  netherchat connect [ws://host:port] [flags]   open the terminal UI
  netherchat send    <room> "message"           send one message (or pipe stdin)
  netherchat send    --file <path> --room <room> relay a file as a secure artifact transfer
  netherchat tail    <room> [--json]             stream messages (or the ndjson event log)
  netherchat stream  <room> [--lines 200]         pipe a live log into a room as one updating block (§2.2)
  netherchat beacon-link <room> [--ttl 2h]       mint a read-only status-beacon link (§1.2)
  netherchat agent   --room <room> --allow runbook.toml   run an edge-exec agent
  netherchat bridge  --room <room> --on decision,ack --post <url>  fire signed callbacks on typed events (§1.6)
  netherchat pair    --lan | --manual [--join]    form a relay-LESS P2P war room (§1.1 Sneakernet)
  netherchat engagement init --name <n> --consultant <h>   generate a turnkey engagement package (C1)
  netherchat engagement close <dir>               consolidate sealed records into a close report (C1)
  netherchat duress  selftest|beacon|verify|check  coercion-resistant safe response (C2)
  netherchat status  [--format tmux|starship] [--json]   compact war-room segment for your prompt (§2.3)
  netherchat whoami  [--json]                     show your identity
  netherchat verify  <artifact.json> [--json]     verify a sealed record, roster, receipt, or identity attestation
                     identity artifacts, and records carrying them, take --issuer <keys> --at <RFC3339>
                     without --issuer nothing about identity is checked, and nothing about it is claimed
  netherchat report  <record.json> [--format html|md] [--executive]  render a shareable incident timeline (§2.6)
  netherchat replay  <record.json> --into <room>  stream a sealed record into a room for a retro
  netherchat rooms   [--json] [--server ws://...] list active rooms
  netherchat doctor  [--paranoid] [--json]        self-test; --paranoid proves the relay is blind
  netherchat version [--json]                     print version info
  netherchat schema                              print the JSON Schema for the --json event stream

Most subcommands accept --json for machine-readable output.

common flags:
  --server <url>      server URL (send/tail; default ws://localhost:3000)
  --room <name>       room to join (connect)
  --name <you>        display name (default: $USER)
  --identity <path>   OpenSSH/age key file (default: ssh-agent → ~/.ssh/id_ed25519 → generated)
  --invite <token>    one-time invite token for an invite-only room
  --tor               dial through a local Tor SOCKS5 proxy (connect; for .onion relays)

examples:
  netherchat connect ws://localhost:3000 --room ops --name alice
  netherchat connect --tor ws://abc123…onion:80 --room ops --name alice
  echo "build failed on main" | netherchat send ops --server ws://localhost:3000
  netherchat tail alerts | grep CRITICAL

self-hosting:
  the relay is a separate artifact — netherchat-server. install it via the installer's
  -WithServer/--with-server flag or from a release archive, or run it in a container;
  see docs/self-hosting.md. no relay? netherchat pair forms a relay-less war room (§1.1).`)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "netherchat: "+err.Error())
	os.Exit(1)
}

// closeOrFail closes an evidence-producing client and refuses a zero exit status
// when the flush could not deliver what it was holding. what names the thing at
// stake, in the operator's terms ("the approval").
//
// It exits rather than returning an error because it runs from a defer, after the
// command has already printed its success line — and a command that says an
// approval is in the record while it sits unsent in a dead process must not also
// tell the shell it worked. Nothing re-files the entry: no peer holds a claim on
// it, and the proposal that produced it is deleted from every client at quorum.
func closeOrFail(c *client.Client, what string) {
	var u *client.UnflushedError
	if !errors.As(c.Close(), &u) || !u.Evidence() {
		return
	}
	fmt.Fprintf(os.Stderr, "netherchat: %s did NOT reach the room: %v\n", what, u)
	fmt.Fprintln(os.Stderr, "netherchat: it exists only on this machine, and nothing will re-file it")
	os.Exit(1)
}
