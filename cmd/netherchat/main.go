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
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/server/config"
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
	case "beacon-link":
		beaconLinkCmd(os.Args[2:])
	case "agent":
		agentCmd(os.Args[2:])
	case "bridge":
		bridgeCmd(os.Args[2:])
	case "pair":
		pairCmd(os.Args[2:])
	case "whoami":
		whoamiCmd(os.Args[2:])
	case "verify":
		verifyCmd(os.Args[2:])
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
	configPath := fs.String("config", "", "netherchat.toml for trust pinning (default: ./netherchat.toml if present)")
	useTor := fs.Bool("tor", false, "dial the relay through a local Tor SOCKS5 proxy (for ws://<addr>.onion relays)")
	torProxy := fs.String("tor-proxy", client.DefaultTorProxy, "Tor SOCKS5 proxy address (Tor Browser uses 127.0.0.1:9150)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netherchat connect [ws://host:port] [--room <name>] [--name <you>] [--identity <path>] [--invite <token>] [--tor [--tor-proxy 127.0.0.1:9050]] [--web-url <url>] [--config <toml>] [--notify <cmd>]")
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
	cfg := clientConfig(*configPath)
	if err := app.Run(url, *name, *identity, *room, *notify, *invite, *webURL, torDial, trustOf(cfg), actionQuorums(cfg), beaconTokens(cfg)); err != nil {
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

// clientConfig loads netherchat.toml for the CLIENT-side concerns it cares about —
// [[trust]] pins (/whois) and [action.*] quorum policy (the Two-Person Rule, §1.3).
// Both are evaluated client-side; the relay never reads them. A missing or
// unreadable file is fine: it just means no pins and default (single-actor) quorums.
func clientConfig(path string) config.Config {
	if path == "" {
		if _, err := os.Stat("netherchat.toml"); err == nil {
			path = "netherchat.toml"
		}
	}
	if path == "" {
		return config.Default()
	}
	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "netherchat: warning: could not read %s: %v\n", path, err)
		return config.Default()
	}
	return cfg
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

// dial is the plain-text wrapper: it exits on error.
func dial(url, room, name, identity, invite string, timeout time.Duration) *client.Client {
	c, err := dialErr(url, room, name, identity, invite, timeout)
	if err != nil {
		fatal(err)
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
  netherchat beacon-link <room> [--ttl 2h]       mint a read-only status-beacon link (§1.2)
  netherchat agent   --room <room> --allow runbook.toml   run an edge-exec agent
  netherchat bridge  --room <room> --on decision,ack --post <url>  fire signed callbacks on typed events (§1.6)
  netherchat pair    --lan | --manual [--join]    form a relay-LESS P2P war room (§1.1 Sneakernet)
  netherchat whoami  [--json]                     show your identity
  netherchat verify  <record.json> [--json]       verify a sealed record's hash chain + signatures
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
  netherchat tail alerts | grep CRITICAL`)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "netherchat: "+err.Error())
	os.Exit(1)
}
