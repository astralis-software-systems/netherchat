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
	"time"

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
	case "agent":
		agentCmd(os.Args[2:])
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
	_ = fs.Parse(args)

	url := fs.Arg(0)
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
	if err := app.Run(url, *name, *identity, *room, *notify, *invite, *webURL, torDial, loadTrust(*configPath)); err != nil {
		fatal(err)
	}
}

// loadTrust reads the client-side [[trust]] pins from netherchat.toml. Trust is a
// purely client-side concern; a missing or unreadable file just means no pins.
func loadTrust(path string) []app.TrustEntry {
	if path == "" {
		if _, err := os.Stat("netherchat.toml"); err == nil {
			path = "netherchat.toml"
		}
	}
	if path == "" {
		return nil
	}
	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "netherchat: warning: could not read %s for trust pinning: %v\n", path, err)
		return nil
	}
	out := make([]app.TrustEntry, 0, len(cfg.Trust))
	for _, t := range cfg.Trust {
		out = append(out, app.TrustEntry{Handle: t.Handle, Fpr: t.Fpr, KeysURL: t.KeysURL})
	}
	return out
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
  netherchat tail    <room> [--json]             stream messages (or the ndjson event log)
  netherchat agent   --room <room> --allow runbook.toml   run an edge-exec agent
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
