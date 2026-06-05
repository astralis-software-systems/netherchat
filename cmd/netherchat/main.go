// Command netherchat is the Netherchat terminal client.
//
//	netherchat connect [ws://host:port] [--room general] [--name alice]
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

	"github.com/salehkreiner/netherchat/tui/client"
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
	identity := fs.String("identity", "", "identity file path (default: per-user config dir)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netherchat connect [ws://host:port] [--room <name>] [--name <you>] [--identity <path>]")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	url := fs.Arg(0)
	if url == "" {
		url = "ws://localhost:3000"
	}

	idPath := *identity
	if idPath == "" {
		p, err := client.DefaultIdentityPath()
		if err != nil {
			fatal(fmt.Errorf("resolve identity path: %w", err))
		}
		idPath = p
	}

	c, err := client.New(url, *room, *name, idPath)
	if err != nil {
		fatal(err)
	}

	dialCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := c.Connect(dialCtx); err != nil {
		fatal(fmt.Errorf("connect to %s: %w", url, err))
	}

	if err := app.Run(c, *room, *name, c.Fingerprint()); err != nil {
		fatal(err)
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

func usage() {
	fmt.Fprintln(os.Stderr, `netherchat — messaging that lives below the surface

usage:
  netherchat connect [ws://host:port] [flags]

flags (connect):
  --room <name>       room to join (default "general")
  --name <you>        display name (default: $USER)
  --identity <path>   identity key file (default: per-user config dir)

examples:
  netherchat connect ws://localhost:3000 --room ops --name alice
  netherchat connect wss://chat.example.com`)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "netherchat: "+err.Error())
	os.Exit(1)
}
