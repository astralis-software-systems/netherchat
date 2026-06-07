package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/eventlog"
	"github.com/salehkreiner/netherchat/tui/output"
)

// utf8BOM is the byte-order mark some shells (notably Windows PowerShell)
// prepend to data piped into a process. We strip it from stdin so it never
// leaks into a message.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// sendCmd implements `netherchat send <room> [message] [flags]`. With no message
// argument it reads the message from stdin, so it composes with pipes:
//
//	echo "build failed on main" | netherchat send ops --server ws://host:3000
//
// The room must be the first argument (Go's flag parser stops at the first
// positional, so flags follow the room).
func sendCmd(args []string) {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	url := fs.String("server", "ws://localhost:3000", "server URL")
	name := fs.String("name", defaultName(), "display name")
	identity := fs.String("identity", "", "identity file path")
	invite := fs.String("invite", "", "one-time invite token")
	timeout := fs.Duration("timeout", 10*time.Second, "max time to wait for the room key")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `usage: netherchat send <room> ["message"] [flags]   (reads stdin if no message)`)
		fs.PrintDefaults()
	}
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fs.Usage()
		os.Exit(2)
	}
	room := strings.TrimPrefix(args[0], "#")
	_ = fs.Parse(args[1:])

	msg := strings.Join(fs.Args(), " ")
	if msg == "" {
		b, _ := io.ReadAll(os.Stdin)
		b = bytes.TrimPrefix(b, utf8BOM)
		msg = strings.TrimRight(string(b), "\r\n")
	}
	if msg == "" {
		fatal(errors.New("nothing to send (give a message argument or pipe it via stdin)"))
	}

	c := dial(*url, room, *name, *identity, *invite, *timeout)
	defer c.Close()
	if err := sendAfterKey(c, msg, *timeout); err != nil {
		fatal(err)
	}
}

// sendAfterKey waits until the room key is established, sends the message, then
// allows a brief grace period for the frame to flush (the protocol has no
// delivery ack — send is fire-and-forget to whoever is currently in the room).
func sendAfterKey(c *client.Client, msg string, timeout time.Duration) error {
	deadline := time.After(timeout)
	for {
		select {
		case ev := <-c.Events():
			if _, ok := ev.(client.EvKeyReady); ok {
				if err := c.Send(msg); err != nil {
					return err
				}
				time.Sleep(400 * time.Millisecond)
				return nil
			}
		case <-c.Done():
			return errors.New("disconnected before the room key was established")
		case <-deadline:
			return errors.New("timed out waiting for the room key")
		}
	}
}

// tailCmd implements `netherchat tail <room> [flags]`. By default it prints
// decrypted messages to stdout as plain text (pipe into grep/tee). With --json it
// emits the structured, versioned, metadata-only event stream (§1.7) as ndjson —
// no message bodies unless --include-bodies is also passed.
func tailCmd(args []string) {
	fs := flag.NewFlagSet("tail", flag.ExitOnError)
	url := fs.String("server", "ws://localhost:3000", "server URL")
	name := fs.String("name", defaultName(), "display name")
	identity := fs.String("identity", "", "identity file path")
	invite := fs.String("invite", "", "one-time invite token")
	jsonMode := fs.Bool("json", false, "emit the structured ndjson event stream (metadata only)")
	includeBodies := fs.Bool("include-bodies", false, "with --json, include decrypted message bodies (creates a local content record)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netherchat tail <room> [--json] [--include-bodies] [--server ws://...]")
		fs.PrintDefaults()
	}
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fs.Usage()
		os.Exit(2)
	}
	room := strings.TrimPrefix(args[0], "#")
	_ = fs.Parse(args[1:])

	c, err := dialErr(*url, room, *name, *identity, *invite, 15*time.Second)
	if err != nil {
		output.Fatal(*jsonMode, err)
	}
	defer c.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *jsonMode {
		tailJSON(ctx, c, room, *includeBodies)
		return
	}

	for {
		select {
		case ev := <-c.Events():
			switch e := ev.(type) {
			case client.EvMessage:
				if !e.Self {
					fmt.Printf("%s %s: %s\n", e.At.Format("15:04:05"), e.FromName, e.Text)
				}
			case client.EvServerMessage:
				fmt.Printf("%s %s (plaintext): %s\n", e.At.Format("15:04:05"), e.From, e.Text)
			}
		case <-c.Done():
			fmt.Fprintln(os.Stderr, "netherchat: disconnected")
			return
		case <-ctx.Done():
			return
		}
	}
}

// tailJSON streams the structured event log: each client event is mapped to zero
// or more eventlog events and written as one ndjson line. Bodies are emitted only
// when includeBodies is set.
func tailJSON(ctx context.Context, c *client.Client, room string, includeBodies bool) {
	mapper := eventlog.NewMapper(room, includeBodies)
	for {
		select {
		case ev := <-c.Events():
			for _, e := range mapper.Map(ev) {
				_ = output.WriteJSON(e)
			}
			if _, done := ev.(client.EvDisconnected); done {
				return
			}
		case <-c.Done():
			return
		case <-ctx.Done():
			return
		}
	}
}
