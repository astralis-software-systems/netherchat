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

// tailCmd implements `netherchat tail <room> [flags]`: it prints decrypted
// messages to stdout, one per line, for piping into grep/tee. Plain text only.
func tailCmd(args []string) {
	fs := flag.NewFlagSet("tail", flag.ExitOnError)
	url := fs.String("server", "ws://localhost:3000", "server URL")
	name := fs.String("name", defaultName(), "display name")
	identity := fs.String("identity", "", "identity file path")
	invite := fs.String("invite", "", "one-time invite token")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netherchat tail <room> [--server ws://...]")
		fs.PrintDefaults()
	}
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fs.Usage()
		os.Exit(2)
	}
	room := strings.TrimPrefix(args[0], "#")
	_ = fs.Parse(args[1:])

	c := dial(*url, room, *name, *identity, *invite, 15*time.Second)
	defer c.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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
