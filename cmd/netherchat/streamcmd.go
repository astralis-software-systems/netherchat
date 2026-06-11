package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/client"
)

// streamCmd implements `tail -f app.log | netherchat stream #room` (§2.2): it joins
// the room as a normal member and pipes stdin into a single live-updating block in
// everyone's TUI — a fixed-size ring buffer flushed every 500ms, never persisted.
// When stdin closes it sends a StreamEnd and exits.
func streamCmd(args []string) {
	fs := flag.NewFlagSet("stream", flag.ExitOnError)
	url := fs.String("server", "ws://localhost:3000", "server URL")
	name := fs.String("name", defaultName(), "display name")
	identity := fs.String("identity", "", "identity key (default: ssh-agent → ~/.ssh/id_ed25519 → generated)")
	invite := fs.String("invite", "", "one-time invite token (for an invite-only room)")
	lines := fs.Int("lines", client.DefaultStreamLines, "ring-buffer size (max 1000)")
	label := fs.String("label", "stdin", "source label shown in the block header")
	timeout := fs.Duration("timeout", 15*time.Second, "max time to wait for the room key")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: tail -f app.log | netherchat stream <room> [--lines 200] [--label app.log] [--server ws://...]")
		fmt.Fprintln(os.Stderr, "\nPipe a live log into a room as a single updating block (§2.2). Streams are")
		fmt.Fprintln(os.Stderr, "live-only and never persisted; joiners see the next update, not history.")
		fs.PrintDefaults()
	}

	// The room is the leading positional; peel it before parsing flags.
	var room string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		room = strings.TrimPrefix(args[0], "#")
		_ = fs.Parse(args[1:])
	} else {
		_ = fs.Parse(args)
	}
	if room == "" {
		fs.Usage()
		os.Exit(2)
	}
	if *label == "stdin" {
		// If stdin is a file (not a tty/pipe), use its basename as a friendlier label.
		if fi, err := os.Stdin.Stat(); err == nil && fi.Mode().IsRegular() && fi.Name() != "" {
			*label = filepath.Base(fi.Name())
		}
	}

	c := dial(*url, room, *name, *identity, *invite, *timeout)
	defer c.Close()
	if err := waitForKey(c, *timeout); err != nil {
		fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st := c.NewStream(*label, *lines)
	fmt.Fprintf(os.Stderr, "streaming to #%s as %s — Ctrl+C or end the pipe to stop\n", room, *name)

	// Drain our own events (the Self echoes) so the client's event channel never
	// blocks the streamer; print periodic progress to stderr.
	go func() {
		for {
			select {
			case <-c.Events():
			case <-ctx.Done():
				return
			case <-c.Done():
				return
			}
		}
	}()
	go progress(ctx, st, room)

	st.Run(ctx, client.ScanLines(ctx, os.Stdin), protocol.StreamEndDisconnected)
	fmt.Fprintf(os.Stderr, "\nstream ended (%d lines sent)\n", st.Sent())
}

// progress prints a periodic "streaming to #ops (N lines sent)" line to stderr.
func progress(ctx context.Context, st *client.Stream, room string) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fmt.Fprintf(os.Stderr, "\rstreaming to #%s (%d lines sent)   ", room, st.Sent())
		}
	}
}
