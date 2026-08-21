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

	"github.com/salehkreiner/netherchat/internal/cliargs"
	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/eventlog"
	"github.com/salehkreiner/netherchat/tui/output"
)

// utf8BOM is the byte-order mark some shells (notably Windows PowerShell)
// prepend to data piped into a process. We strip it from stdin so it never
// leaks into a message.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// sendCmd implements `netherchat send`. With a positional room it sends a message
// (reading stdin if none is given), so it composes with pipes:
//
//	echo "build failed on main" | netherchat send ops --server ws://host:3000
//
// With --file it relays a local artifact as a secure, end-to-end-encrypted,
// relay-blind transfer (§2.3) — the room then comes from --room:
//
//	netherchat send --file heap.prof --room ops --server ws://host:3000
func sendCmd(args []string) {
	a, fs := parseSendArgs(args)
	if a.room == "" {
		fs.Usage()
		os.Exit(2)
	}

	if a.file != "" {
		c := dial(a.url, a.room, a.name, a.identity, a.invite, a.timeout)
		defer c.Close()
		if err := sendFileAfterKey(c, a.file, a.timeout); err != nil {
			fatal(err)
		}
		return
	}

	msg := a.msg
	if msg == "" {
		b, _ := io.ReadAll(os.Stdin)
		b = bytes.TrimPrefix(b, utf8BOM)
		msg = strings.TrimRight(string(b), "\r\n")
	}
	if msg == "" {
		fatal(errors.New("nothing to send (give a message argument, pipe it via stdin, or use --file)"))
	}

	c := dial(a.url, a.room, a.name, a.identity, a.invite, a.timeout)
	defer c.Close()
	if err := sendAfterKey(c, msg, a.timeout); err != nil {
		fatal(err)
	}
}

// sendArgs is one `netherchat send` command line, resolved.
type sendArgs struct {
	url, room, name, identity, invite, file, msg string
	timeout                                      time.Duration
}

// parseSendArgs turns argv into what sendCmd runs on. It is a separate function
// because the flag is the surface a user touches and a test has to start there
// (roadmap §8) — the same split `runVerify` and `parseConnectFlags` already
// carry, and for the same reason: a flag parsed here and not passed on is
// invisible to a test that begins below this line.
func parseSendArgs(args []string) (sendArgs, *flag.FlagSet) {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	url := fs.String("server", "ws://localhost:3000", "server URL")
	roomFlag := fs.String("room", "", "room (use this with --file, where there is no positional room; with it, every positional is message text)")
	name := fs.String("name", defaultName(), "display name")
	identity := fs.String("identity", "", "identity file path")
	invite := fs.String("invite", "", "one-time invite token")
	file := fs.String("file", "", "relay a local artifact as a secure E2E transfer instead of a message")
	timeout := fs.Duration("timeout", 10*time.Second, "max time to wait for the room key")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `usage:
  netherchat send <room> ["message"]             send a message (reads stdin if no message)
  netherchat send --file <path> --room <room>    relay a file as a secure artifact transfer`)
		fs.PrintDefaults()
	}

	// `send` is the one command with more than one positional — a room and then
	// the message words — and that is what made it the worst case of the
	// flags-after-positionals class. Peeling the leading room and calling
	// fs.Parse on the rest left the parser stopped at the message, so
	//
	//	send airgap "relay is on a LAN" --server ws://192.168.0.203:3000
	//
	// parsed no --server, dialled the DEFAULT relay, and joined the flags into
	// the message — encrypting an --identity path, or a one-time --invite token,
	// into a room as chat text. cliargs.Parse takes the flags wherever they were
	// typed and hands back only the positionals.
	//
	// One consequence, stated because it is a real behaviour change: a message
	// WORD that begins with "-" is now parsed as a flag and rejected instead of
	// being sent. The first such word already was (fs.Parse ran straight into
	// it), so this extends an existing rule rather than inventing one, and "--"
	// passes anything through verbatim: send ops -- --not-a-flag.
	pos := cliargs.Parse(fs, args)

	// The room is --room, or the first positional when --room is absent. The
	// flag is checked FIRST and consumes no positional: --room exists for the
	// form that has no positional room (--file), so when it is given, every
	// positional is message text. Taking pos[0] as the room first and letting
	// --room overwrite it would silently drop a message word into nothing, which
	// is the failure this whole change is about.
	var room string
	switch {
	case *roomFlag != "":
		room = strings.TrimPrefix(*roomFlag, "#")
	case len(pos) > 0:
		room = strings.TrimPrefix(pos[0], "#")
		pos = pos[1:]
	}

	return sendArgs{
		url: *url, room: room, name: *name, identity: *identity,
		invite: *invite, file: *file, timeout: *timeout,
		msg: strings.Join(pos, " "),
	}, fs
}

// sendFileAfterKey waits for the room key, starts a secure artifact transfer, and
// renders progress until it completes or fails (§2.3).
func sendFileAfterKey(c *client.Client, path string, timeout time.Duration) error {
	if err := waitForKey(c, timeout); err != nil {
		return err
	}
	if err := c.SendFile(path); err != nil {
		return err // immediate rejection (unreadable, or over the size cap at offer time)
	}
	for {
		select {
		case ev := <-c.Events():
			switch e := ev.(type) {
			case client.EvFileProgress:
				fmt.Fprintf(os.Stderr, "\rsending %s (%s)... %d%%   ",
					e.Filename, humanSize(e.TotalBytes), pctOf(e.SentChunks, e.TotalChunks))
			case client.EvFileSent:
				fmt.Fprintf(os.Stderr, "\r✓ %s sent (%s, %s)            \n",
					e.Filename, humanSize(e.Size), e.Elapsed.Round(time.Second))
				return nil
			case client.EvFileFailed:
				fmt.Fprintf(os.Stderr, "\r✗ transfer failed: %s            \n", e.Reason)
				return errors.New(e.Reason)
			}
		case <-c.Done():
			return errors.New("disconnected during transfer")
		}
	}
}

// humanSize renders a byte count like "4.2 MB" for transfer progress.
func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}

func pctOf(done, total int) int {
	if total <= 0 {
		return 100
	}
	return done * 100 / total
}

// sendAfterKey waits until the room key is established, sends the message, then
// allows a brief grace period for the frame to flush (the protocol has no
// delivery ack — send is fire-and-forget to whoever is currently in the room).
func sendAfterKey(c *client.Client, msg string, timeout time.Duration) error {
	if err := waitForKey(c, timeout); err != nil {
		return err
	}
	if err := c.Send(msg); err != nil {
		return err
	}
	time.Sleep(400 * time.Millisecond)
	return nil
}

// waitForKey blocks until the room key is established (EvKeyReady), the client
// disconnects, or the timeout elapses. The non-interactive commands (send,
// replay) need the key before they can encrypt anything for the room.
func waitForKey(c *client.Client, timeout time.Duration) error {
	deadline := time.After(timeout)
	for {
		select {
		case ev := <-c.Events():
			if _, ok := ev.(client.EvKeyReady); ok {
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
	// A tail is a room MEMBER: it appears in everyone's participant list and its
	// presence is announced like anyone else's. So it can carry the credential its
	// operator acts under, for the same reason `connect` can — and without this it
	// was the one long-lived participant that structurally could not.
	attestation := fs.String("attestation", "", "your identity attestation (identity.json), carried with your presence")
	jsonMode := fs.Bool("json", false, "emit the structured ndjson event stream (metadata only)")
	includeBodies := fs.Bool("include-bodies", false, "with --json, include decrypted message bodies (creates a local content record)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netherchat tail <room> [--json] [--include-bodies] [--attestation <identity.json>] [--server ws://...]")
		fs.PrintDefaults()
	}
	room := strings.TrimPrefix(parseFlags1("netherchat tail", fs, args), "#")
	if room == "" {
		fs.Usage()
		os.Exit(2)
	}

	// Fatal rather than a quiet join without it, matching `connect` and `pair`.
	var credential *attest.IdentityAttestation
	if *attestation != "" {
		a, aerr := readAttestation(*attestation)
		if aerr != nil {
			output.Fatal(*jsonMode, aerr)
		}
		credential = a
	}

	c, err := dialErr(*url, room, *name, *identity, *invite, 15*time.Second, credential)
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
