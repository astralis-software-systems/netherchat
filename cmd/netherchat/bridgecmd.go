package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"

	"github.com/salehkreiner/netherchat/tui/bridge"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/output"
)

// bridgeCmd implements `netherchat bridge` (§1.6 — the Two-Way Bridge): it joins a
// room as an ordinary, decrypting E2E member, watches for typed events
// (decision/action/ack/seal/vanish/scuttle), and fires a templated outbound
// callback to the operator's OWN system for each subscribed event. The callback
// carries the original in-room Ed25519 signature (X-Netherchat-Sig) so the
// receiver can attribute the action to a real room member, not a forged curl.
//
// The relay never does this — it is blind and cannot read a decision to act on it.
// That is precisely why the bridge is a client member: provenance flows from the
// in-room signature, not from a server's say-so.
//
// EPHEMERALITY GUARD: retries are in-memory and bounded; there is NO on-disk
// queue. If the bridge process dies, undelivered callbacks die with it. This is
// intentional — a durable queue would re-introduce persistence. For reliable
// delivery, run the bridge on stable infrastructure and make the receiver
// idempotent.
func bridgeCmd(args []string) {
	fs := flag.NewFlagSet("bridge", flag.ExitOnError)
	url := fs.String("server", "ws://localhost:3000", "server URL")
	room := fs.String("room", "", "room to join and watch (required)")
	on := fs.String("on", bridge.DefaultEvents, "comma-separated event types: decision,action,ack,seal,vanish,scuttle")
	post := fs.String("post", "", "URL to POST callbacks to — YOUR OWN system (required)")
	tmplPath := fs.String("template", "", "path to a Go text/template for the POST body (default: built-in JSON)")
	name := fs.String("name", "bridge", "display name in the room")
	identity := fs.String("identity", "", "identity key (generated if not found; default: ssh-agent → ~/.ssh/id_ed25519 → generated)")
	jsonMode := fs.Bool("json", false, "emit an ndjson stream of bridge events (what fired, when, where, status) to stdout")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netherchat bridge --room <room> --on decision,action,ack --post <url> [--template <path>] [--server ws://...] [--name <name>] [--identity <path>] [--json]")
		fmt.Fprintln(os.Stderr, "\nThe bridge joins as a decrypting member and POSTs a signed, templated callback")
		fmt.Fprintln(os.Stderr, "to YOUR system for each subscribed event. --post must be your own endpoint;")
		fmt.Fprintln(os.Stderr, "Astralis makes no outbound calls on your behalf.")
		fmt.Fprintln(os.Stderr, "\nEPHEMERALITY: callbacks are fire-and-forget with in-memory retry only (1s, 2s,")
		fmt.Fprintln(os.Stderr, "4s). If the bridge restarts, pending callbacks are lost — this is intentional;")
		fmt.Fprintln(os.Stderr, "a durable queue would re-introduce persistence. Make your receiver idempotent.")
		fs.PrintDefaults()
	}
	parseFlags("netherchat bridge", fs, args)

	if *room == "" || *post == "" {
		fs.Usage()
		os.Exit(2)
	}
	room0 := strings.TrimPrefix(*room, "#")

	events, err := bridge.ParseEvents(*on)
	if err != nil {
		fatal(err)
	}
	tmpl, err := loadBridgeTemplate(*tmplPath)
	if err != nil {
		fatal(err)
	}

	c := dial(*url, room0, *name, *identity, "", 15*time.Second)
	defer c.Close()

	br, err := bridge.New(bridge.Config{
		Room:     room0,
		On:       events,
		PostURL:  *post,
		Template: tmpl,
		JSON:     *jsonMode,
		Out:      output.Out,
	})
	if err != nil {
		fatal(err)
	}

	fmt.Fprintf(os.Stderr, "netherchat bridge watching #%s as %s (%s) — on %s → %s\n",
		room0, *name, c.Fingerprint(), onSummary(events), *post)
	fmt.Fprintln(os.Stderr, "callbacks are fire-and-forget with in-memory retry only; if this process dies, pending callbacks are lost (by design).")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	for {
		select {
		case ev := <-c.Events():
			switch e := ev.(type) {
			case client.EvKeyReady:
				fmt.Fprintf(os.Stderr, "netherchat bridge: room key established (epoch %d); watching for events\n", e.Epoch)
			case client.EvError:
				fmt.Fprintf(os.Stderr, "netherchat bridge: client error: %v\n", e.Err)
			default:
				if cb, ok := br.Match(ev); ok {
					// Deliver off the event loop: a delivery blocks for the whole retry
					// schedule, and the event loop must keep decrypting in the meantime.
					wg.Add(1)
					go func(cb bridge.Callback) {
						defer wg.Done()
						br.Fire(ctx, cb)
					}(cb)
				}
			}
		case <-c.Done():
			fmt.Fprintln(os.Stderr, "netherchat bridge: disconnected")
			wg.Wait()
			return
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "netherchat bridge: shutting down")
			// Give in-flight deliveries a brief moment to settle; pending retries are
			// cancelled by ctx and reported as failures (never silently dropped).
			waitWithTimeout(&wg, 2*time.Second)
			return
		}
	}
}

// loadBridgeTemplate reads and compiles a custom POST-body template, or returns
// nil so the bridge uses its built-in default.
func loadBridgeTemplate(path string) (*template.Template, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read template %s: %w", path, err)
	}
	t, err := bridge.ParseTemplate(string(b))
	if err != nil {
		return nil, fmt.Errorf("parse template %s: %w", path, err)
	}
	return t, nil
}

// onSummary renders the subscribed event set in the canonical order for the banner.
func onSummary(events map[string]bool) string {
	order := []string{"decision", "action", "ack", "seal", "vanish", "scuttle"}
	var on []string
	for _, e := range order {
		if events[e] {
			on = append(on, e)
		}
	}
	return strings.Join(on, ",")
}

// waitWithTimeout waits for wg, or returns after d — so shutdown never hangs on a
// stuck delivery.
func waitWithTimeout(wg *sync.WaitGroup, d time.Duration) {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
	}
}
