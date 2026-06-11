package main

import (
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/salehkreiner/netherchat/tui/qr"
)

// beaconLinkCmd implements `netherchat beacon-link <room> [--ttl 2h]` (§1.2): it
// connects to the room as an ordinary member, derives the beacon key from the room
// key, and prints a read-only beacon URL embedding that key. The key in the URL is
// the ONLY thing needed to read the status — it confers no room membership and
// cannot decrypt messages.
func beaconLinkCmd(args []string) {
	fs := flag.NewFlagSet("beacon-link", flag.ExitOnError)
	server := fs.String("server", "ws://localhost:3000", "server URL")
	name := fs.String("name", defaultName(), "display name")
	identity := fs.String("identity", "", "identity file path")
	invite := fs.String("invite", "", "one-time invite token (for an invite-only room)")
	webURL := fs.String("web-url", "", "base URL of the beacon web page (default: derived from the server URL)")
	ttl := fs.Duration("ttl", time.Hour, "beacon link lifetime (default 1h, max 24h)")
	timeout := fs.Duration("timeout", 10*time.Second, "max time to wait for the room key")
	qrFlag := fs.Bool("qr", false, "also render the link as a scannable terminal QR code (§2.4)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netherchat beacon-link <room> [--ttl 2h] [--qr] [--server ws://...] [--web-url <url>]")
		fs.PrintDefaults()
	}

	// The room is the leading positional; peel it before parsing flags (Go's flag
	// parser stops at the first non-flag argument).
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

	d := *ttl
	if d <= 0 {
		d = time.Hour
	}
	if d > 24*time.Hour {
		d = 24 * time.Hour
	}

	c := dial(*server, room, *name, *identity, *invite, *timeout)
	defer c.Close()
	if err := waitForKey(c, *timeout); err != nil {
		fatal(err)
	}
	key, ok := c.BeaconKeyB64()
	if !ok {
		fatal(errors.New("room key not established; cannot derive the beacon key"))
	}
	link := beaconLinkURL(webBaseFor(*server, *webURL), room, key, int(d.Seconds()))
	fmt.Println(link)
	if *qrFlag {
		if code, ok := qr.Render(link, qr.TerminalWidth()); ok {
			fmt.Println(code)
		} else {
			fmt.Fprintln(os.Stderr, "(terminal too narrow for a QR — share the link above)")
		}
	}
}

// webBaseFor returns the explicit --web-url, or the server URL mapped from ws(s)://
// to http(s):// (path dropped) — the origin that serves the /beacon web page.
func webBaseFor(serverURL, webURL string) string {
	if webURL != "" {
		return webURL
	}
	u, err := url.Parse(serverURL)
	if err != nil || u.Host == "" {
		return serverURL
	}
	switch u.Scheme {
	case "ws":
		u.Scheme = "http"
	case "wss":
		u.Scheme = "https"
	}
	return u.Scheme + "://" + u.Host
}

// beaconLinkURL builds the read-only beacon URL.
func beaconLinkURL(base, room, keyB64 string, ttlSeconds int) string {
	base = strings.TrimRight(base, "/")
	q := url.Values{"room": {room}, "key": {keyB64}, "ttl": {strconv.Itoa(ttlSeconds)}}
	return base + "/beacon?" + q.Encode()
}
