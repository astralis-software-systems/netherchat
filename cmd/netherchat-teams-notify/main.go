// Command netherchat-teams-notify posts Microsoft Teams notices when a Netherchat
// war room opens, seals, or scuttles (NC-3, outbound notify). It follows the
// two-way bridge pattern (tui/bridge): it joins the room as an ordinary,
// DECRYPTING member and reacts to typed events — but instead of a generic signed
// callback it renders a Teams Adaptive Card and POSTs it to an incoming webhook.
//
// THE BOUNDARY LAW: a card carries only a pointer (a one-time join link) and
// metadata (room, severity, source, actor, a record/receipt hash, elapsed time,
// reason). It NEVER carries message content, decision text, or the transcript.
// Although this process can decrypt the room (it is a member), the card mappers
// read only event metadata — the seal card uses the chain head hash and signer
// count, never the sealed decisions. The boundary test proves no entry body leaks.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/salehkreiner/netherchat/connector"
	"github.com/salehkreiner/netherchat/internal/cliargs"
	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/teams"
	"github.com/salehkreiner/netherchat/tui/client"
)

const defaultConfigFile = "netherchat-teams.toml"

// validNotifyEvents is the closed set of events the Teams notifier understands.
var validNotifyEvents = map[string]bool{"open": true, "seal": true, "scuttle": true}

type notifyConfig struct {
	Room       string   `toml:"room"`
	WebhookURL string   `toml:"webhook_url"`
	On         []string `toml:"on"`
	Server     string   `toml:"server"`
	Name       string   `toml:"name"`
	Identity   string   `toml:"identity"`
	WebURL     string   `toml:"web_url"`
	Invite     string   `toml:"invite"`
}

// openPending holds the alert metadata captured from a room's ingress notice while
// the notifier waits for a one-time invite token to mint the join link.
type openPending struct {
	severity string
	source   string
}

// notifier maps decrypted room events to Teams cards. requestInvite and
// clockElapsed are injected (the live client's methods in main, stubs in tests).
type notifier struct {
	room    string
	on      map[string]bool
	webBase string
	expires string // room TTL captured at connect, shown on the open card

	requestInvite func()
	clockElapsed  func() (time.Duration, bool, bool)

	pendingOpen   *openPending
	lastScuttleBy string
}

// cards returns the Teams cards to POST for one client event (usually zero or one).
// It is the whole event→card policy, kept free of I/O so it is unit-testable.
func (n *notifier) cards(ev client.Event) [][]byte {
	switch e := ev.(type) {
	case client.EvConnected:
		n.expires = formatExpires(e.TTLSeconds)
		return nil

	case client.EvServerMessage:
		// The relay posts a marked-plaintext "alert" notice into a war room it opened
		// (NC-1). That is our "open" trigger; we mint a one-time link to put on the card.
		if e.Kind != "alert" || !n.on["open"] {
			return nil
		}
		sev, src := parseAlertNotice(e.Text)
		n.pendingOpen = &openPending{severity: sev, source: src}
		n.requestInvite()
		return nil

	case client.EvInvite:
		if n.pendingOpen == nil {
			return nil
		}
		p := n.pendingOpen
		n.pendingOpen = nil
		card := teams.OpenCard(teams.OpenMeta{
			Room: e.Room, Severity: p.severity, Source: p.source, Actor: "ingress",
			JoinURL: joinLink(n.webBase, e.Room, e.Token), Expires: n.expires,
		})
		return [][]byte{card}

	case client.EvSealComplete:
		if !n.on["seal"] {
			return nil
		}
		return [][]byte{n.sealCard(e)}

	case client.EvControl:
		// Capture who scuttled (a display name); the receipt that follows carries the
		// reason and the proof hash.
		if e.Action == protocol.ActionScuttle {
			n.lastScuttleBy = e.ByName
		}
		return nil

	case client.EvScuttleReceipt:
		if !n.on["scuttle"] {
			return nil
		}
		return [][]byte{n.scuttleCard(e)}
	}
	return nil
}

// sealCard builds the seal card from ONLY the record's metadata — the head hash and
// the signer count. It never touches the sealed entries (the decisions).
func (n *notifier) sealCard(e client.EvSealComplete) []byte {
	hash, signers := "", e.Signers
	if e.Record != nil {
		hash = e.Record.HeadHash
		if signers == 0 {
			signers = len(e.Record.Signatures)
		}
	}
	elapsed := ""
	if d, _, ok := n.clockElapsed(); ok {
		elapsed = formatDuration(d)
	}
	return teams.SealCard(teams.SealMeta{Room: n.room, Signers: signers, RecordHash: hash, Elapsed: elapsed})
}

// scuttleCard builds the scuttle card from the signed receipt's metadata.
func (n *notifier) scuttleCard(e client.EvScuttleReceipt) []byte {
	actor, reason, hash := n.lastScuttleBy, "", ""
	if e.Receipt != nil {
		reason = e.Receipt.Reason
		hash = e.Receipt.ReceiptHash
		if actor == "" {
			actor = e.Receipt.ScuttledBy
		}
	}
	return teams.ScuttleCard(teams.ScuttleMeta{Room: n.room, Actor: actor, Reason: reason, ReceiptHash: hash})
}

func main() {
	fs := flag.NewFlagSet("netherchat-teams-notify", flag.ExitOnError)
	room := fs.String("room", "", "room to watch and notify Teams about")
	webhook := fs.String("webhook", "", "Teams incoming webhook URL")
	on := fs.String("on", "", "comma-separated events: open,seal,scuttle")
	server := fs.String("server", "", "relay URL (default ws://localhost:3000)")
	name := fs.String("name", "", "display name in the room (default teams-bridge)")
	identity := fs.String("identity", "", "identity key file")
	webURL := fs.String("web-url", "", "base URL of the browser join client (default: derived from --server)")
	invite := fs.String("invite", "", "one-time invite token, if the watched room is invite-only")
	configPath := fs.String("config", "", "config file (default: ./"+defaultConfigFile+" if present)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "netherchat-teams-notify — post Teams Adaptive Cards on room open/seal/scuttle (NC-3)")
		fmt.Fprintln(os.Stderr, "\nusage:\n  netherchat-teams-notify --room ops --webhook <teams-url> --on open,seal,scuttle --server ws://...")
		fs.PrintDefaults()
	}
	// No positional arguments: a stray one used to make every flag after it
	// invisible (internal/cliargs). Refuse it rather than start on defaults.
	cliargs.MustParse("netherchat-teams-notify", fs, os.Args[1:], 0)

	cfg := loadConfig(*configPath)
	room0 := strings.TrimPrefix(connector.FirstNonEmpty(*room, cfg.Room), "#")
	webhookURL := connector.FirstNonEmpty(*webhook, cfg.WebhookURL)
	srv := connector.FirstNonEmpty(*server, cfg.Server, "ws://localhost:3000")
	dispName := connector.FirstNonEmpty(*name, cfg.Name, "teams-bridge")
	onSet, err := parseEvents(connector.FirstNonEmpty(*on, strings.Join(cfg.On, ",")))
	if err != nil {
		fatal(err)
	}
	if room0 == "" || webhookURL == "" {
		fatal(fmt.Errorf("--room and --webhook are required (via flags or config)"))
	}

	c, err := client.New(srv, room0, dispName, connector.FirstNonEmpty(*identity, cfg.Identity))
	if err != nil {
		fatal(err)
	}
	defer c.Close()
	if tok := connector.FirstNonEmpty(*invite, cfg.Invite); tok != "" {
		c.UseInviteToken(tok)
	}
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 15*time.Second)
	connErr := c.Connect(dialCtx)
	dialCancel()
	if connErr != nil {
		fatal(connErr)
	}

	n := &notifier{
		room: room0, on: onSet,
		webBase:       webBaseFor(srv, connector.FirstNonEmpty(*webURL, cfg.WebURL)),
		requestInvite: c.RequestInvite,
		clockElapsed:  c.ClockElapsed,
	}
	httpClient := &http.Client{Timeout: 10 * time.Second}

	fmt.Fprintf(os.Stderr, "netherchat-teams-notify watching #%s as %s (%s) — on %s → Teams\n",
		room0, dispName, c.Fingerprint(), strings.Join(sortedEvents(onSet), ","))
	fmt.Fprintln(os.Stderr, "cards are fire-and-forget with no on-disk queue; if this process dies, pending cards are lost (by design).")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var wg sync.WaitGroup
	for {
		select {
		case ev := <-c.Events():
			switch e := ev.(type) {
			case client.EvError:
				fmt.Fprintf(os.Stderr, "netherchat-teams-notify: client error: %v\n", e.Err)
			case client.EvKeyReady:
				fmt.Fprintf(os.Stderr, "netherchat-teams-notify: room key established (epoch %d)\n", e.Epoch)
			}
			for _, card := range n.cards(ev) {
				wg.Add(1)
				go func(card []byte) {
					defer wg.Done()
					if err := teams.Post(ctx, httpClient, webhookURL, card); err != nil {
						fmt.Fprintf(os.Stderr, "netherchat-teams-notify: post failed: %v\n", err)
					}
				}(card)
			}
		case <-c.Done():
			fmt.Fprintln(os.Stderr, "netherchat-teams-notify: disconnected")
			wg.Wait()
			return
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "netherchat-teams-notify: shutting down")
			waitWithTimeout(&wg, 2*time.Second)
			return
		}
	}
}

// parseAlertNotice extracts the severity and source from a relay alert notice of
// the form "[<severity>] <source>/<kind>: <summary>". Best-effort: missing pieces
// come back empty.
func parseAlertNotice(s string) (severity, source string) {
	if !strings.HasPrefix(s, "[") {
		return "", ""
	}
	end := strings.Index(s, "]")
	if end < 0 {
		return "", ""
	}
	severity = strings.TrimSpace(s[1:end])
	rest := strings.TrimSpace(s[end+1:])
	if slash := strings.Index(rest, "/"); slash >= 0 {
		source = strings.TrimSpace(rest[:slash])
	}
	return severity, source
}

func parseEvents(s string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		if !validNotifyEvents[p] {
			return nil, fmt.Errorf("unknown event %q (valid: open, seal, scuttle)", p)
		}
		out[p] = true
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no events given to --on (valid: open, seal, scuttle)")
	}
	return out, nil
}

func sortedEvents(on map[string]bool) []string {
	var out []string
	for _, e := range []string{"open", "seal", "scuttle"} {
		if on[e] {
			out = append(out, e)
		}
	}
	return out
}

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

func joinLink(base, room, token string) string {
	base = strings.TrimRight(base, "/")
	q := url.Values{"room": {room}, "token": {token}}
	return base + "/join?" + q.Encode()
}

func formatExpires(sec int) string {
	if sec <= 0 {
		return "no fixed expiry"
	}
	return formatDuration(time.Duration(sec) * time.Second)
}

func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	return d.Truncate(time.Second).String()
}

func loadConfig(path string) notifyConfig {
	var cfg notifyConfig
	if path == "" {
		if _, err := os.Stat(defaultConfigFile); err == nil {
			path = defaultConfigFile
		}
	}
	if path == "" {
		return cfg
	}
	if err := connector.LoadInto(path, &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not read %s: %v\n", path, err)
	}
	return cfg
}

func waitWithTimeout(wg *sync.WaitGroup, d time.Duration) {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "netherchat-teams-notify: "+err.Error())
	os.Exit(1)
}
