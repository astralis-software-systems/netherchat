// Command netherchat-itsm attaches a sealed incident record to a ServiceNow or Jira
// ticket as the authoritative, offline-verifiable artifact (NC-4). It follows the
// two-way bridge pattern: it joins the room as a decrypting member, watches for the
// seal event, and on /seal files the signed record to the configured ticket.
//
// THE BOUNDARY LAW: only the deliberately-sealed record is sent — the same bytes
// `netherchat verify` validates — plus a metadata work note (head hash, signers,
// elapsed, verify command). The room transcript and unsealed message content are
// never in the record and never cross. Ed25519 provenance headers (the sealer's
// signature over the head, checkable against the record) accompany every request.
//
// Delivery is in-memory with bounded retry and NO on-disk queue (the ephemerality
// guarantee). If every attempt fails, the record JSON is printed to stdout so the
// operator can attach it manually — the only fallback, and an operator action.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/salehkreiner/netherchat/connector"
	"github.com/salehkreiner/netherchat/itsm"
	"github.com/salehkreiner/netherchat/tui/client"
)

const defaultConfigFile = "netherchat-itsm.toml"

type itsmConfig struct {
	Room      string `toml:"room"`
	Server    string `toml:"server"`
	Name      string `toml:"name"`
	Identity  string `toml:"identity"`
	ITSM      string `toml:"itsm"`
	ITSMURL   string `toml:"itsm_url"`
	ITSMUser  string `toml:"itsm_user"`
	ITSMToken string `toml:"itsm_token"`
	Ticket    string `toml:"ticket"`
	Invite    string `toml:"invite"`
}

func main() {
	fs := flag.NewFlagSet("netherchat-itsm", flag.ExitOnError)
	room := fs.String("room", "", "room to watch for seal events")
	server := fs.String("server", "", "relay URL (default ws://localhost:3000)")
	name := fs.String("name", "", "display name in the room (default itsm-bridge)")
	identity := fs.String("identity", "", "identity key file")
	invite := fs.String("invite", "", "one-time invite token, if the room is invite-only")
	backend := fs.String("itsm", "", "itsm backend: servicenow | jira")
	itsmURL := fs.String("itsm-url", "", "ITSM base URL")
	itsmUser := fs.String("itsm-user", "", "ITSM user")
	itsmToken := fs.String("itsm-token", "", "ITSM password or API token")
	ticket := fs.String("ticket", "", "incident ticket id (ServiceNow sys_id/number or Jira issue key)")
	configPath := fs.String("config", "", "config file (default: ./"+defaultConfigFile+" if present)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "netherchat-itsm — attach the sealed record to a ServiceNow/Jira ticket on seal (NC-4)")
		fmt.Fprintln(os.Stderr, "\nusage:\n  netherchat-itsm --room ops --itsm servicenow --ticket INC0010001 \\")
		fmt.Fprintln(os.Stderr, "    --itsm-url https://instance.service-now.com --itsm-user admin --itsm-token <tok> --server ws://...")
		fs.PrintDefaults()
	}
	_ = fs.Parse(os.Args[1:])

	cfg := loadConfig(*configPath)
	room0 := strings.TrimPrefix(connector.FirstNonEmpty(*room, cfg.Room), "#")
	srv := connector.FirstNonEmpty(*server, cfg.Server, "ws://localhost:3000")
	dispName := connector.FirstNonEmpty(*name, cfg.Name, "itsm-bridge")
	be := strings.ToLower(connector.FirstNonEmpty(*backend, cfg.ITSM))
	ticketID := connector.FirstNonEmpty(*ticket, cfg.Ticket)
	icfg := itsm.Config{
		URL:   connector.FirstNonEmpty(*itsmURL, cfg.ITSMURL),
		User:  connector.FirstNonEmpty(*itsmUser, cfg.ITSMUser),
		Token: connector.FirstNonEmpty(*itsmToken, cfg.ITSMToken),
	}
	if room0 == "" || ticketID == "" || icfg.URL == "" {
		fatal(fmt.Errorf("--room, --ticket, and --itsm-url are required (via flags or config)"))
	}
	if be != "servicenow" && be != "jira" {
		fatal(fmt.Errorf(`--itsm must be "servicenow" or "jira"`))
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

	fmt.Fprintf(os.Stderr, "netherchat-itsm watching #%s as %s (%s) — on seal → %s ticket %s\n", room0, dispName, c.Fingerprint(), be, ticketID)
	fmt.Fprintln(os.Stderr, "delivery is in-memory with bounded retry and NO on-disk queue; on failure the record is printed to stdout for manual attach.")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var wg sync.WaitGroup
	for {
		select {
		case ev := <-c.Events():
			switch e := ev.(type) {
			case client.EvError:
				fmt.Fprintf(os.Stderr, "netherchat-itsm: client error: %v\n", e.Err)
			case client.EvKeyReady:
				fmt.Fprintf(os.Stderr, "netherchat-itsm: room key established (epoch %d)\n", e.Epoch)
			case client.EvSealComplete:
				elapsed := ""
				if d, _, ok := c.ClockElapsed(); ok {
					elapsed = formatDuration(d)
				}
				record, res, prov, ok := attachmentFor(e, ticketID, elapsed)
				if !ok {
					fmt.Fprintln(os.Stderr, "netherchat-itsm: seal carried no record; nothing to attach")
					continue
				}
				cl, err := itsm.New(be, icfg, prov)
				if err != nil {
					fatal(err)
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					if err := itsm.Deliver(cl, res, record, os.Stdout); err != nil {
						fmt.Fprintf(os.Stderr, "netherchat-itsm: %v\n", err)
					} else {
						fmt.Fprintf(os.Stderr, "netherchat-itsm: attached %s to %s ticket %s\n", res.Filename, be, ticketID)
					}
				}()
			}
		case <-c.Done():
			fmt.Fprintln(os.Stderr, "netherchat-itsm: disconnected")
			wg.Wait()
			return
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "netherchat-itsm: shutting down")
			waitWithTimeout(&wg, 5*time.Second)
			return
		}
	}
}

// attachmentFor builds the attachment, work-note metadata, and provenance from a
// seal event. The attachment is EXACTLY the marshaled sealed record — nothing
// else. Provenance is the sealer's own signature over the head (already in the
// record), so it is checkable against the record's signer keys.
func attachmentFor(e client.EvSealComplete, ticketID, elapsed string) ([]byte, itsm.AttachResult, itsm.Provenance, bool) {
	if e.Record == nil {
		return nil, itsm.AttachResult{}, itsm.Provenance{}, false
	}
	rec := e.Record
	record, err := rec.Marshal()
	if err != nil {
		return nil, itsm.AttachResult{}, itsm.Provenance{}, false
	}
	filename := "netherchat-record-" + safeName(rec.Room) + "-" + strconv.FormatInt(time.Now().Unix(), 10) + ".json"
	signers := e.Signers
	if signers == 0 {
		signers = len(rec.Signatures)
	}
	res := itsm.AttachResult{
		TicketID:  ticketID,
		Filename:  filename,
		HeadHash:  rec.HeadHash,
		Signers:   signers,
		Elapsed:   elapsed,
		VerifyCmd: "netherchat verify " + filename,
	}
	fpr := rec.SealedBy
	sig := rec.Signatures[fpr]
	if sig == "" {
		for f, s := range rec.Signatures {
			fpr, sig = f, s
			break
		}
	}
	prov := itsm.Provenance{Room: rec.Room, Fpr: fpr, Sig: sig, Ts: rec.SealedAt}
	return record, res, prov, true
}

// safeName sanitizes a room name for use in a filename.
func safeName(s string) string {
	if s == "" {
		return "incident"
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, s)
}

func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	return d.Truncate(time.Second).String()
}

func loadConfig(path string) itsmConfig {
	var cfg itsmConfig
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
	fmt.Fprintln(os.Stderr, "netherchat-itsm: "+err.Error())
	os.Exit(1)
}
