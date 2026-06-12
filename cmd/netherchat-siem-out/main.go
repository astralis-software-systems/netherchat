// Command netherchat-siem-out streams metadata-only room events from a Netherchat war
// room to a SIEM, for one unified, tamper-evident audit trail (NC-5). It follows the
// two-way bridge pattern: it joins the room as a decrypting member, and on each typed
// event it extracts ONLY metadata (type, actor, fingerprint, room, timestamp, epoch),
// batches it, and POSTs it to a Splunk HEC, a Microsoft Sentinel collector, or a
// generic JSON endpoint.
//
// THE BOUNDARY LAW: although this process can decrypt the room, the event mapper
// reads only metadata fields — never a message body, a decision, a tag, a reason, or
// any content. The only shape that crosses is siemout.Event, which has no field for
// content, so a batch cannot carry any. The boundary test proves it. Batching is
// in-memory with NO on-disk queue — the same ephemerality guarantee as the room.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/salehkreiner/netherchat/connector"
	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/siemout"
	"github.com/salehkreiner/netherchat/tui/client"
)

const defaultConfigFile = "netherchat-siem-out.toml"

type outConfig struct {
	Room          string `toml:"room"`
	Server        string `toml:"server"`
	Name          string `toml:"name"`
	Identity      string `toml:"identity"`
	SIEM          string `toml:"siem"`
	SIEMURL       string `toml:"siem_url"`
	SIEMToken     string `toml:"siem_token"`
	BatchSize     int    `toml:"batch_size"`
	FlushInterval string `toml:"flush_interval"`
	Invite        string `toml:"invite"`
}

// bridge maps decrypted room events to metadata-only SIEM events. It is kept free of
// I/O so the mapping is unit-testable in isolation.
type bridge struct {
	room string
}

// mapEvent translates one client event to a metadata-only siemout.Event. ok is false
// for events that are not part of the audit trail. It reads ONLY metadata fields —
// there is no path here for a message body, tag, reason, or decision text to cross.
func (br *bridge) mapEvent(ev client.Event, epoch uint64, now time.Time) (siemout.Event, bool) {
	at := func(t time.Time) time.Time {
		if t.IsZero() {
			return now
		}
		return t
	}
	mk := func(typ, actor, fpr string, t time.Time) siemout.Event {
		return siemout.Event{
			Type:      typ,
			Room:      br.room,
			Actor:     actor,
			Fpr:       fpr,
			TS:        at(t).UTC().Format(time.RFC3339),
			RoomEpoch: epoch,
		}
	}
	switch e := ev.(type) {
	case client.EvMemberJoined:
		return mk("join", e.Name, e.Fingerprint, now), true
	case client.EvMemberLeft:
		return mk("leave", e.Name, "", now), true
	case client.EvAck:
		return mk("ack", e.Actor, e.Fpr, e.At), true
	case client.EvControl:
		switch e.Action {
		case protocol.ActionVanish:
			return mk("vanish", e.ByName, "", now), true
		case protocol.ActionScuttle:
			return mk("scuttle", e.ByName, "", now), true
		}
		return siemout.Event{}, false
	case client.EvSealComplete:
		fpr := ""
		if e.Record != nil {
			fpr = e.Record.SealedBy
		}
		return mk("seal", "", fpr, now), true
	case client.EvClockStart:
		return mk("clock_start", e.Actor, e.Fpr, e.At), true
	case client.EvClockStop:
		return mk("clock_stop", e.Actor, e.Fpr, e.At), true
	case client.EvActionRequest:
		return mk("action_request", e.RequesterName, e.RequesterFpr, e.At), true
	case client.EvActionExecuted:
		return mk("action_executed", e.RequesterName, e.RequesterFpr, e.At), true
	case client.EvActionVetoed:
		return mk("action_vetoed", e.VetoerName, e.VetoerFpr, e.At), true
	}
	return siemout.Event{}, false
}

func main() {
	fs := flag.NewFlagSet("netherchat-siem-out", flag.ExitOnError)
	room := fs.String("room", "", "room to stream events from")
	server := fs.String("server", "", "relay URL (default ws://localhost:3000)")
	name := fs.String("name", "", "display name in the room (default siem-out-bridge)")
	identity := fs.String("identity", "", "identity key file")
	invite := fs.String("invite", "", "one-time invite token, if the room is invite-only")
	siem := fs.String("siem", "", "siem type: splunk | sentinel | generic")
	siemURL := fs.String("siem-url", "", "SIEM collector URL")
	siemToken := fs.String("siem-token", "", "SIEM token (Splunk HEC token / Sentinel shared key / generic bearer)")
	batchSize := fs.Int("batch-size", 0, "flush after this many events (default 100)")
	flushInterval := fs.String("flush-interval", "", "flush at least this often (default 5s)")
	configPath := fs.String("config", "", "config file (default: ./"+defaultConfigFile+" if present)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "netherchat-siem-out — stream metadata-only room events to a SIEM (NC-5)")
		fmt.Fprintln(os.Stderr, "\nusage:\n  netherchat-siem-out --room ops --siem splunk --siem-url https://splunk:8088 --siem-token <hec> --server ws://...")
		fs.PrintDefaults()
	}
	_ = fs.Parse(os.Args[1:])

	cfg := loadConfig(*configPath)
	room0 := strings.TrimPrefix(connector.FirstNonEmpty(*room, cfg.Room), "#")
	srv := connector.FirstNonEmpty(*server, cfg.Server, "ws://localhost:3000")
	dispName := connector.FirstNonEmpty(*name, cfg.Name, "siem-out-bridge")
	siemType := connector.FirstNonEmpty(*siem, cfg.SIEM)
	siemDest := connector.FirstNonEmpty(*siemURL, cfg.SIEMURL)
	if room0 == "" || siemType == "" || siemDest == "" {
		fatal(fmt.Errorf("--room, --siem, and --siem-url are required (via flags or config)"))
	}

	sink, err := siemout.NewSink(siemType, siemDest, connector.FirstNonEmpty(*siemToken, cfg.SIEMToken), &http.Client{Timeout: 15 * time.Second})
	if err != nil {
		fatal(err)
	}
	size := *batchSize
	if size == 0 {
		size = cfg.BatchSize
	}
	interval := parseInterval(connector.FirstNonEmpty(*flushInterval, cfg.FlushInterval), 5*time.Second)

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

	// The flush callback delivers a batch in its own goroutine so a slow/unreachable
	// SIEM never stalls the room event loop. Failures are logged and dropped — there
	// is no on-disk queue.
	var wg sync.WaitGroup
	flush := func(events []siemout.Event) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := sink.Send(ctx, events); err != nil {
				fmt.Fprintf(os.Stderr, "netherchat-siem-out: flush of %d event(s) failed: %v\n", len(events), err)
			}
		}()
	}
	batcher := siemout.NewBatcher(size, interval, flush)
	batcherCtx, stopBatcher := context.WithCancel(context.Background())
	go batcher.Run(batcherCtx)

	br := &bridge{room: room0}

	fmt.Fprintf(os.Stderr, "netherchat-siem-out streaming #%s as %s (%s) → %s (batch %d / %s)\n",
		room0, dispName, c.Fingerprint(), siemType, batcher.Size(), interval)
	fmt.Fprintln(os.Stderr, "only metadata crosses (type, actor, fingerprint, room, ts, epoch); batching is in-memory with NO on-disk queue.")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	for {
		select {
		case ev := <-c.Events():
			switch e := ev.(type) {
			case client.EvError:
				fmt.Fprintf(os.Stderr, "netherchat-siem-out: client error: %v\n", e.Err)
			case client.EvKeyReady:
				fmt.Fprintf(os.Stderr, "netherchat-siem-out: room key established (epoch %d)\n", e.Epoch)
			}
			if out, ok := br.mapEvent(ev, c.Epoch(), time.Now()); ok {
				batcher.Add(out)
			}
		case <-c.Done():
			fmt.Fprintln(os.Stderr, "netherchat-siem-out: disconnected")
			stopBatcher() // final flush
			wg.Wait()
			return
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "netherchat-siem-out: shutting down")
			stopBatcher() // final flush of buffered events
			waitWithTimeout(&wg, 5*time.Second)
			return
		}
	}
}

// parseInterval parses a Go duration string, falling back to def on empty/invalid.
func parseInterval(s string, def time.Duration) time.Duration {
	if strings.TrimSpace(s) == "" {
		return def
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d
	}
	return def
}

func loadConfig(path string) outConfig {
	var cfg outConfig
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
	fmt.Fprintln(os.Stderr, "netherchat-siem-out: "+err.Error())
	os.Exit(1)
}
