// Command netherchat-egress-adapter forwards AI/LLM egress signals to a Netherchat
// relay as NC-1 metadata alerts (NC-2). Any tool that monitors AI prompt egress and
// detects sensitive data — credentials, PII, proprietary content — can signal
// Netherchat to open a coordinated response war room. It is thin typed sugar over
// the generic ingress socket; removing it removes no core functionality.
//
// THE BOUNDARY LAW: the actual detected/scrubbed content is NEVER part of this
// signal and NEVER forwarded — by design the signal carries only metadata (an
// event type, the monitored tool, a count, and category labels). The content stays
// local to the egress monitor. The boundary test in main_test.go proves only the
// seven allowed alert fields cross.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/salehkreiner/netherchat/connector"
	"github.com/salehkreiner/netherchat/internal/cliargs"
)

const (
	defaultConfigFile = "netherchat-egress.toml"
	alertKind         = "egress-signal"
)

// egressEvent is the AI egress signal shape. The actual detected content is, by
// design, not a field here — only metadata about what was detected.
type egressEvent struct {
	EventID    string   `json:"event_id"`
	Severity   string   `json:"severity"`
	EventType  string   `json:"event_type"`  // credential_leak | pii_leak | proprietary_leak | sensitive_data
	Tool       string   `json:"tool"`        // the LLM tool being monitored
	ScrubCount int      `json:"scrub_count"` // number of items detected
	Categories []string `json:"categories"`  // e.g. ["api_key","email"] — labels only, never values
	TS         string   `json:"ts"`          // RFC3339
}

// translate maps an egress signal to the generic NC-1 alert. The summary is built
// only from the event type, the monitored tool, the count, and category LABELS —
// never any detected value.
func translate(e egressEvent, source string) (connector.Alert, error) {
	if strings.TrimSpace(e.Severity) == "" {
		return connector.Alert{}, errors.New("egress event has no severity")
	}
	eventType := e.EventType
	if eventType == "" {
		eventType = "sensitive_data"
	}
	tool := e.Tool
	if tool == "" {
		tool = "(unknown tool)"
	}
	summary := eventType + " detected in " + tool + ": " + strconv.Itoa(e.ScrubCount) + " items"
	if len(e.Categories) > 0 {
		summary += " (" + strings.Join(e.Categories, ", ") + ")"
	}
	return connector.Alert{
		Source:   source,
		Severity: strings.ToLower(strings.TrimSpace(e.Severity)),
		Kind:     alertKind,
		Summary:  connector.Truncate(strings.TrimSpace(summary), connector.SummaryMax),
		Ref:      e.EventID,
		TS:       connector.ParseRFC3339(e.TS),
	}, nil
}

func main() {
	fs := flag.NewFlagSet("netherchat-egress-adapter", flag.ExitOnError)
	eventFile := fs.String("event", "", "path to a single egress event JSON file (omit to read ndjson, one event per line, from stdin)")
	server := fs.String("server", "", "relay base URL, e.g. https://relay.example.com")
	source := fs.String("source", "", "registered [[source]] name to authenticate as")
	token := fs.String("token", "", "per-source bearer token")
	hmacSecret := fs.String("hmac-secret", "", "per-source HMAC secret (signs each alert)")
	minSeverity := fs.String("min-severity", "", "drop events below this severity (info|low|medium|high|critical)")
	configPath := fs.String("config", "", "config file (default: ./"+defaultConfigFile+" if present)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "netherchat-egress-adapter — forward AI egress signals to a Netherchat relay (NC-2)")
		fmt.Fprintln(os.Stderr, "\nusage:\n  netherchat-egress-adapter --event e.json --server <url> --source <name> --token <tok>")
		fs.PrintDefaults()
	}
	// No positional arguments: a stray one used to make every flag after it
	// invisible (internal/cliargs). Refuse it rather than start on defaults.
	cliargs.MustParse("netherchat-egress-adapter", fs, os.Args[1:], 0)

	cfg := loadConfig(*configPath)
	eff := connector.Config{
		Server:      connector.FirstNonEmpty(*server, cfg.Server),
		Source:      connector.FirstNonEmpty(*source, cfg.Source),
		Token:       connector.FirstNonEmpty(*token, cfg.Token),
		HMACSecret:  connector.FirstNonEmpty(*hmacSecret, cfg.HMACSecret),
		MinSeverity: connector.FirstNonEmpty(*minSeverity, cfg.MinSeverity),
	}
	if eff.Server == "" || eff.Source == "" {
		fatal(errors.New("--server and --source are required (via flags or config)"))
	}
	if eff.Token == "" && eff.HMACSecret == "" {
		fmt.Fprintln(os.Stderr, "warning: no token or hmac-secret set — the relay will reject this source")
	}

	client := &connector.Client{Server: eff.Server, Token: eff.Token, HMACSecret: eff.HMACSecret}

	if *eventFile != "" {
		raw, err := os.ReadFile(*eventFile)
		if err != nil {
			fatal(err)
		}
		if err := processOne(client, raw, eff.Source, eff.MinSeverity); err != nil {
			fatal(err)
		}
		return
	}

	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	n, failed := 0, 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		n++
		if err := processOne(client, []byte(line), eff.Source, eff.MinSeverity); err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "line %d: %v\n", n, err)
		}
	}
	if err := sc.Err(); err != nil {
		fatal(err)
	}
	if n == 0 {
		fatal(errors.New("no events provided (pass --event or pipe ndjson on stdin)"))
	}
	if failed > 0 {
		os.Exit(1)
	}
}

func processOne(client *connector.Client, raw []byte, source, minSeverity string) error {
	e, err := parseEvent(raw)
	if err != nil {
		return err
	}
	if !connector.MeetsMin(e.Severity, minSeverity) {
		fmt.Fprintf(os.Stderr, "skipped %s: severity %q below min %q\n", e.EventID, e.Severity, minSeverity)
		return nil
	}
	a, err := translate(e, source)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res, err := client.Send(ctx, a)
	if err != nil {
		return err
	}
	connector.PrintResult(os.Stdout, a.Ref, res)
	return nil
}

func parseEvent(raw []byte) (egressEvent, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var e egressEvent
	if err := dec.Decode(&e); err != nil {
		return egressEvent{}, fmt.Errorf("parse egress event: %w", err)
	}
	return e, nil
}

func loadConfig(path string) connector.Config {
	var cfg connector.Config
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

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "netherchat-egress-adapter: "+err.Error())
	os.Exit(1)
}
