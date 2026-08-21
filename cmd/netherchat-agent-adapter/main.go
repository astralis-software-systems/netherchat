// Command netherchat-agent-adapter forwards agent lifecycle events to a Netherchat
// relay as NC-1 metadata alerts (NC-W2). Any agentic tool that can emit the event
// shape below — "I produced an artifact", "I ingested sensitive input", "I propose a
// decision", "I detected an anomaly" — can open or update a war room for human review
// with no core changes, and removing this adapter removes no core functionality. It
// is generic: no product name, no special-casing any harness.
//
// THE BOUNDARY LAW: only metadata crosses. The artifact CONTENT is never part of an
// event and never forwarded — `artifact_hash` (hex SHA-256) is its only
// representation, and the input shape has no content field at all. The boundary test
// in main_test.go proves only the seven allowed alert fields appear in the POSTed body.
//
// THE SECOND LAW: an agent event can OPEN/UPDATE a room and seed the proposal context
// for human reviewers; it can never approve, seal, or execute. Approval happens
// inside the E2E room under the Two-Person Rule (NC-W1).
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/salehkreiner/netherchat/connector"
	"github.com/salehkreiner/netherchat/internal/cliargs"
)

const defaultConfigFile = "netherchat-agent.toml"

// validKinds is the closed set of agent event kinds (the NC-1 `kind` field). An
// unknown kind is rejected — a malformed event must not silently spawn a room.
var validKinds = map[string]bool{
	"artifact_produced": true, // agent produced an artifact for review
	"sensitive_ingest":  true, // agent ingested input that may be sensitive
	"decision_proposed": true, // agent proposes a decision for human approval
	"anomaly_detected":  true, // agent detected anomalous behavior
}

// agentEvent is the generic agent lifecycle event. There is, by design, NO content
// field — only metadata about what the agent did. ArtifactHash is the hex SHA-256 of
// any artifact, never the artifact itself.
type agentEvent struct {
	EventID      string `json:"event_id"`
	Severity     string `json:"severity"`
	Kind         string `json:"kind"`
	Source       string `json:"source"`
	ArtifactRef  string `json:"artifact_ref"`
	ArtifactHash string `json:"artifact_hash"`
	Summary      string `json:"summary"`
	TS           string `json:"ts"` // RFC3339
}

// translate maps an agent event to the generic NC-1 alert. ONLY metadata crosses; the
// summary gains a "[hash: <first8>]" tag when an artifact hash is present so reviewers
// can cross-check the artifact, and is capped at 200 chars.
func translate(e agentEvent, source string) (connector.Alert, error) {
	if strings.TrimSpace(e.Severity) == "" {
		return connector.Alert{}, errors.New("agent event has no severity")
	}
	kind := strings.TrimSpace(e.Kind)
	if !validKinds[kind] {
		return connector.Alert{}, fmt.Errorf("unknown agent event kind %q (use artifact_produced|sensitive_ingest|decision_proposed|anomaly_detected)", kind)
	}
	summary := strings.TrimSpace(e.Summary)
	if summary == "" {
		summary = strings.TrimSpace(e.ArtifactRef)
	}
	if summary == "" {
		summary = kind
	}
	if hash := strings.TrimSpace(e.ArtifactHash); hash != "" {
		tag := " [hash: " + shortHash(hash, 8) + "]"
		budget := connector.SummaryMax - len(tag)
		if budget < 0 {
			budget = 0
		}
		summary = connector.Truncate(summary, budget) + tag
	}
	return connector.Alert{
		Source:   source,
		Severity: strings.ToLower(strings.TrimSpace(e.Severity)),
		Kind:     kind,
		Summary:  connector.Truncate(summary, connector.SummaryMax),
		Ref:      e.EventID,
		TS:       connector.ParseRFC3339(e.TS),
	}, nil
}

// shortHash returns the first n characters of a hex hash (no ellipsis — it is a
// reference fragment, not a display truncation).
func shortHash(h string, n int) string {
	if len(h) <= n {
		return h
	}
	return h[:n]
}

func main() {
	fs := flag.NewFlagSet("netherchat-agent-adapter", flag.ExitOnError)
	eventFile := fs.String("event", "", "path to a single agent event JSON file (omit to read ndjson, one event per line, from stdin)")
	server := fs.String("server", "", "relay base URL, e.g. https://relay.example.com")
	source := fs.String("source", "", "registered [[source]] name to authenticate as")
	token := fs.String("token", "", "per-source bearer token")
	hmacSecret := fs.String("hmac-secret", "", "per-source HMAC secret (signs each alert)")
	minSeverity := fs.String("min-severity", "", "drop events below this severity (info|low|medium|high|critical)")
	configPath := fs.String("config", "", "config file (default: ./"+defaultConfigFile+" if present)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "netherchat-agent-adapter — forward agent lifecycle events to a Netherchat relay (NC-W2)")
		fmt.Fprintln(os.Stderr, "\nusage:\n  netherchat-agent-adapter --event e.json --server <url> --source my-agent --token <tok>")
		fmt.Fprintln(os.Stderr, "  my-agent | netherchat-agent-adapter --server <url> --source my-agent --token <tok>")
		fs.PrintDefaults()
	}
	// No positional arguments: a stray one used to make every flag after it
	// invisible (internal/cliargs). Refuse it rather than start on defaults.
	cliargs.MustParse("netherchat-agent-adapter", fs, os.Args[1:], 0)

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

	// Pipe mode: ndjson, one event per line. A bad line is reported and skipped so a
	// stream is not aborted by a single malformed record.
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

// processOne parses, filters, translates, and sends a single agent event. It decodes
// strictly so an unexpected field fails loudly rather than being silently dropped.
// For an artifact_produced event that spawned a room, it surfaces the exact
// `netherchat propose` command that seeds the human-approval flow (NC-W1).
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
	if e.Kind == "artifact_produced" && strings.TrimSpace(e.ArtifactHash) != "" && res.Spawned {
		// Seed the human-approval flow: print the exact propose command for the spawned
		// room. Proposing rides the E2E room (NC-W1), so it is a deliberate next step,
		// not an inbound action — the second law holds (an agent never self-approves).
		fmt.Fprintf(os.Stderr, "artifact_produced → seed the approval flow in room %s with:\n  netherchat propose --room %s --source %s --ref %q --hash %s\n",
			res.Room, res.Room, source, e.ArtifactRef, e.ArtifactHash)
	}
	return nil
}

func parseEvent(raw []byte) (agentEvent, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var e agentEvent
	if err := dec.Decode(&e); err != nil {
		return agentEvent{}, fmt.Errorf("parse agent event: %w", err)
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
	fmt.Fprintln(os.Stderr, "netherchat-agent-adapter: "+err.Error())
	os.Exit(1)
}
