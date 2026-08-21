// Command netherchat-findings-adapter forwards generic security findings to a
// Netherchat relay as NC-1 metadata alerts (NC-2). It is thin typed sugar over the
// generic ingress socket: any tool that produces findings in the shape below —
// cloud security scanners, CSPM platforms, vulnerability scanners, infrastructure
// audit tools, pen-test reporters — can feed Netherchat with no core changes, and
// removing this adapter removes no core functionality.
//
// THE BOUNDARY LAW: only metadata crosses. A finding's `description` and
// `remediation` are deliberately NEVER forwarded — they are not even read into the
// alert. Only {check_id, title, resource, severity, finding_id, ts} become the
// generic alert's metadata fields. The boundary test in main_test.go proves it.
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

const (
	defaultConfigFile = "netherchat-findings.toml"
	alertKind         = "security-finding"
)

// finding is the generic security-finding input shape. Description and Remediation
// are parsed only so a strict decode does not reject them — they are NEVER
// forwarded (see translate).
type finding struct {
	FindingID   string `json:"finding_id"`
	Severity    string `json:"severity"`
	CheckID     string `json:"check_id"`
	Resource    string `json:"resource"`
	Region      string `json:"region"`
	Title       string `json:"title"`
	Description string `json:"description"` // NOT forwarded — boundary law
	Remediation string `json:"remediation"` // NOT forwarded — boundary law
	TS          string `json:"ts"`          // RFC3339
}

// translate maps a finding to the generic NC-1 alert. ONLY metadata crosses:
// description and remediation are never read into the Alert. The summary is built
// from check_id/title/resource and truncated to keep it a one-line notice.
func translate(f finding, source string) (connector.Alert, error) {
	if strings.TrimSpace(f.Severity) == "" {
		return connector.Alert{}, errors.New("finding has no severity")
	}
	summary := f.Title
	if f.CheckID != "" {
		summary = f.CheckID + ": " + f.Title
	}
	if f.Resource != "" {
		summary += " (" + f.Resource + ")"
	}
	return connector.Alert{
		Source:   source,
		Severity: strings.ToLower(strings.TrimSpace(f.Severity)),
		Kind:     alertKind,
		Summary:  connector.Truncate(strings.TrimSpace(summary), connector.SummaryMax),
		Ref:      f.FindingID,
		TS:       connector.ParseRFC3339(f.TS),
	}, nil
}

func main() {
	fs := flag.NewFlagSet("netherchat-findings-adapter", flag.ExitOnError)
	findingFile := fs.String("finding", "", "path to a single finding JSON file (omit to read ndjson, one finding per line, from stdin)")
	server := fs.String("server", "", "relay base URL, e.g. https://relay.example.com")
	source := fs.String("source", "", "registered [[source]] name to authenticate as")
	token := fs.String("token", "", "per-source bearer token")
	hmacSecret := fs.String("hmac-secret", "", "per-source HMAC secret (signs each alert)")
	minSeverity := fs.String("min-severity", "", "drop findings below this severity (info|low|medium|high|critical)")
	configPath := fs.String("config", "", "config file (default: ./"+defaultConfigFile+" if present)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "netherchat-findings-adapter — forward security findings to a Netherchat relay (NC-2)")
		fmt.Fprintln(os.Stderr, "\nusage:\n  netherchat-findings-adapter --finding f.json --server <url> --source <name> --token <tok>")
		fmt.Fprintln(os.Stderr, "  my-scanner | netherchat-findings-adapter --server <url> --source <name> --token <tok>")
		fs.PrintDefaults()
	}
	// No positional arguments: a stray one used to make every flag after it
	// invisible (internal/cliargs). Refuse it rather than start on defaults.
	cliargs.MustParse("netherchat-findings-adapter", fs, os.Args[1:], 0)

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

	if *findingFile != "" {
		raw, err := os.ReadFile(*findingFile)
		if err != nil {
			fatal(err)
		}
		if err := processOne(client, raw, eff.Source, eff.MinSeverity); err != nil {
			fatal(err)
		}
		return
	}

	// Pipe mode: ndjson, one finding per line. A bad line is reported and skipped
	// so a stream is not aborted by a single malformed record.
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
		fatal(errors.New("no findings provided (pass --finding or pipe ndjson on stdin)"))
	}
	if failed > 0 {
		os.Exit(1)
	}
}

// processOne parses, filters, translates, and sends a single finding. It decodes
// strictly so an unexpected field fails loudly rather than being silently dropped.
func processOne(client *connector.Client, raw []byte, source, minSeverity string) error {
	f, err := parseFinding(raw)
	if err != nil {
		return err
	}
	if !connector.MeetsMin(f.Severity, minSeverity) {
		fmt.Fprintf(os.Stderr, "skipped %s: severity %q below min %q\n", f.FindingID, f.Severity, minSeverity)
		return nil
	}
	a, err := translate(f, source)
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

func parseFinding(raw []byte) (finding, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var f finding
	if err := dec.Decode(&f); err != nil {
		return finding{}, fmt.Errorf("parse finding: %w", err)
	}
	return f, nil
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
	fmt.Fprintln(os.Stderr, "netherchat-findings-adapter: "+err.Error())
	os.Exit(1)
}
