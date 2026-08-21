// Command netherchat-paging receives PagerDuty or Opsgenie webhooks and forwards new
// pages to a Netherchat relay as NC-1 metadata alerts (NC-5), so a sealed-record war
// room opens alongside the page (it complements paging, it does not replace it). One
// binary serves both providers via the --pager flag. It is thin typed sugar over the
// generic ingress socket; removing it removes no core functionality.
//
// THE BOUNDARY LAW: only metadata crosses — the page title/message (≤200 chars), the
// mapped severity, and the provider's incident/alert id as a reference. Custom
// details, the responder, the html_url, and any other payload field are never read
// into the alert. Only the page that OPENS (PagerDuty incident.triggered / Opsgenie
// Create) is forwarded; acknowledge/resolve/close never cross. The boundary test in
// main_test.go proves only the seven allowed alert fields appear in the forwarded body.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/salehkreiner/netherchat/connector"
	"github.com/salehkreiner/netherchat/internal/cliargs"
)

const (
	defaultConfigFile = "netherchat-paging.toml"
	alertKind         = "page"
	refMax            = 256
	maxBody           = 256 << 10
)

// pagingConfig is the adapter config: the listener, relay coordinates, the provider,
// and the severity filter. It never contains message content.
type pagingConfig struct {
	Listen      string `toml:"listen"`
	Server      string `toml:"server"`
	Source      string `toml:"source"`
	Token       string `toml:"token"`
	HMACSecret  string `toml:"hmac_secret"`
	Pager       string `toml:"pager"` // pd | opsgenie
	MinSeverity string `toml:"min_severity"`
}

type adapter struct {
	client      *connector.Client
	pager       string // "pd" | "opsgenie"
	source      string
	minSeverity string
}

func main() {
	fs := flag.NewFlagSet("netherchat-paging", flag.ExitOnError)
	listen := fs.String("listen", "", "address to receive paging webhooks on (default :8082)")
	server := fs.String("server", "", "relay base URL, e.g. https://relay.example.com")
	source := fs.String("source", "", "registered [[source]] name (default: paging-<pager>)")
	token := fs.String("token", "", "per-source bearer token")
	hmacSecret := fs.String("hmac-secret", "", "per-source HMAC secret (signs each alert)")
	pager := fs.String("pager", "", "paging provider: pd | opsgenie")
	minSeverity := fs.String("min-severity", "", "drop pages below this severity (info|low|medium|high|critical)")
	configPath := fs.String("config", "", "config file (default: ./"+defaultConfigFile+" if present)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "netherchat-paging — open a war room when a PagerDuty/Opsgenie page fires (NC-5)")
		fmt.Fprintln(os.Stderr, "\nusage:\n  netherchat-paging --listen :8082 --server <url> --source paging --token <tok> --pager pd")
		fs.PrintDefaults()
	}
	// No positional arguments: a stray one used to make every flag after it
	// invisible (internal/cliargs). Refuse it rather than start on defaults.
	cliargs.MustParse("netherchat-paging", fs, os.Args[1:], 0)

	cfg := loadConfig(*configPath)
	pgr := normalizePager(connector.FirstNonEmpty(*pager, cfg.Pager))
	if pgr != "pd" && pgr != "opsgenie" {
		fatal(errors.New(`--pager must be "pd" or "opsgenie"`))
	}
	srv := connector.FirstNonEmpty(*server, cfg.Server)
	if srv == "" {
		fatal(errors.New("--server is required (via flag or config)"))
	}
	src := connector.FirstNonEmpty(*source, cfg.Source, "paging-"+pgr)
	tok := connector.FirstNonEmpty(*token, cfg.Token)
	hmac := connector.FirstNonEmpty(*hmacSecret, cfg.HMACSecret)
	if tok == "" && hmac == "" {
		fmt.Fprintln(os.Stderr, "warning: no token or hmac-secret set — the relay will reject this source")
	}
	addr := connector.FirstNonEmpty(*listen, cfg.Listen, ":8082")

	ad := &adapter{
		client:      &connector.Client{Server: srv, Token: tok, HMACSecret: hmac},
		pager:       pgr,
		source:      src,
		minSeverity: connector.FirstNonEmpty(*minSeverity, cfg.MinSeverity),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	mux.HandleFunc("POST /", ad.handle)

	httpSrv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	fmt.Fprintf(os.Stderr, "netherchat-paging: listening on %s, forwarding %s pages to %s as source %q\n", addr, pgr, srv, src)
	if err := httpSrv.ListenAndServe(); err != nil {
		fatal(err)
	}
}

// handle receives one paging webhook, translates it, applies the severity filter,
// and forwards it. Only a page that OPENS is forwarded; everything else is accepted
// and ignored. It NEVER echoes the inbound payload.
func (ad *adapter) handle(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	var (
		a       connector.Alert
		forward bool
	)
	switch ad.pager {
	case "pd":
		a, forward, err = translatePagerDuty(raw, ad.source)
	case "opsgenie":
		a, forward, err = translateOpsgenie(raw, ad.source)
	default:
		http.Error(w, "adapter misconfigured: unknown pager", http.StatusInternalServerError)
		return
	}
	if err != nil {
		http.Error(w, "bad webhook: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !forward {
		writeJSON(w, http.StatusOK, map[string]any{"accepted": false, "reason": "event does not open a room (only a new page does)"})
		return
	}
	if !connector.MeetsMin(a.Severity, ad.minSeverity) {
		writeJSON(w, http.StatusOK, map[string]any{"accepted": false, "reason": "below min_severity"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	res, err := ad.client.Send(ctx, a)
	if err != nil {
		http.Error(w, "forward to relay failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// pdPayload is the slice of a PagerDuty v3 webhook we read. html_url and any other
// field are intentionally not forwarded.
type pdPayload struct {
	Event struct {
		EventType string `json:"event_type"`
		Data      struct {
			ID      string `json:"id"`
			Title   string `json:"title"`
			Urgency string `json:"urgency"`
			HTMLURL string `json:"html_url"`
		} `json:"data"`
	} `json:"event"`
}

// translatePagerDuty extracts only metadata from a PagerDuty v3 webhook. forward is
// true only for incident.triggered (the event that opens a page).
func translatePagerDuty(raw []byte, source string) (connector.Alert, bool, error) {
	var p pdPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return connector.Alert{}, false, fmt.Errorf("parse pagerduty webhook: %w", err)
	}
	if !strings.EqualFold(p.Event.EventType, "incident.triggered") {
		return connector.Alert{}, false, nil
	}
	d := p.Event.Data
	if strings.TrimSpace(d.Title) == "" && strings.TrimSpace(d.ID) == "" {
		return connector.Alert{}, false, errors.New("pagerduty webhook missing incident data")
	}
	return connector.Alert{
		Source:   source,
		Severity: mapPDUrgency(d.Urgency),
		Kind:     alertKind,
		Summary:  connector.Truncate(strings.TrimSpace(d.Title), connector.SummaryMax),
		Ref:      connector.Truncate(d.ID, refMax),
		TS:       time.Now().Unix(),
	}, true, nil
}

// ogPayload is the slice of an Opsgenie webhook we read.
type ogPayload struct {
	Action string `json:"action"`
	Alert  struct {
		AlertID  string `json:"alertId"`
		Message  string `json:"message"`
		Priority string `json:"priority"`
		Source   string `json:"source"`
	} `json:"alert"`
}

// translateOpsgenie extracts only metadata from an Opsgenie webhook. forward is true
// only for the Create action (a new alert).
func translateOpsgenie(raw []byte, source string) (connector.Alert, bool, error) {
	var p ogPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return connector.Alert{}, false, fmt.Errorf("parse opsgenie webhook: %w", err)
	}
	if !strings.EqualFold(p.Action, "Create") {
		return connector.Alert{}, false, nil
	}
	if strings.TrimSpace(p.Alert.Message) == "" && strings.TrimSpace(p.Alert.AlertID) == "" {
		return connector.Alert{}, false, errors.New("opsgenie webhook missing alert data")
	}
	return connector.Alert{
		Source:   source,
		Severity: mapOGPriority(p.Alert.Priority),
		Kind:     alertKind,
		Summary:  connector.Truncate(strings.TrimSpace(p.Alert.Message), connector.SummaryMax),
		Ref:      connector.Truncate(p.Alert.AlertID, refMax),
		TS:       time.Now().Unix(),
	}, true, nil
}

// mapPDUrgency maps PagerDuty urgency to the canonical five (spec: high→critical,
// low→medium). Unknown defaults to medium.
func mapPDUrgency(u string) string {
	switch strings.ToLower(strings.TrimSpace(u)) {
	case "high":
		return "critical"
	case "low":
		return "medium"
	default:
		return "medium"
	}
}

// mapOGPriority maps Opsgenie P1–P5 to the canonical five (spec: P1→critical,
// P2→high, P3→medium, P4/P5→low). Unknown defaults to medium.
func mapOGPriority(p string) string {
	switch strings.ToUpper(strings.TrimSpace(p)) {
	case "P1":
		return "critical"
	case "P2":
		return "high"
	case "P3":
		return "medium"
	case "P4", "P5":
		return "low"
	default:
		return "medium"
	}
}

// normalizePager accepts a few friendly spellings for each provider.
func normalizePager(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "pd", "pagerduty":
		return "pd"
	case "opsgenie", "og":
		return "opsgenie"
	default:
		return strings.ToLower(strings.TrimSpace(s))
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func loadConfig(path string) pagingConfig {
	var cfg pagingConfig
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
	fmt.Fprintln(os.Stderr, "netherchat-paging: "+err.Error())
	os.Exit(1)
}
