// Command netherchat-siem-adapter receives Splunk or Microsoft Sentinel webhook
// alerts and forwards them to a Netherchat relay as NC-1 metadata alerts (NC-2). It
// runs as a small HTTP server the SIEM points its alert action / playbook at. It is
// thin typed sugar over the generic ingress socket; removing it removes no core
// functionality.
//
// THE BOUNDARY LAW: SIEM payloads are parsed leniently and only a handful of
// metadata fields are extracted (rule/search name, host, severity, time). Raw log
// content (Splunk `result._raw` and friends) and Sentinel `alertContext` are NEVER
// read into the alert, so they cannot cross. The boundary test in main_test.go
// proves only the seven allowed alert fields appear in the forwarded body.
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
	"strconv"
	"strings"
	"time"

	"github.com/salehkreiner/netherchat/connector"
)

const (
	defaultConfigFile = "netherchat-siem.toml"
	alertKind         = "siem-alert"
	refMax            = 256 // mirrors the relay's per-field cap for `ref`
	maxBody           = 256 << 10
)

// siemConfig extends the shared adapter config with the listener and SIEM type.
type siemConfig struct {
	Listen      string `toml:"listen"`
	Server      string `toml:"server"`
	Source      string `toml:"source"`
	Token       string `toml:"token"`
	HMACSecret  string `toml:"hmac_secret"`
	SIEM        string `toml:"siem"`
	MinSeverity string `toml:"min_severity"`
}

// adapter holds the request-handling state. connector.Client is safe for concurrent
// use, so a single adapter serves all inbound webhooks.
type adapter struct {
	client      *connector.Client
	siem        string // "splunk" | "sentinel"
	source      string
	minSeverity string
}

func main() {
	fs := flag.NewFlagSet("netherchat-siem-adapter", flag.ExitOnError)
	listen := fs.String("listen", "", "address to receive SIEM webhooks on (default :8080)")
	server := fs.String("server", "", "relay base URL, e.g. https://relay.example.com")
	source := fs.String("source", "", "registered [[source]] name (default: siem-<siem>)")
	token := fs.String("token", "", "per-source bearer token")
	hmacSecret := fs.String("hmac-secret", "", "per-source HMAC secret (signs each alert)")
	siem := fs.String("siem", "", "siem type: splunk | sentinel")
	minSeverity := fs.String("min-severity", "", "drop alerts below this severity (info|low|medium|high|critical)")
	configPath := fs.String("config", "", "config file (default: ./"+defaultConfigFile+" if present)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "netherchat-siem-adapter — forward Splunk/Sentinel webhooks to a Netherchat relay (NC-2)")
		fmt.Fprintln(os.Stderr, "\nusage:\n  netherchat-siem-adapter --listen :8080 --server <url> --source <name> --token <tok> --siem splunk")
		fs.PrintDefaults()
	}
	_ = fs.Parse(os.Args[1:])

	cfg := loadConfig(*configPath)
	siemType := strings.ToLower(connector.FirstNonEmpty(*siem, cfg.SIEM))
	if siemType != "splunk" && siemType != "sentinel" {
		fatal(errors.New(`--siem must be "splunk" or "sentinel"`))
	}
	srv := connector.FirstNonEmpty(*server, cfg.Server)
	if srv == "" {
		fatal(errors.New("--server is required (via flag or config)"))
	}
	src := connector.FirstNonEmpty(*source, cfg.Source, "siem-"+siemType)
	tok := connector.FirstNonEmpty(*token, cfg.Token)
	hmac := connector.FirstNonEmpty(*hmacSecret, cfg.HMACSecret)
	if tok == "" && hmac == "" {
		fmt.Fprintln(os.Stderr, "warning: no token or hmac-secret set — the relay will reject this source")
	}
	addr := connector.FirstNonEmpty(*listen, cfg.Listen, ":8080")

	ad := &adapter{
		client:      &connector.Client{Server: srv, Token: tok, HMACSecret: hmac},
		siem:        siemType,
		source:      src,
		minSeverity: connector.FirstNonEmpty(*minSeverity, cfg.MinSeverity),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	mux.HandleFunc("POST /", ad.handle)

	httpSrv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	fmt.Fprintf(os.Stderr, "netherchat-siem-adapter: listening on %s, forwarding %s alerts to %s as source %q\n", addr, siemType, srv, src)
	if err := httpSrv.ListenAndServe(); err != nil {
		fatal(err)
	}
}

// handle receives one SIEM webhook, translates it, applies the severity filter, and
// forwards it. It NEVER echoes the inbound payload; only the translated metadata
// alert (or an error) is the response.
func (ad *adapter) handle(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	var a connector.Alert
	switch ad.siem {
	case "splunk":
		a, err = translateSplunk(raw, ad.source)
	case "sentinel":
		a, err = translateSentinel(raw, ad.source)
	default:
		http.Error(w, "adapter misconfigured: unknown siem type", http.StatusInternalServerError)
		return
	}
	if err != nil {
		http.Error(w, "bad webhook: "+err.Error(), http.StatusBadRequest)
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

// translateSplunk extracts only metadata from a Splunk webhook payload. Raw log
// content (result._raw, etc.) is never read into the alert.
func translateSplunk(raw []byte, source string) (connector.Alert, error) {
	var p struct {
		SearchName string         `json:"search_name"`
		Severity   string         `json:"severity"`
		Result     map[string]any `json:"result"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return connector.Alert{}, fmt.Errorf("parse splunk webhook: %w", err)
	}
	if strings.TrimSpace(p.SearchName) == "" {
		return connector.Alert{}, errors.New("splunk webhook missing search_name")
	}
	host := toStr(p.Result["host"])
	if host == "" {
		host = "(unknown host)"
	}
	sev := p.Severity
	if sev == "" {
		sev = toStr(p.Result["severity"])
	}
	timeStr := toStr(p.Result["_time"])
	return connector.Alert{
		Source:   source,
		Severity: mapSplunkSeverity(sev),
		Kind:     alertKind,
		Summary:  connector.Truncate(p.SearchName+" triggered on "+host, connector.SummaryMax),
		Ref:      connector.Truncate(p.SearchName+"_"+timeStr, refMax),
		TS:       parseSplunkTime(timeStr),
	}, nil
}

// translateSentinel extracts only metadata from a Microsoft Sentinel webhook.
// alertContext (the full alert detail) is never read into the alert.
func translateSentinel(raw []byte, source string) (connector.Alert, error) {
	var p struct {
		AlertRule     string `json:"alertRule"`
		Severity      string `json:"severity"`
		FiredDateTime string `json:"firedDateTime"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return connector.Alert{}, fmt.Errorf("parse sentinel webhook: %w", err)
	}
	if strings.TrimSpace(p.AlertRule) == "" {
		return connector.Alert{}, errors.New("sentinel webhook missing alertRule")
	}
	return connector.Alert{
		Source:   source,
		Severity: mapSentinelSeverity(p.Severity),
		Kind:     alertKind,
		Summary:  connector.Truncate(p.AlertRule+" triggered", connector.SummaryMax),
		Ref:      connector.Truncate(p.AlertRule+"_"+p.FiredDateTime, refMax),
		TS:       connector.ParseRFC3339(p.FiredDateTime),
	}, nil
}

// mapSplunkSeverity maps a Splunk severity (string or numeric) to the canonical
// five. Unknown values default to medium (surfaced, not dropped).
func mapSplunkSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "fatal", "severe", "5", "6":
		return "critical"
	case "high", "error", "4":
		return "high"
	case "medium", "warn", "warning", "3":
		return "medium"
	case "low", "notice", "2":
		return "low"
	case "info", "informational", "information", "debug", "0", "1":
		return "info"
	default:
		return "medium"
	}
}

// mapSentinelSeverity maps Sentinel's Sev0–Sev4 (or High/Medium/Low/Informational)
// to the canonical five.
func mapSentinelSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "sev0", "critical":
		return "critical"
	case "sev1", "high":
		return "high"
	case "sev2", "medium":
		return "medium"
	case "sev3", "low":
		return "low"
	case "sev4", "informational", "information", "info":
		return "info"
	default:
		return "medium"
	}
}

// parseSplunkTime parses Splunk's _time, which is epoch seconds (often fractional)
// or, less commonly, RFC3339. Returns 0 when absent/unparseable.
func parseSplunkTime(s string) int64 {
	if s == "" {
		return 0
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return int64(f)
	}
	return connector.ParseRFC3339(s)
}

// toStr renders a scalar JSON value (string or number) from a decoded map.
func toStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func loadConfig(path string) siemConfig {
	var cfg siemConfig
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
	fmt.Fprintln(os.Stderr, "netherchat-siem-adapter: "+err.Error())
	os.Exit(1)
}
