// Command netherchat-alertmanager receives Prometheus Alertmanager webhook POSTs and
// forwards firing alerts to a Netherchat relay as NC-1 metadata alerts (NC-5). It
// runs as a small HTTP server that Alertmanager points a webhook receiver at. It is
// thin typed sugar over the generic ingress socket; removing it removes no core
// functionality.
//
// THE BOUNDARY LAW: only metadata crosses. An alert's `annotations.description` is
// deliberately NEVER read into the alert — only the alertname, instance, severity
// label, and the short `annotations.summary` become the generic alert's metadata.
// Resolved alerts are not forwarded at all. The boundary test in main_test.go proves
// only the seven allowed alert fields appear in the forwarded body.
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
	defaultConfigFile = "netherchat-alertmanager.toml"
	alertKind         = "infra-alert"
	refMax            = 256 // mirrors the relay's per-field cap for `ref`
	maxBody           = 256 << 10
)

// amConfig is the adapter config: the listener, relay coordinates, and the severity
// filter. It never contains message content.
type amConfig struct {
	Listen      string `toml:"listen"`
	Server      string `toml:"server"`
	Source      string `toml:"source"`
	Token       string `toml:"token"`
	HMACSecret  string `toml:"hmac_secret"`
	MinSeverity string `toml:"min_severity"`
}

// amAlert is the slice of an Alertmanager alert we read. `annotations.description`
// is intentionally not given a field, so it can never be read into a forwarded
// alert; extra labels/annotations are ignored by the lenient decode.
type amAlert struct {
	Status      string            `json:"status"` // firing | resolved
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	StartsAt    string            `json:"startsAt"`
}

type amPayload struct {
	Alerts []amAlert `json:"alerts"`
}

// adapter holds the request-handling state. connector.Client is safe for concurrent
// use, so a single adapter serves all inbound webhooks.
type adapter struct {
	client      *connector.Client
	source      string
	minSeverity string
}

func main() {
	fs := flag.NewFlagSet("netherchat-alertmanager", flag.ExitOnError)
	listen := fs.String("listen", "", "address to receive Alertmanager webhooks on (default :8081)")
	server := fs.String("server", "", "relay base URL, e.g. https://relay.example.com")
	source := fs.String("source", "", "registered [[source]] name (default alertmanager)")
	token := fs.String("token", "", "per-source bearer token")
	hmacSecret := fs.String("hmac-secret", "", "per-source HMAC secret (signs each alert)")
	minSeverity := fs.String("min-severity", "", "drop alerts below this severity (info|low|medium|high|critical)")
	configPath := fs.String("config", "", "config file (default: ./"+defaultConfigFile+" if present)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "netherchat-alertmanager — forward Prometheus Alertmanager webhooks to a Netherchat relay (NC-5)")
		fmt.Fprintln(os.Stderr, "\nusage:\n  netherchat-alertmanager --listen :8081 --server <url> --source alertmanager --token <tok>")
		fs.PrintDefaults()
	}
	// No positional arguments: a stray one used to make every flag after it
	// invisible (internal/cliargs). Refuse it rather than start on defaults.
	cliargs.MustParse("netherchat-alertmanager", fs, os.Args[1:], 0)

	cfg := loadConfig(*configPath)
	srv := connector.FirstNonEmpty(*server, cfg.Server)
	if srv == "" {
		fatal(errors.New("--server is required (via flag or config)"))
	}
	src := connector.FirstNonEmpty(*source, cfg.Source, "alertmanager")
	tok := connector.FirstNonEmpty(*token, cfg.Token)
	hmac := connector.FirstNonEmpty(*hmacSecret, cfg.HMACSecret)
	if tok == "" && hmac == "" {
		fmt.Fprintln(os.Stderr, "warning: no token or hmac-secret set — the relay will reject this source")
	}
	addr := connector.FirstNonEmpty(*listen, cfg.Listen, ":8081")

	ad := &adapter{
		client:      &connector.Client{Server: srv, Token: tok, HMACSecret: hmac},
		source:      src,
		minSeverity: connector.FirstNonEmpty(*minSeverity, cfg.MinSeverity),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	mux.HandleFunc("POST /", ad.handle)

	httpSrv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	fmt.Fprintf(os.Stderr, "netherchat-alertmanager: listening on %s, forwarding firing alerts to %s as source %q\n", addr, srv, src)
	if err := httpSrv.ListenAndServe(); err != nil {
		fatal(err)
	}
}

// handle receives one Alertmanager webhook (which may carry several alerts),
// forwards each FIRING alert that meets the severity filter, and reports counts. It
// NEVER echoes the inbound payload.
func (ad *adapter) handle(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	var p amPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		http.Error(w, "bad webhook: "+err.Error(), http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	forwarded, skipped := 0, 0
	for _, al := range p.Alerts {
		// Only firing alerts open a war room. A resolved alert is the all-clear; it
		// never crosses (the second law: detection rings the bell, it does not act).
		if !strings.EqualFold(strings.TrimSpace(al.Status), "firing") {
			skipped++
			continue
		}
		a, ok := translateAlert(al, ad.source)
		if !ok || !connector.MeetsMin(a.Severity, ad.minSeverity) {
			skipped++
			continue
		}
		if _, err := ad.client.Send(ctx, a); err != nil {
			http.Error(w, "forward to relay failed: "+err.Error(), http.StatusBadGateway)
			return
		}
		forwarded++
	}
	writeJSON(w, http.StatusOK, map[string]int{"forwarded": forwarded, "skipped": skipped})
}

// translateAlert maps one firing Alertmanager alert to the generic NC-1 alert. ONLY
// metadata crosses: the description annotation is never read. ok is false when the
// alert has no alertname to key on.
func translateAlert(al amAlert, source string) (connector.Alert, bool) {
	alertname := strings.TrimSpace(al.Labels["alertname"])
	if alertname == "" {
		return connector.Alert{}, false
	}
	instance := strings.TrimSpace(al.Labels["instance"])
	summary := alertname
	if instance != "" {
		summary += " on " + instance
	}
	if s := strings.TrimSpace(al.Annotations["summary"]); s != "" {
		summary += ": " + s
	}
	return connector.Alert{
		Source:   source,
		Severity: mapSeverity(al.Labels["severity"]),
		Kind:     alertKind,
		Summary:  connector.Truncate(summary, connector.SummaryMax),
		Ref:      connector.Truncate(alertname+"_"+al.StartsAt, refMax),
		TS:       connector.ParseRFC3339(al.StartsAt),
	}, true
}

// mapSeverity maps an Alertmanager `severity` label to the canonical five. The
// common Prometheus values map per spec (warning→high, info→low); already-canonical
// values pass through; anything unknown defaults to medium (surfaced, not dropped).
func mapSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "crit", "page", "fatal":
		return "critical"
	case "high":
		return "high"
	case "warning", "warn":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "info", "informational", "information", "none":
		return "low"
	default:
		return "medium"
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func loadConfig(path string) amConfig {
	var cfg amConfig
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
	fmt.Fprintln(os.Stderr, "netherchat-alertmanager: "+err.Error())
	os.Exit(1)
}
