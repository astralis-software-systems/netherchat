// Command netherchat-slack-bot lets a Slack user open a Netherchat war room from a
// channel (NC-5, inbound initiate). It is a small HTTP server that receives a Slack
// slash-command webhook, verifies Slack's v0 request signature, opens a war room via
// the NC-1 ingress socket, and replies with a one-time join link. It is the
// Slack-native twin of netherchat-teams-bot.
//
// THE BOUNDARY LAW: only metadata crosses INTO Netherchat. The bot forwards just a
// parsed severity and a short summary (≤200 chars) plus Slack's opaque trigger_id as
// a reference — never the invoking user, the channel, or any other slash-command
// field. The sensitive discussion then stays entirely E2E inside Netherchat; Slack
// gets back only an ephemeral pointer. The second law holds: the bot can INITIATE a
// room, never approve, seal, or execute inside one.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/salehkreiner/netherchat/connector"
	"github.com/salehkreiner/netherchat/internal/cliargs"
	"github.com/salehkreiner/netherchat/slack"
)

const (
	defaultConfigFile = "netherchat-slack-bot.toml"
	alertKind         = "slack-initiate"
	maxBody           = 64 << 10
	maxSkew           = 5 * time.Minute // reject signatures older than this (replay guard)
)

type botConfig struct {
	Listen             string   `toml:"listen"`
	Server             string   `toml:"server"`
	Source             string   `toml:"source"`
	Token              string   `toml:"token"`
	SlackSigningSecret string   `toml:"slack_signing_secret"`
	DefaultTTL         string   `toml:"default_ttl"`
	DefaultInvitees    []string `toml:"default_invitees"` // informational: the relay [[route]] is authoritative for who is invited
}

// bot holds the request-handling state. connector.Client is safe for concurrent use.
type bot struct {
	client     *connector.Client
	signingKey []byte // Slack signing secret bytes
	source     string
	defaultTTL string
	now        func() time.Time // injectable clock for tests
}

func main() {
	fs := flag.NewFlagSet("netherchat-slack-bot", flag.ExitOnError)
	listen := fs.String("listen", "", "address to receive Slack slash commands on (default :9091)")
	server := fs.String("server", "", "relay base URL, e.g. https://relay.example.com")
	source := fs.String("source", "", "registered [[source]] name (default slack-bot)")
	token := fs.String("token", "", "NC-1 per-source bearer token")
	signingSecret := fs.String("slack-signing-secret", "", "Slack app signing secret (verifies v0 request signatures)")
	configPath := fs.String("config", "", "config file (default: ./"+defaultConfigFile+" if present)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "netherchat-slack-bot — open a Netherchat war room from a Slack slash command (NC-5)")
		fmt.Fprintln(os.Stderr, "\nusage:\n  netherchat-slack-bot --listen :9091 --server https://relay --source slack-bot --token <tok> --slack-signing-secret <secret>")
		fs.PrintDefaults()
	}
	// No positional arguments: a stray one used to make every flag after it
	// invisible (internal/cliargs). Refuse it rather than start on defaults.
	cliargs.MustParse("netherchat-slack-bot", fs, os.Args[1:], 0)

	cfg := loadConfig(*configPath)
	srv := connector.FirstNonEmpty(*server, cfg.Server)
	if srv == "" {
		fatal(errors.New("--server is required (via flag or config)"))
	}
	secret := connector.FirstNonEmpty(*signingSecret, cfg.SlackSigningSecret)
	if secret == "" {
		fatal(errors.New("--slack-signing-secret is required (Slack signs slash commands; unsigned requests are rejected)"))
	}
	addr := connector.FirstNonEmpty(*listen, cfg.Listen, ":9091")

	b := &bot{
		client:     &connector.Client{Server: srv, Token: connector.FirstNonEmpty(*token, cfg.Token)},
		signingKey: []byte(secret),
		source:     connector.FirstNonEmpty(*source, cfg.Source, "slack-bot"),
		defaultTTL: connector.FirstNonEmpty(cfg.DefaultTTL, "2h"),
		now:        time.Now,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	mux.HandleFunc("POST /", b.handle)

	httpSrv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	fmt.Fprintf(os.Stderr, "netherchat-slack-bot: listening on %s, opening rooms on %s as source %q\n", addr, srv, b.source)
	if err := httpSrv.ListenAndServe(); err != nil {
		fatal(err)
	}
}

// handle verifies the Slack signature, parses the command, opens a war room via the
// ingress socket, and replies with an ephemeral join link.
func (b *bot) handle(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	if !b.validSignature(body, r.Header.Get("X-Slack-Request-Timestamp"), r.Header.Get("X-Slack-Signature")) {
		http.Error(w, "invalid or missing Slack signature", http.StatusUnauthorized)
		return
	}

	form, err := url.ParseQuery(string(body))
	if err != nil {
		http.Error(w, "bad slash command payload", http.StatusBadRequest)
		return
	}
	severity, summary, ok := parseCommand(form.Get("text"))
	if !ok {
		writeJSON(w, slack.TextResponse("Unknown command. Use: /netherchat sev1|sev2|sev3|incident|drill <summary>"))
		return
	}
	if strings.TrimSpace(summary) == "" {
		summary = "(no summary provided)"
	}

	alert := connector.Alert{
		Source:   b.source,
		Severity: severity,
		Kind:     alertKind,
		Summary:  connector.Truncate(summary, connector.SummaryMax),
		Ref:      form.Get("trigger_id"), // Slack's opaque request id — metadata, not content
		TS:       b.now().Unix(),
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	res, err := b.client.Send(ctx, alert)
	if err != nil {
		writeJSON(w, slack.TextResponse("Could not open a war room: "+err.Error()))
		return
	}
	if !res.Spawned {
		writeJSON(w, slack.TextResponse("Alert accepted, but no routing rule opened a war room for it."))
		return
	}
	writeJSON(w, slack.OpenResponse(slack.OpenMeta{
		Room:     res.Room,
		Severity: severity,
		Source:   "Slack",
		JoinURL:  firstLink(res.Links),
		Expires:  b.defaultTTL,
	}))
}

// validSignature verifies Slack's v0 request signature: the X-Slack-Signature header
// ("v0=<hex>") must equal HMAC-SHA256(signing_secret, "v0:"+ts+":"+body), in constant
// time. It also rejects a timestamp outside the allowed skew (replay protection).
func (b *bot) validSignature(body []byte, tsHeader, sigHeader string) bool {
	if !strings.HasPrefix(sigHeader, "v0=") {
		return false
	}
	provided, err := hex.DecodeString(strings.TrimPrefix(sigHeader, "v0="))
	if err != nil || len(provided) == 0 {
		return false
	}
	ts, err := strconv.ParseInt(strings.TrimSpace(tsHeader), 10, 64)
	if err != nil {
		return false
	}
	if d := b.now().Sub(time.Unix(ts, 0)); d < -maxSkew || d > maxSkew {
		return false // too old or too far in the future — refuse to verify
	}
	mac := hmac.New(sha256.New, b.signingKey)
	mac.Write([]byte("v0:" + tsHeader + ":"))
	mac.Write(body)
	return hmac.Equal(provided, mac.Sum(nil))
}

// parseCommand maps a slash-command severity prefix to a severity and pulls out the
// summary. ok is false for an unrecognized command. The slash-command text is the
// part after "/netherchat", e.g. "sev1 database down".
func parseCommand(text string) (severity, summary string, ok bool) {
	t := strings.TrimSpace(text)
	fields := strings.Fields(t)
	if len(fields) == 0 {
		return "", "", false
	}
	switch strings.ToLower(fields[0]) {
	case "sev1":
		severity = "critical"
	case "sev2":
		severity = "high"
	case "sev3":
		severity = "medium"
	case "incident":
		severity = "high"
	case "drill":
		severity = "low"
	default:
		return "", "", false
	}
	return severity, strings.TrimSpace(t[len(fields[0]):]), true
}

// firstLink returns one join link from the result (sorted by invitee name for
// deterministic output), or "" if none.
func firstLink(links map[string]string) string {
	if len(links) == 0 {
		return ""
	}
	names := make([]string, 0, len(links))
	for n := range links {
		names = append(names, n)
	}
	sort.Strings(names)
	return links[names[0]]
}

func writeJSON(w http.ResponseWriter, payload []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

func loadConfig(path string) botConfig {
	var cfg botConfig
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
	fmt.Fprintln(os.Stderr, "netherchat-slack-bot: "+err.Error())
	os.Exit(1)
}
