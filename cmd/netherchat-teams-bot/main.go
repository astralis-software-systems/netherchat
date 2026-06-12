// Command netherchat-teams-bot lets a Teams user open a Netherchat war room from a
// channel (NC-3, inbound initiate). It is a small HTTP server that receives a Teams
// outgoing-webhook command, verifies Teams' HMAC signature, opens a war room via
// the NC-1 ingress socket, and replies with a one-time join link.
//
// THE BOUNDARY LAW: only metadata crosses INTO Netherchat. The bot forwards just a
// parsed severity and a short summary (≤200 chars) plus the Teams message id as a
// reference — never the full Teams thread, the sender, or channel data. The
// sensitive discussion then stays entirely E2E inside Netherchat; Teams gets back
// only a pointer. The second law holds: the bot can INITIATE a room, never approve,
// seal, or execute inside one.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/salehkreiner/netherchat/connector"
	"github.com/salehkreiner/netherchat/teams"
)

const (
	defaultConfigFile = "netherchat-teams-bot.toml"
	alertKind         = "teams-initiate"
	maxBody           = 64 << 10
)

type botConfig struct {
	Listen          string   `toml:"listen"`
	Server          string   `toml:"server"`
	Source          string   `toml:"source"`
	Token           string   `toml:"token"`
	TeamsSecret     string   `toml:"teams_secret"`
	DefaultTTL      string   `toml:"default_ttl"`
	DefaultInvitees []string `toml:"default_invitees"` // informational: the relay [[route]] is authoritative for who is invited
}

// bot holds the request-handling state. connector.Client is safe for concurrent use.
type bot struct {
	client     *connector.Client
	hmacKey    []byte // decoded Teams shared secret
	source     string
	defaultTTL string
}

// teamsWebhook is the slice of a Teams outgoing-webhook payload we read. Everything
// else (from, channelData, the full thread) is deliberately ignored — never read,
// never forwarded.
type teamsWebhook struct {
	Text string `json:"text"`
	ID   string `json:"id"`
}

func main() {
	fs := flag.NewFlagSet("netherchat-teams-bot", flag.ExitOnError)
	listen := fs.String("listen", "", "address to receive Teams webhooks on (default :9090)")
	server := fs.String("server", "", "relay base URL, e.g. https://relay.example.com")
	source := fs.String("source", "", "registered [[source]] name (default teams-bot)")
	token := fs.String("token", "", "NC-1 per-source bearer token")
	teamsSecret := fs.String("teams-secret", "", "Teams outgoing-webhook HMAC secret (base64)")
	configPath := fs.String("config", "", "config file (default: ./"+defaultConfigFile+" if present)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "netherchat-teams-bot — open a Netherchat war room from a Teams command (NC-3)")
		fmt.Fprintln(os.Stderr, "\nusage:\n  netherchat-teams-bot --listen :9090 --server https://relay --source teams-bot --token <tok> --teams-secret <b64>")
		fs.PrintDefaults()
	}
	_ = fs.Parse(os.Args[1:])

	cfg := loadConfig(*configPath)
	srv := connector.FirstNonEmpty(*server, cfg.Server)
	if srv == "" {
		fatal(errors.New("--server is required (via flag or config)"))
	}
	secret := connector.FirstNonEmpty(*teamsSecret, cfg.TeamsSecret)
	if secret == "" {
		fatal(errors.New("--teams-secret is required (Teams signs outgoing webhooks; unsigned requests are rejected)"))
	}
	addr := connector.FirstNonEmpty(*listen, cfg.Listen, ":9090")

	b := &bot{
		client:     &connector.Client{Server: srv, Token: connector.FirstNonEmpty(*token, cfg.Token)},
		hmacKey:    decodeSecret(secret),
		source:     connector.FirstNonEmpty(*source, cfg.Source, "teams-bot"),
		defaultTTL: connector.FirstNonEmpty(cfg.DefaultTTL, "2h"),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	mux.HandleFunc("POST /", b.handle)

	httpSrv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	fmt.Fprintf(os.Stderr, "netherchat-teams-bot: listening on %s, opening rooms on %s as source %q\n", addr, srv, b.source)
	if err := httpSrv.ListenAndServe(); err != nil {
		fatal(err)
	}
}

// handle verifies the Teams signature, parses the command, opens a war room via the
// ingress socket, and replies with a join link.
func (b *bot) handle(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	if !b.validSignature(body, r.Header.Get("Authorization")) {
		http.Error(w, "invalid or missing HMAC signature", http.StatusUnauthorized)
		return
	}

	var p teamsWebhook
	if err := json.Unmarshal(body, &p); err != nil {
		http.Error(w, "bad webhook payload", http.StatusBadRequest)
		return
	}
	severity, summary, ok := parseCommand(p.Text)
	if !ok {
		writeCard(w, teams.TextCard("Unknown command. Use: @netherchat sev1|sev2|sev3|incident|drill <summary>"))
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
		Ref:      p.ID,
		TS:       time.Now().Unix(),
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	res, err := b.client.Send(ctx, alert)
	if err != nil {
		writeCard(w, teams.TextCard("Could not open a war room: "+err.Error()))
		return
	}
	if !res.Spawned {
		writeCard(w, teams.TextCard("Alert accepted, but no routing rule opened a war room for it."))
		return
	}
	writeCard(w, teams.OpenCard(teams.OpenMeta{
		Room:     res.Room,
		Severity: severity,
		Actor:    "Teams",
		JoinURL:  firstLink(res.Links),
		Expires:  b.defaultTTL,
	}))
}

// validSignature checks Teams' HMAC-SHA256 over the raw request body against the
// Authorization header ("HMAC <base64>"), in constant time.
func (b *bot) validSignature(body []byte, authHeader string) bool {
	provided := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(authHeader), "HMAC"))
	sig, err := base64.StdEncoding.DecodeString(provided)
	if err != nil || len(sig) == 0 {
		return false
	}
	mac := hmac.New(sha256.New, b.hmacKey)
	mac.Write(body)
	return hmac.Equal(sig, mac.Sum(nil))
}

// parseCommand maps a Teams command prefix to a severity and pulls out the summary.
// ok is false for an unrecognized command.
func parseCommand(text string) (severity, summary string, ok bool) {
	t := stripMention(text)
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

// stripMention removes a leading bot mention (a "<at>…</at>" tag and/or a leading
// @token) so command parsing sees just "sev1 <summary>".
func stripMention(text string) string {
	t := strings.TrimSpace(text)
	if strings.HasPrefix(t, "<at>") {
		if i := strings.Index(t, "</at>"); i >= 0 {
			t = strings.TrimSpace(t[i+len("</at>"):])
		}
	}
	if strings.HasPrefix(t, "@") {
		if sp := strings.IndexAny(t, " \t"); sp >= 0 {
			t = strings.TrimSpace(t[sp:])
		} else {
			t = ""
		}
	}
	return t
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

// decodeSecret base64-decodes the Teams secret to its key bytes, falling back to
// the raw bytes if it is not valid base64.
func decodeSecret(secret string) []byte {
	if k, err := base64.StdEncoding.DecodeString(secret); err == nil && len(k) > 0 {
		return k
	}
	return []byte(secret)
}

func writeCard(w http.ResponseWriter, card []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(card)
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
	fmt.Fprintln(os.Stderr, "netherchat-teams-bot: "+err.Error())
	os.Exit(1)
}
