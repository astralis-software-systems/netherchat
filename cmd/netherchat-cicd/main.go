// Command netherchat-cicd opens a short-TTL war room when a CI/CD pipeline fails and
// signals a resolution when a re-run passes (NC-5). It is the generalization of B3
// (the CI ephemeral war room) onto the NC-1 ingress socket — there is no standalone
// B3 binary; this is it. A failed pipeline POSTs a `ci-failure` alert (a route opens
// a room); a later pass POSTs a `ci-resolved` alert (a route can auto-scuttle it).
//
// Two modes:
//   - webhook server (--ci github|gitlab): receives GitHub Actions / GitLab webhooks,
//     verifies the provider's signature, and forwards failed/passed pipeline events.
//   - CLI step (--ci cli): run directly inside a pipeline with --status/--job/etc.
//
// THE BOUNDARY LAW: only build metadata crosses — a job name, the repo, a short
// commit sha, and the run id. Log output, diffs, commit messages, and every other
// payload field are never read into the alert. The boundary test in main_test.go
// proves only the seven allowed alert fields appear in the forwarded body.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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
	defaultConfigFile = "netherchat-cicd.toml"
	kindFailure       = "ci-failure"
	kindResolved      = "ci-resolved"
	refMax            = 256
	maxBody           = 256 << 10
)

type cicdConfig struct {
	Listen       string `toml:"listen"`
	Server       string `toml:"server"`
	Source       string `toml:"source"`
	Token        string `toml:"token"`
	HMACSecret   string `toml:"hmac_secret"`
	CI           string `toml:"ci"` // github | gitlab | cli
	GitHubSecret string `toml:"github_secret"`
	GitLabToken  string `toml:"gitlab_token"`
	DefaultTTL   string `toml:"default_ttl"`
}

// ciFields is the normalized, metadata-only set the translator works from, shared by
// the webhook and CLI paths.
type ciFields struct {
	Status string // "failed" | "passed"
	Job    string
	Repo   string
	Commit string
	RunID  string
}

type adapter struct {
	client       *connector.Client
	ci           string // "github" | "gitlab"
	source       string
	githubSecret []byte
	gitlabToken  string
}

func main() {
	fs := flag.NewFlagSet("netherchat-cicd", flag.ExitOnError)
	listen := fs.String("listen", "", "address to receive CI webhooks on (default :8083)")
	server := fs.String("server", "", "relay base URL, e.g. https://relay.example.com")
	source := fs.String("source", "", "registered [[source]] name (default: ci-<provider>)")
	token := fs.String("token", "", "per-source bearer token")
	hmacSecret := fs.String("hmac-secret", "", "per-source HMAC secret (signs each alert)")
	ci := fs.String("ci", "", "mode: github | gitlab | cli")
	githubSecret := fs.String("github-secret", "", "GitHub webhook secret (validates X-Hub-Signature-256)")
	gitlabToken := fs.String("gitlab-token", "", "GitLab webhook token (validates X-Gitlab-Token)")
	// CLI-mode flags:
	status := fs.String("status", "", "[cli] pipeline result: failed | passed")
	job := fs.String("job", "", "[cli] job/workflow name")
	runID := fs.String("run-id", "", "[cli] run id (used as the alert ref)")
	repo := fs.String("repo", "", "[cli] repository, e.g. owner/repo")
	commit := fs.String("commit", "", "[cli] commit sha")
	configPath := fs.String("config", "", "config file (default: ./"+defaultConfigFile+" if present)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "netherchat-cicd — open a war room on CI failure, resolve on pass (NC-5, B3)")
		fmt.Fprintln(os.Stderr, "\nwebhook:\n  netherchat-cicd --ci github --listen :8083 --server <url> --source ci --token <tok> --github-secret <s>")
		fmt.Fprintln(os.Stderr, "cli step:\n  netherchat-cicd --ci cli --server <url> --source ci --token <tok> \\\n    --status failed --job build --run-id 42 --repo owner/repo --commit $GITHUB_SHA")
		fs.PrintDefaults()
	}
	_ = fs.Parse(os.Args[1:])

	cfg := loadConfig(*configPath)
	mode := strings.ToLower(connector.FirstNonEmpty(*ci, cfg.CI))
	if mode != "github" && mode != "gitlab" && mode != "cli" {
		fatal(errors.New(`--ci must be "github", "gitlab", or "cli"`))
	}
	srv := connector.FirstNonEmpty(*server, cfg.Server)
	if srv == "" {
		fatal(errors.New("--server is required (via flag or config)"))
	}
	src := connector.FirstNonEmpty(*source, cfg.Source, "ci-"+mode)
	tok := connector.FirstNonEmpty(*token, cfg.Token)
	hmac := connector.FirstNonEmpty(*hmacSecret, cfg.HMACSecret)
	if tok == "" && hmac == "" {
		fmt.Fprintln(os.Stderr, "warning: no token or hmac-secret set — the relay will reject this source")
	}
	client := &connector.Client{Server: srv, Token: tok, HMACSecret: hmac}

	// CLI mode: one-shot, no HTTP server.
	if mode == "cli" {
		runCLI(client, src, ciFields{
			Status: normalizeStatus(*status),
			Job:    *job, RunID: *runID, Repo: *repo, Commit: *commit,
		})
		return
	}

	ad := &adapter{
		client:       client,
		ci:           mode,
		source:       src,
		githubSecret: []byte(connector.FirstNonEmpty(*githubSecret, cfg.GitHubSecret)),
		gitlabToken:  connector.FirstNonEmpty(*gitlabToken, cfg.GitLabToken),
	}
	if mode == "github" && len(ad.githubSecret) == 0 {
		fatal(errors.New("--github-secret is required in github mode (unsigned webhooks are rejected)"))
	}
	if mode == "gitlab" && ad.gitlabToken == "" {
		fatal(errors.New("--gitlab-token is required in gitlab mode (untokened webhooks are rejected)"))
	}
	addr := connector.FirstNonEmpty(*listen, cfg.Listen, ":8083")

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	mux.HandleFunc("POST /", ad.handle)

	httpSrv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	fmt.Fprintf(os.Stderr, "netherchat-cicd: listening on %s, forwarding %s CI events to %s as source %q (default_ttl %s)\n",
		addr, mode, srv, src, connector.FirstNonEmpty(cfg.DefaultTTL, "1h"))
	if err := httpSrv.ListenAndServe(); err != nil {
		fatal(err)
	}
}

// runCLI translates and forwards a single pipeline result from CLI flags.
func runCLI(client *connector.Client, source string, f ciFields) {
	a, ok := translate(f, source)
	if !ok {
		fatal(errors.New("--status must be failed or passed"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res, err := client.Send(ctx, a)
	if err != nil {
		fatal(err)
	}
	connector.PrintResult(os.Stdout, a.Ref, res)
}

// handle receives one CI webhook, validates the provider signature, translates a
// failed/passed pipeline event, and forwards it. Non-terminal events (queued,
// running, cancelled) are accepted and ignored. It NEVER echoes the inbound payload.
func (ad *adapter) handle(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	var (
		f       ciFields
		forward bool
	)
	switch ad.ci {
	case "github":
		if !ad.validGitHub(raw, r.Header.Get("X-Hub-Signature-256")) {
			http.Error(w, "invalid or missing GitHub signature", http.StatusUnauthorized)
			return
		}
		f, forward, err = parseGitHub(raw)
	case "gitlab":
		if !ad.validGitLab(r.Header.Get("X-Gitlab-Token")) {
			http.Error(w, "invalid or missing GitLab token", http.StatusUnauthorized)
			return
		}
		f, forward, err = parseGitLab(raw)
	default:
		http.Error(w, "adapter misconfigured: unknown ci provider", http.StatusInternalServerError)
		return
	}
	if err != nil {
		http.Error(w, "bad webhook: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !forward {
		writeJSON(w, http.StatusOK, map[string]any{"accepted": false, "reason": "event is not a terminal pipeline result"})
		return
	}
	a, ok := translate(f, ad.source)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"accepted": false, "reason": "unrecognized status"})
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

// translate maps normalized CI fields to the generic NC-1 alert. A failure opens a
// room (high / ci-failure); a pass signals resolution (info / ci-resolved). No log
// content is ever read — the summary is built only from job/repo/commit metadata.
func translate(f ciFields, source string) (connector.Alert, bool) {
	var sev, kind, verb string
	switch f.Status {
	case "failed":
		sev, kind, verb = "high", kindFailure, "failed"
	case "passed":
		sev, kind, verb = "info", kindResolved, "passed"
	default:
		return connector.Alert{}, false
	}
	job := connector.FirstNonEmpty(strings.TrimSpace(f.Job), "pipeline")
	repo := connector.FirstNonEmpty(strings.TrimSpace(f.Repo), "(unknown repo)")
	summary := job + " " + verb + " on " + repo
	if short := shortSHA(f.Commit); short != "" {
		summary += "@" + short
	}
	return connector.Alert{
		Source:   source,
		Severity: sev,
		Kind:     kind,
		Summary:  connector.Truncate(summary, connector.SummaryMax),
		Ref:      connector.Truncate(strings.TrimSpace(f.RunID), refMax),
		TS:       time.Now().Unix(),
	}, true
}

// --- GitHub Actions (workflow_run) ---------------------------------------------

type ghPayload struct {
	Action      string `json:"action"` // requested | in_progress | completed
	WorkflowRun struct {
		Name       string `json:"name"`
		Conclusion string `json:"conclusion"` // success | failure | cancelled | ...
		ID         int64  `json:"id"`
		HeadSHA    string `json:"head_sha"`
	} `json:"workflow_run"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
}

// parseGitHub reads a workflow_run webhook. forward is true only when a run has
// COMPLETED with a failure or success conclusion.
func parseGitHub(raw []byte) (ciFields, bool, error) {
	var p ghPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return ciFields{}, false, fmt.Errorf("parse github webhook: %w", err)
	}
	if !strings.EqualFold(p.Action, "completed") {
		return ciFields{}, false, nil
	}
	status := normalizeStatus(p.WorkflowRun.Conclusion)
	if status == "" {
		return ciFields{}, false, nil // cancelled, skipped, timed_out, etc.
	}
	return ciFields{
		Status: status,
		Job:    p.WorkflowRun.Name,
		Repo:   p.Repository.FullName,
		Commit: p.WorkflowRun.HeadSHA,
		RunID:  strconv.FormatInt(p.WorkflowRun.ID, 10),
	}, true, nil
}

// validGitHub verifies the X-Hub-Signature-256 header ("sha256=<hex>") against
// HMAC-SHA256(secret, body), in constant time.
func (ad *adapter) validGitHub(body []byte, header string) bool {
	if !strings.HasPrefix(header, "sha256=") {
		return false
	}
	provided, err := hex.DecodeString(strings.TrimPrefix(header, "sha256="))
	if err != nil || len(provided) == 0 {
		return false
	}
	mac := hmac.New(sha256.New, ad.githubSecret)
	mac.Write(body)
	return hmac.Equal(provided, mac.Sum(nil))
}

// --- GitLab (Pipeline Hook) ----------------------------------------------------

type glPayload struct {
	ObjectKind       string `json:"object_kind"` // pipeline
	ObjectAttributes struct {
		ID     int64  `json:"id"`
		Status string `json:"status"` // failed | success | running | ...
		SHA    string `json:"sha"`
		Ref    string `json:"ref"`
	} `json:"object_attributes"`
	Project struct {
		PathWithNamespace string `json:"path_with_namespace"`
	} `json:"project"`
}

// parseGitLab reads a Pipeline Hook. forward is true only for a failed or success
// pipeline status.
func parseGitLab(raw []byte) (ciFields, bool, error) {
	var p glPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return ciFields{}, false, fmt.Errorf("parse gitlab webhook: %w", err)
	}
	status := normalizeStatus(p.ObjectAttributes.Status)
	if status == "" {
		return ciFields{}, false, nil
	}
	return ciFields{
		Status: status,
		Job:    "pipeline",
		Repo:   p.Project.PathWithNamespace,
		Commit: p.ObjectAttributes.SHA,
		RunID:  strconv.FormatInt(p.ObjectAttributes.ID, 10),
	}, true, nil
}

// validGitLab compares the X-Gitlab-Token header to the configured token in constant
// time.
func (ad *adapter) validGitLab(header string) bool {
	if ad.gitlabToken == "" || header == "" {
		return false
	}
	return hmac.Equal([]byte(header), []byte(ad.gitlabToken))
}

// normalizeStatus folds the providers' status/conclusion vocabularies into the two
// terminal results we act on. Anything non-terminal returns "".
func normalizeStatus(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "failed", "failure", "error", "errored":
		return "failed"
	case "passed", "pass", "success", "succeeded", "ok":
		return "passed"
	default:
		return ""
	}
}

// shortSHA returns the first 7 characters of a commit sha (git's short form), or the
// sha unchanged when it is already short or empty.
func shortSHA(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 7 {
		return s
	}
	return s[:7]
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func loadConfig(path string) cicdConfig {
	var cfg cicdConfig
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
	fmt.Fprintln(os.Stderr, "netherchat-cicd: "+err.Error())
	os.Exit(1)
}
