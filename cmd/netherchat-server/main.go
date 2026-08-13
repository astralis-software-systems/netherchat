// Command netherchat-server is the Netherchat relay server: a WebSocket hub that
// routes end-to-end-encrypted messages between clients. It is a blind relay — it
// never sees plaintext and, by default, writes nothing to disk (R4) and makes no
// outbound network calls. Zero telemetry: no analytics, no phone-home. Every call
// it can make is opt-in and operator-configured — a [[route]] with a reply_url
// (server/internal/api.postReply) and --tor, which runs a local tor daemon to
// publish an onion service.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/salehkreiner/netherchat/buildinfo"
	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
)

func main() {
	configPath := flag.String("config", "", "path to netherchat.toml (optional)")
	addr := flag.String("addr", "", "listen address override, e.g. :3000")
	webURL := flag.String("web-url", "", "base URL of the browser join client for auto-war-room links (overrides [server].web_url)")
	useTor := flag.Bool("tor", false, "also publish a v3 onion service (requires `tor` in PATH); additive to the TCP listener")
	torDataDir := flag.String("tor-data-dir", "", "tor state directory for a STABLE .onion address (default: ephemeral per run)")
	showVersion := flag.Bool("version", false, "print version and exit")
	healthcheck := flag.Bool("healthcheck", false, "probe the local /health endpoint and exit 0/1 (used by Docker HEALTHCHECK)")
	flag.Parse()

	if *showVersion {
		fmt.Println("netherchat-server " + buildinfo.Version)
		return
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg := config.Default()
	if *configPath != "" {
		loaded, err := config.Load(*configPath)
		if err != nil {
			log.Error("failed to load config", "path", *configPath, "err", err)
			os.Exit(1)
		}
		cfg = loaded
		log.Info("loaded config", "path", *configPath, "rooms", len(cfg.Rooms))
	}
	if *addr != "" {
		cfg.Server.Addr = *addr
	}
	if *webURL != "" {
		cfg.Server.WebURL = *webURL
	}

	if *healthcheck {
		os.Exit(runHealthcheck(cfg.Server.Addr))
	}

	// --tor is a hard prerequisite check: we never bundle tor. A failure to find it
	// is a config error the operator must fix, so we exit with install guidance
	// rather than silently falling back (a runtime tor failure later IS best-effort).
	if *useTor && !server.TorInstalled() {
		fmt.Fprintln(os.Stderr, torNotInstalledMessage)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	tor := server.TorOptions{Enabled: *useTor, DataDir: *torDataDir}
	if err := server.Run(ctx, cfg, tor, log); err != nil {
		log.Error("server error", "err", err)
		os.Exit(1)
	}
}

// torNotInstalledMessage guides the operator to install tor when they ask for
// --tor without it. We deliberately do not bundle tor (it would bloat the static
// binary and entangle its release); the dependency is the operator's to provide.
const torNotInstalledMessage = `netherchat-server: --tor requires the tor daemon, which was not found in PATH.

Install it, then retry with --tor:
  macOS:          brew install tor
  Debian/Ubuntu:  sudo apt install tor
  Alpine:         apk add tor
  Arch:           sudo pacman -S tor

Netherchat does not bundle tor — see docs/self-hosting.md.`

// runHealthcheck performs a localhost GET /health against the configured port.
// It is compiled into the binary so the FROM-scratch image (no shell, no curl)
// can declare a HEALTHCHECK. Returns a process exit code.
func runHealthcheck(addr string) int {
	_, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		port = "3000"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + "/health")
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthcheck: status", resp.StatusCode)
		return 1
	}
	return 0
}
