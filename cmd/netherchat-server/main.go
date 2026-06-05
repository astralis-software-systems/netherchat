// Command netherchat-server is the Netherchat relay server: a WebSocket hub that
// routes end-to-end-encrypted messages between clients. It is a blind relay — it
// never sees plaintext and, by default, writes nothing to disk (R4). Zero
// telemetry: it makes no outbound network calls.
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

	if *healthcheck {
		os.Exit(runHealthcheck(cfg.Server.Addr))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := server.Run(ctx, cfg, log); err != nil {
		log.Error("server error", "err", err)
		os.Exit(1)
	}
}

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
