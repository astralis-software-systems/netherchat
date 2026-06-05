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
)

func main() {
	addr := flag.String("addr", ":3000", "address to listen on, e.g. :3000")
	showVersion := flag.Bool("version", false, "print version and exit")
	healthcheck := flag.Bool("healthcheck", false, "probe the local /health endpoint and exit 0/1 (used by Docker HEALTHCHECK)")
	flag.Parse()

	switch {
	case *showVersion:
		fmt.Println("netherchat-server " + buildinfo.Version)
		return
	case *healthcheck:
		os.Exit(runHealthcheck(*addr))
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := server.Run(ctx, *addr, log); err != nil {
		log.Error("server error", "err", err)
		os.Exit(1)
	}
}

// runHealthcheck performs a localhost GET /health against the same port the
// server listens on. It is compiled into the binary so the FROM-scratch image
// (which has no shell or curl) can still declare a HEALTHCHECK. Returns a
// process exit code.
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
