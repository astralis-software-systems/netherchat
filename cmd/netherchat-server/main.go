// Command netherchat-server is the Netherchat relay server: a WebSocket hub that
// routes end-to-end-encrypted messages between clients. It is a blind relay — it
// never sees plaintext and, by default, writes nothing to disk (R4). Zero
// telemetry: it makes no outbound network calls.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/salehkreiner/netherchat/server"
)

func main() {
	addr := flag.String("addr", ":3000", "address to listen on, e.g. :3000")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := server.Run(ctx, *addr, log); err != nil {
		log.Error("server error", "err", err)
		os.Exit(1)
	}
}
