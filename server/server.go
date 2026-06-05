// Package server wires the Netherchat relay together: the WebSocket transport
// and the REST API over a shared in-memory hub. It is the exported seam between
// the thin cmd/netherchat-server entrypoint (and tests) and the internal
// packages, which Go's internal-package rule keeps unreachable from outside the
// server/ tree.
package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/salehkreiner/netherchat/buildinfo"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/server/internal/api"
	"github.com/salehkreiner/netherchat/server/internal/hub"
	"github.com/salehkreiner/netherchat/server/internal/ws"
)

// Handler builds the HTTP handler (WebSocket relay at /ws plus the read-only
// REST endpoints) backed by a fresh in-memory hub. Each call returns an
// independent server with its own room state — convenient for tests.
func Handler(cfg config.Config, log *slog.Logger) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	h := hub.New()
	transport := ws.NewServer(h, cfg, log)
	rest := api.New(h, cfg, log)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /ws", transport.HandleWS)
	rest.Register(mux)
	return mux
}

// Run starts the server on cfg.Server.Addr and blocks until ctx is cancelled,
// then shuts down gracefully.
func Run(ctx context.Context, cfg config.Config, log *slog.Logger) error {
	if log == nil {
		log = slog.Default()
	}
	srv := &http.Server{
		Addr:              cfg.Server.Addr,
		Handler:           Handler(cfg, log),
		ReadHeaderTimeout: 10 * time.Second,
		// No WriteTimeout: WebSocket connections are long-lived.
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("netherchat server listening", "addr", cfg.Server.Addr, "version", buildinfo.Version)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
