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
	"github.com/salehkreiner/netherchat/server/internal/ephemeral"
	"github.com/salehkreiner/netherchat/server/internal/hub"
	"github.com/salehkreiner/netherchat/server/internal/invite"
	"github.com/salehkreiner/netherchat/server/internal/store"
	"github.com/salehkreiner/netherchat/server/internal/ws"
)

// Handler builds the HTTP handler (WebSocket relay at /ws plus the read-only
// REST endpoints) backed by a fresh in-memory hub, opening a message store if
// persistence is enabled. Each call returns an independent server — convenient
// for tests.
func Handler(cfg config.Config, log *slog.Logger) http.Handler {
	return handlerWithStore(cfg, openStore(cfg, log), log)
}

func handlerWithStore(cfg config.Config, st store.Store, log *slog.Logger) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	h := hub.New(cfg, log)
	invites := invite.New()
	// Ephemeral (break-glass) war rooms: invite-only, hard TTL. The registry's
	// janitor closes each room through the hub when its deadline passes.
	eph := ephemeral.New(log)
	eph.Start(h.ExpireRoom)
	transport := ws.NewServer(h, cfg, invites, eph, st, log)
	rest := api.New(h, cfg, log)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /ws", transport.HandleWS)
	rest.Register(mux)
	return mux
}

// openStore builds the message store implied by the config, or nil when
// persistence is disabled (the default — zero persistence).
func openStore(cfg config.Config, log *slog.Logger) store.Store {
	if log == nil {
		log = slog.Default()
	}
	if !cfg.Persistence.Enabled {
		return nil
	}
	if cfg.Persistence.Path == "" {
		log.Info("persistence: in-memory history", "limit", cfg.Persistence.History)
		return store.NewMemory(cfg.Persistence.History)
	}
	st, err := store.OpenSQLite(cfg.Persistence.Path, cfg.Persistence.History)
	if err != nil {
		log.Error("persistence: failed to open sqlite; continuing without persistence", "err", err)
		return nil
	}
	log.Info("persistence: sqlite", "path", cfg.Persistence.Path, "limit", cfg.Persistence.History)
	return st
}

// Run starts the server on cfg.Server.Addr and blocks until ctx is cancelled,
// then shuts down gracefully.
func Run(ctx context.Context, cfg config.Config, log *slog.Logger) error {
	if log == nil {
		log = slog.Default()
	}
	st := openStore(cfg, log)
	if st != nil {
		defer st.Close()
	}
	srv := &http.Server{
		Addr:              cfg.Server.Addr,
		Handler:           handlerWithStore(cfg, st, log),
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
