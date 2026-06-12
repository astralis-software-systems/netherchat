// Package server wires the Netherchat relay together: the WebSocket transport
// and the REST API over a shared in-memory hub. It is the exported seam between
// the thin cmd/netherchat-server entrypoint (and tests) and the internal
// packages, which Go's internal-package rule keeps unreachable from outside the
// server/ tree.
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/salehkreiner/netherchat/buildinfo"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/server/internal/alert"
	"github.com/salehkreiner/netherchat/server/internal/api"
	"github.com/salehkreiner/netherchat/server/internal/beacon"
	"github.com/salehkreiner/netherchat/server/internal/ephemeral"
	"github.com/salehkreiner/netherchat/server/internal/hub"
	"github.com/salehkreiner/netherchat/server/internal/invite"
	"github.com/salehkreiner/netherchat/server/internal/scuttle"
	"github.com/salehkreiner/netherchat/server/internal/store"
	"github.com/salehkreiner/netherchat/server/internal/ws"
)

// Handler builds the HTTP handler (WebSocket relay at /ws plus the read-only
// REST endpoints) backed by a fresh in-memory hub, opening a message store if
// persistence is enabled. Each call returns an independent server — convenient
// for tests.
func Handler(cfg config.Config, log *slog.Logger) http.Handler {
	return handlerWithStore(cfg, openStore(cfg, log), nil, log)
}

// HandlerWithTap is Handler plus a diagnostic frame tap: every raw inbound relay
// frame is copied to tap before the relay decodes it. It exists for
// `netherchat doctor --paranoid` (§3.1), which uses it to prove the relay sees
// only ciphertext. Never wired in normal server startup.
func HandlerWithTap(cfg config.Config, tap func([]byte), log *slog.Logger) http.Handler {
	return handlerWithStore(cfg, openStore(cfg, log), tap, log)
}

func handlerWithStore(cfg config.Config, st store.Store, tap func([]byte), log *slog.Logger) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	h := hub.New(cfg, log)
	invites := invite.New()
	// Ephemeral (break-glass) war rooms: invite-only, hard TTL. The registry's
	// janitor closes each room through the hub when its deadline passes.
	eph := ephemeral.New(log)
	eph.Start(h.ExpireRoom)
	// Dead-man's switch (§1.6): per-room idle/owner-loss scuttle, driven by the
	// connection lifecycle in the transport. Policy comes from each room's config.
	sc := scuttle.New(h, scuttlePolicyOf(cfg), log)
	transport := ws.NewServer(h, cfg, invites, eph, sc, st, log)
	if tap != nil {
		transport.SetFrameTap(tap)
	}
	// Status Beacon store (§1.2): the single bounded exception to zero-persistence.
	// Purged when a room is torn down (scuttle / ephemeral deadline / idle TTL).
	beacons := beacon.New()
	h.SetOnClose(beacons.Delete)
	// Per-source ingress hardening for the generic alert socket (NC-1): rate +
	// spawn caps keyed by [[source]]. Built once; lives for the handler's lifetime.
	guards := alert.NewGuards()
	rest := api.New(h, cfg, invites, eph, beacons, guards, log)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /ws", transport.HandleWS)
	rest.Register(mux)
	return mux
}

// scuttlePolicyOf adapts the room config into the scuttle manager's
// transport-agnostic Policy (stdlib durations, heartbeat defaulted/capped).
func scuttlePolicyOf(cfg config.Config) func(room string) scuttle.Policy {
	return func(room string) scuttle.Policy {
		p := cfg.Room(room).Scuttle
		return scuttle.Policy{
			IdleAfter:     p.IdleAfter.Std(),
			OwnerLossBurn: p.OwnerLossBurn,
			Heartbeat:     p.HeartbeatOrDefault(),
		}
	}
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
	secret, err := persistSecret(cfg, log)
	if err != nil {
		log.Error("persistence: cannot establish an at-rest key; continuing without persistence", "err", err)
		return nil
	}
	st, err := store.OpenSQLite(cfg.Persistence.Path, cfg.Persistence.History, secret)
	if err != nil {
		log.Error("persistence: failed to open sqlite; continuing without persistence", "err", err)
		return nil
	}
	log.Info("persistence: sqlite (encrypted at rest)", "path", cfg.Persistence.Path, "limit", cfg.Persistence.History)
	return st
}

// persistSecret resolves the at-rest encryption secret for the SQLite store (§7),
// in priority order:
//
//  1. $NETHERCHAT_PERSIST_KEY — supplied out of band; the only source that also
//     protects against theft of the database disk itself.
//  2. [persistence] key in netherchat.toml.
//  3. an auto-generated sidecar key file (<path>.key, 0600).
//
// The relay is blind and holds no room or identity key, so the at-rest key
// cannot be derived from a client identity (as a client-side store could) — it is
// an operator secret. The sidecar fallback keeps the database readable across
// restarts with zero configuration, but a thief who takes both files defeats it;
// we say so and recommend option 1. The store derives the AES-256 key from this
// secret via HKDF-SHA256("netherchat/sqlite/v1"). See docs/encryption.md.
func persistSecret(cfg config.Config, log *slog.Logger) ([]byte, error) {
	if v := os.Getenv("NETHERCHAT_PERSIST_KEY"); v != "" {
		return []byte(v), nil
	}
	if cfg.Persistence.Key != "" {
		return []byte(cfg.Persistence.Key), nil
	}
	keyPath := cfg.Persistence.Path + ".key"
	if b, err := os.ReadFile(keyPath); err == nil && len(b) > 0 {
		return b, nil
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	secret := []byte(hex.EncodeToString(raw))
	if err := os.WriteFile(keyPath, secret, 0o600); err != nil {
		return nil, fmt.Errorf("write sidecar key %s: %w", keyPath, err)
	}
	log.Warn("persistence: generated a sidecar at-rest key; for protection against disk theft set NETHERCHAT_PERSIST_KEY out of band instead",
		"key_file", keyPath)
	return secret, nil
}

// Run starts the server on cfg.Server.Addr and blocks until ctx is cancelled,
// then shuts down gracefully. When tor.Enabled, it ALSO publishes a v3 onion
// service over the same handler (and hub), so onion and TCP clients share rooms
// — the onion is purely an additional reachability path (§1.5).
func Run(ctx context.Context, cfg config.Config, tor TorOptions, log *slog.Logger) error {
	if log == nil {
		log = slog.Default()
	}
	st := openStore(cfg, log)
	if st != nil {
		defer st.Close()
	}
	handler := handlerWithStore(cfg, st, nil, log)
	srv := &http.Server{
		Addr:              cfg.Server.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		// No WriteTimeout: WebSocket connections are long-lived.
	}

	// Optional onion listener. Best-effort: if tor fails to start or publish, the
	// relay still serves on TCP — --tor must never take the core relay down (§1.5).
	if tor.Enabled {
		if onion, err := startOnion(ctx, tor.DataDir, log); err != nil {
			log.Warn("tor onion service unavailable; continuing on TCP only", "err", err)
		} else {
			defer onion.close()
			osrv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
			go func() {
				if err := osrv.Serve(onion.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
					log.Warn("onion listener stopped", "err", err)
				}
			}()
		}
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
