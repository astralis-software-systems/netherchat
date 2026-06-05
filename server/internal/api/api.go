// Package api implements the small set of read-only REST endpoints the server
// exposes alongside the WebSocket transport (R4: "HTTP for REST config endpoints
// only"). None of these endpoints expose message content.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/salehkreiner/netherchat/buildinfo"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/server/internal/hub"
)

// API serves the REST endpoints.
type API struct {
	hub *hub.Hub
	cfg config.Config
	log *slog.Logger
}

// New constructs an API bound to the hub and config.
func New(h *hub.Hub, cfg config.Config, log *slog.Logger) *API {
	if log == nil {
		log = slog.Default()
	}
	return &API{hub: h, cfg: cfg, log: log}
}

// Register wires the REST routes onto the mux. Go 1.22+ method+path patterns.
func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", a.health)
	mux.HandleFunc("GET /version", a.version)
	mux.HandleFunc("GET /rooms", a.rooms)
}

func (a *API) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *API) version(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version":  buildinfo.Version,
		"protocol": 1,
		"product":  "netherchat",
	})
}

func (a *API) rooms(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"rooms": a.hub.Stats()})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
