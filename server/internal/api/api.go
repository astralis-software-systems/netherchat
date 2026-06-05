// Package api implements the small set of read-only REST endpoints the server
// exposes alongside the WebSocket transport (R4: "HTTP for REST config endpoints
// only"). None of these endpoints expose message content.
package api

import (
	"encoding/json"
	"net/http"

	"github.com/salehkreiner/netherchat/server/internal/hub"
)

// Version is the server version string, overridable at build time via -ldflags.
var Version = "0.1.0-m1"

// API serves the REST endpoints.
type API struct {
	hub *hub.Hub
}

// New constructs an API bound to the hub.
func New(h *hub.Hub) *API { return &API{hub: h} }

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
		"version":  Version,
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
