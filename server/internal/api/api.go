// Package api implements the small set of read-only REST endpoints the server
// exposes alongside the WebSocket transport (R4: "HTTP for REST config endpoints
// only"). None of these endpoints expose message content.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/salehkreiner/netherchat/buildinfo"
	"github.com/salehkreiner/netherchat/protocol"
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
	mux.HandleFunc("POST /webhook/{room}", a.webhook)
}

// webhook injects an inbound message into a room from an external system (CI,
// monitoring, etc). The message is plaintext and server-originated, so it is NOT
// end-to-end encrypted; clients render it with a clear marker. It is gated by a
// per-room token configured in netherchat.toml (secure by default: rooms without
// a webhook token reject all webhook posts).
func (a *API) webhook(w http.ResponseWriter, r *http.Request) {
	room := r.PathValue("room")
	policy := a.cfg.Room(room)
	if !policy.Webhook {
		http.Error(w, "webhooks are not enabled for this room", http.StatusNotFound)
		return
	}
	token := r.Header.Get("X-Netherchat-Token")
	if token == "" {
		token = r.URL.Query().Get("token")
	}
	if policy.WebhookToken == "" || token != policy.WebhookToken {
		http.Error(w, "invalid or missing webhook token", http.StatusUnauthorized)
		return
	}

	var body struct {
		Text string `json:"text"`
		From string `json:"from"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil || body.Text == "" {
		http.Error(w, `expected JSON {"text": "...", "from": "..."}`, http.StatusBadRequest)
		return
	}
	from := body.From
	if from == "" {
		from = "webhook"
	}

	env, err := protocol.Encode(protocol.OpServerMessage, protocol.ServerMessage{
		Kind: "webhook",
		From: from,
		Text: body.Text,
		At:   time.Now().Unix(),
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	a.hub.Broadcast(room, "", env)
	a.log.Info("webhook delivered", "room", room, "from", from)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
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
