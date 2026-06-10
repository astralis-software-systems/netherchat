// Package api implements the small set of read-only REST endpoints the server
// exposes alongside the WebSocket transport (R4: "HTTP for REST config endpoints
// only"), plus the inbound webhook receiver. None of these endpoints expose
// message content.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/salehkreiner/netherchat/buildinfo"
	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/server/internal/beacon"
	"github.com/salehkreiner/netherchat/server/internal/ephemeral"
	"github.com/salehkreiner/netherchat/server/internal/hub"
	"github.com/salehkreiner/netherchat/server/internal/invite"
	"github.com/salehkreiner/netherchat/server/internal/route"
)

// replyTimeout bounds the fire-and-forget POST to a route's reply_url.
const replyTimeout = 5 * time.Second

// API serves the REST endpoints and the inbound webhook. It holds the invite
// store and ephemeral registry so the webhook can spawn auto-war-rooms (§1.3) —
// the same break-glass machinery the WebSocket transport uses.
type API struct {
	hub       *hub.Hub
	cfg       config.Config
	invites   *invite.Store
	ephemeral *ephemeral.Registry
	beacons   *beacon.Store
	log       *slog.Logger
}

// New constructs an API bound to the hub, config, invite store, ephemeral
// registry, and beacon store.
func New(h *hub.Hub, cfg config.Config, invites *invite.Store, eph *ephemeral.Registry, beacons *beacon.Store, log *slog.Logger) *API {
	if log == nil {
		log = slog.Default()
	}
	return &API{hub: h, cfg: cfg, invites: invites, ephemeral: eph, beacons: beacons, log: log}
}

// Register wires the REST routes onto the mux. Go 1.22+ method+path patterns.
func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", a.health)
	mux.HandleFunc("GET /version", a.version)
	mux.HandleFunc("GET /rooms", a.rooms)
	mux.HandleFunc("POST /webhook/{room}", a.webhook)
	// Status Beacon (§1.2): PUT/DELETE write (token-gated), GET reads (no auth — the
	// ciphertext is useless without the beacon key, which never reaches the server).
	mux.HandleFunc("PUT /beacon/{room}", a.beaconPut)
	mux.HandleFunc("GET /beacon/{room}", a.beaconGet)
	mux.HandleFunc("DELETE /beacon/{room}", a.beaconDelete)
}

// webhook injects an inbound message into a room from an external system (CI,
// monitoring, etc). It is gated by a per-room token configured in
// netherchat.toml (secure by default: rooms without a webhook token reject all
// posts).
//
// Before normal delivery, the decoded payload is evaluated against the [[route]]
// rules (§1.3). If a rule matches, the server spawns an ephemeral break-glass war
// room, mints one-time join links for the named invitees, returns them as JSON,
// and stops — the alert opened its own incident room. If no rule matches, the
// payload is delivered as a plaintext, server-originated message exactly as
// before. Routing happens AFTER authentication: spawning a war room is at least
// as privileged as posting a message, so it requires the same valid token.
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

	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		http.Error(w, `expected a JSON object body`, http.StatusBadRequest)
		return
	}

	// Auto-war-room: first matching route wins. On match we spawn and return; the
	// payload is NOT also delivered to the (intake) room.
	if idx, rule, ok := route.Match(a.cfg.Routes, payload); ok {
		a.fireRoute(w, r, room, idx, rule)
		return
	}

	// No route matched: normal webhook delivery (plaintext, server-originated).
	text, _ := payload["text"].(string)
	if text == "" {
		http.Error(w, `expected JSON {"text": "...", "from": "..."}`, http.StatusBadRequest)
		return
	}
	from, _ := payload["from"].(string)
	if from == "" {
		from = "webhook"
	}
	env, err := protocol.Encode(protocol.OpServerMessage, protocol.ServerMessage{
		Kind: "webhook",
		From: from,
		Text: text,
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

// routeResponse is the JSON body returned to the webhook caller (and POSTed to a
// route's reply_url) when a route fires: the spawned room and a one-time join
// link per invited name.
type routeResponse struct {
	Room  string            `json:"room"`
	Links map[string]string `json:"links"`
}

// fireRoute spawns the incident war room for a matched rule, mints the links,
// notifies the intake room's observers (route_fired), and replies. Room creation
// failure is the only path that returns 500; reply_url failures are ignored
// because the links are already delivered in the HTTP response.
func (a *API) fireRoute(w http.ResponseWriter, r *http.Request, intakeRoom string, idx int, rule config.RouteConfig) {
	if a.ephemeral == nil || a.invites == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "auto-war-room is unavailable"})
		return
	}

	ttl := ephemeral.ClampTTL(rule.TTL.Std())
	prefix := rule.RoomPrefix
	if prefix == "" {
		prefix = "inc"
	}
	er := a.ephemeral.CreateNamed(ttl, "webhook:"+intakeRoom, prefix)

	base := a.webBase(r)
	links := make(map[string]string, len(rule.Invite))
	invitees := make([]string, 0, len(rule.Invite))
	for _, name := range rule.Invite {
		name = strings.TrimPrefix(strings.TrimSpace(name), "@")
		if name == "" {
			continue
		}
		invitees = append(invitees, name)
		// Each invitee gets a one-time token scoped to (and expiring with) the room.
		// A name with no matching [[trust]] handle still gets a link; the handle is
		// just used as the display name.
		tok, _ := a.invites.Generate(er.Name, ttl)
		links[name] = joinLink(base, er.Name, tok)
	}

	a.log.Info("auto-war-room fired", "intake", intakeRoom, "room", er.Name,
		"trigger_rule", idx, "invitees", len(invitees), "ttl", ttl.String())

	// Tell the intake room's members (e.g. `tail #alerts --json`) that a room was
	// spawned, so the auto-war-room shows up in the structured event stream.
	fired, _ := protocol.Encode(protocol.OpRouteFired, protocol.RouteFired{
		Room:        er.Name,
		TriggerRule: idx,
		Invitees:    invitees,
		TTLSeconds:  int(ttl.Seconds()),
		At:          time.Now().Unix(),
	})
	a.hub.Broadcast(intakeRoom, "", fired)

	resp := routeResponse{Room: er.Name, Links: links}

	// reply_url is the operator's OWN system (e.g. a PagerDuty note endpoint).
	// Astralis makes no outbound calls of its own; this is admin-initiated and
	// fire-and-forget — a failure is logged and ignored because the links are
	// already in the HTTP response below.
	if rule.ReplyURL != "" {
		go a.postReply(rule.ReplyURL, resp)
	}

	writeJSON(w, http.StatusOK, resp)
}

// postReply POSTs the route response to the operator-configured reply_url. Best
// effort: bounded timeout, errors logged and swallowed.
func (a *API) postReply(replyURL string, resp routeResponse) {
	b, _ := json.Marshal(resp)
	ctx, cancel := context.WithTimeout(context.Background(), replyTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, replyURL, bytes.NewReader(b))
	if err != nil {
		a.log.Warn("route reply_url: bad url", "url", replyURL, "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	httpResp, err := http.DefaultClient.Do(req)
	if err != nil {
		a.log.Warn("route reply_url: post failed", "url", replyURL, "err", err)
		return
	}
	_ = httpResp.Body.Close()
}

// webBase resolves the base URL for join links: the configured [server].web_url,
// or — when unset — the inbound request's own host (so links work out of the box
// in a single-origin deployment).
func (a *API) webBase(r *http.Request) string {
	if a.cfg.Server.WebURL != "" {
		return a.cfg.Server.WebURL
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// joinLink builds the browser join URL for a room + one-time token.
func joinLink(base, room, token string) string {
	base = strings.TrimRight(base, "/")
	q := url.Values{"room": {room}, "token": {token}}
	return base + "/join?" + q.Encode()
}

func (a *API) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *API) version(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version":  buildinfo.Version,
		"protocol": protocol.Version,
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
