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
	"github.com/salehkreiner/netherchat/server/internal/alert"
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
	guards    *alert.Guards
	log       *slog.Logger
}

// New constructs an API bound to the hub, config, invite store, ephemeral
// registry, beacon store, and per-source ingress guards (NC-1).
func New(h *hub.Hub, cfg config.Config, invites *invite.Store, eph *ephemeral.Registry, beacons *beacon.Store, guards *alert.Guards, log *slog.Logger) *API {
	if log == nil {
		log = slog.Default()
	}
	return &API{hub: h, cfg: cfg, invites: invites, ephemeral: eph, beacons: beacons, guards: guards, log: log}
}

// Register wires the REST routes onto the mux. Go 1.22+ method+path patterns.
func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", a.health)
	mux.HandleFunc("GET /version", a.version)
	mux.HandleFunc("GET /rooms", a.rooms)
	// Config-as-code validation (B1): the Terraform provider POSTs a proposed
	// netherchat.toml here to fail a plan early. Read-only — nothing is applied.
	mux.HandleFunc("POST /api/v1/config/validate", a.configValidate)
	// Generic signed ingress socket (NC-1): a registered [[source]] POSTs a
	// schema-valid metadata alert; a matching [[route]] spawns a break-glass war
	// room. Detection only — it can open a room and post a notice, never act.
	mux.HandleFunc("POST /api/v1/alert", a.alert)
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

// spawnResult bundles what a spawned war room yields its caller.
type spawnResult struct {
	resp     routeResponse
	room     ephemeral.Room
	invitees []string
	ttl      time.Duration
}

// spawnWarRoom is the shared core of the auto-war-room, used by BOTH the per-room
// webhook (fireRoute) and the generic alert socket (alert). It creates an
// ephemeral break-glass room — carrying an optional marked-plaintext join notice —
// mints a one-time invite link per invitee, fires the rule's reply_url
// best-effort, and returns the response. `by` is a short provenance label
// ("webhook:<room>" / "alert:<source>"); `base` is the join-link origin. ok is
// false only when the auto-war-room machinery is unavailable.
//
// This is the ONLY thing an inbound trigger can do: open an invite-only room and
// post a plaintext notice. It constructs no end-to-end op and cannot approve,
// seal, or execute — those are client-signed, room-keyed messages a blind relay
// can never forge (the second law).
func (a *API) spawnWarRoom(rule config.RouteConfig, by, notice, base string) (spawnResult, bool) {
	if a.ephemeral == nil || a.invites == nil {
		return spawnResult{}, false
	}
	ttl := ephemeral.ClampTTL(rule.TTL.Std())
	prefix := rule.RoomPrefix
	if prefix == "" {
		prefix = "inc"
	}
	room := a.ephemeral.CreateNamedNotice(ttl, by, prefix, notice)

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
		tok, _ := a.invites.Generate(room.Name, ttl)
		links[name] = joinLink(base, room.Name, tok)
	}

	resp := routeResponse{Room: room.Name, Links: links}

	// reply_url is the operator's OWN system (e.g. a PagerDuty note endpoint).
	// Astralis makes no outbound calls of its own; this is admin-initiated and
	// fire-and-forget — a failure is logged and ignored because the links are
	// already in the HTTP response.
	if rule.ReplyURL != "" {
		go a.postReply(rule.ReplyURL, resp)
	}
	return spawnResult{resp: resp, room: room, invitees: invitees, ttl: ttl}, true
}

// fireRoute spawns the incident war room for a matched WEBHOOK rule and, unlike the
// alert socket, also notifies the intake room's observers (route_fired) so the
// auto-war-room shows up in their structured event stream. Room-creation
// unavailability is the only 500 path.
func (a *API) fireRoute(w http.ResponseWriter, r *http.Request, intakeRoom string, idx int, rule config.RouteConfig) {
	res, ok := a.spawnWarRoom(rule, "webhook:"+intakeRoom, "", a.webBase(r))
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "auto-war-room is unavailable"})
		return
	}

	a.log.Info("auto-war-room fired", "intake", intakeRoom, "room", res.room.Name,
		"trigger_rule", idx, "invitees", len(res.invitees), "ttl", res.ttl.String())

	// Tell the intake room's members (e.g. `tail #alerts --json`) that a room was
	// spawned, so the auto-war-room shows up in the structured event stream.
	fired, _ := protocol.Encode(protocol.OpRouteFired, protocol.RouteFired{
		Room:        res.room.Name,
		TriggerRule: idx,
		Invitees:    res.invitees,
		TTLSeconds:  int(res.ttl.Seconds()),
		At:          time.Now().Unix(),
	})
	a.hub.Broadcast(intakeRoom, "", fired)

	writeJSON(w, http.StatusOK, res.resp)
}

// alertResponse is the JSON returned by the generic ingress socket.
type alertResponse struct {
	Accepted bool              `json:"accepted"`
	Spawned  bool              `json:"spawned"`
	Room     string            `json:"room,omitempty"`
	Links    map[string]string `json:"links,omitempty"`
}

// alert is the generic signed ingress socket (NC-1). A registered [[source]] POSTs
// a schema-valid metadata alert; if a [[route]] matches, a break-glass war room is
// spawned with one-time invites and a marked-plaintext join notice. Detection
// only — it opens a room and posts a notice; it can never approve, seal, or
// execute (the second law; see spawnWarRoom).
//
// Every rejection (malformed body, unknown source, bad auth, over rate/spawn cap)
// is logged as METADATA ONLY and spawns nothing.
func (a *API) alert(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	al, err := alert.Parse(raw)
	if err != nil {
		a.log.Warn("alert rejected: malformed", "err", err.Error(), "remote", r.RemoteAddr)
		http.Error(w, "invalid alert: "+err.Error(), http.StatusBadRequest)
		return
	}

	src, ok := a.cfg.Source(al.Source)
	if !ok {
		a.log.Warn("alert rejected: unknown source", "source", al.Source, "remote", r.RemoteAddr)
		http.Error(w, "unknown or unauthenticated source", http.StatusUnauthorized)
		return
	}
	if !a.guards.AllowRequest(src) {
		a.log.Warn("alert rejected: rate limited", "source", al.Source)
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	headerToken := r.Header.Get("X-Netherchat-Token")
	if headerToken == "" {
		headerToken = r.URL.Query().Get("token")
	}
	if err := alert.Authenticate(src, al, headerToken); err != nil {
		a.log.Warn("alert rejected: auth failed", "source", al.Source, "err", err.Error())
		http.Error(w, "unknown or unauthenticated source", http.StatusUnauthorized)
		return
	}

	// Freshness gate (NC-1): the ts is inside the HMAC preimage that just verified, so
	// a replayed alert carries an old, signed ts and is rejected here — after auth (we
	// only trust a covered ts) and before route.Match (so EVERY replay is visible, not
	// just route-matching ones). Inert for token-only sources; one-time WARN when an
	// HMAC source sends no timestamp under the baseline.
	if ok, reason, warn := a.guards.AllowFresh(src, al.TS, a.cfg.Ingest.Freshness); !ok {
		a.log.Warn("alert rejected: "+reason, "source", al.Source, "ts", al.TS, "now", time.Now().Unix())
		http.Error(w, "alert rejected: "+reason, http.StatusBadRequest)
		return
	} else if warn != "" {
		a.log.Warn(warn, "source", al.Source)
	}

	// Route on metadata only. No match is a success (the alert was authenticated and
	// accepted) that simply spawns nothing.
	idx, rule, matched := route.Match(a.cfg.Routes, al.ToMatchMap())
	if !matched {
		a.log.Info("alert accepted, no route matched", "source", al.Source, "severity", al.Severity, "kind", al.Kind)
		writeJSON(w, http.StatusOK, alertResponse{Accepted: true, Spawned: false})
		return
	}
	if !a.guards.AllowSpawn(src) {
		a.log.Warn("alert matched but spawn cap exceeded", "source", al.Source)
		http.Error(w, "spawn cap exceeded", http.StatusTooManyRequests)
		return
	}

	res, ok := a.spawnWarRoom(rule, "alert:"+al.Source, al.NoticeLine(), a.webBase(r))
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "auto-war-room is unavailable"})
		return
	}
	a.log.Info("alert spawned war room", "source", al.Source, "severity", al.Severity, "kind", al.Kind,
		"room", res.room.Name, "trigger_rule", idx, "invitees", len(res.invitees), "ttl", res.ttl.String())
	writeJSON(w, http.StatusOK, alertResponse{Accepted: true, Spawned: true, Room: res.room.Name, Links: res.resp.Links})
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

// configValidate checks a proposed netherchat.toml without applying it (B1). The
// request body is the candidate TOML; the response is {"valid":true} or
// {"valid":false,"error":"..."}. The Terraform provider calls this so an invalid
// topology fails `terraform plan` rather than a later server restart. It is
// strictly read-only: nothing is written, applied, or persisted, and — like every
// endpoint here — no message content is ever involved.
//
// A malformed body is reported as valid:false (a client error about the content),
// not an HTTP error about the request, so callers branch on one field.
func (a *API) configValidate(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 256<<10))
	if err != nil {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	if _, err := config.Parse(raw); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"valid": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
