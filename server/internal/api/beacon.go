package api

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// Status Beacon REST handlers (§1.2). The beacon is the ONE place the relay holds
// room state — one mutable, TTL'd ciphertext blob per room — and it holds ONLY
// ciphertext: the beacon key (HKDF of the room secret) never reaches the server,
// so the relay can store and serve a beacon's status without ever reading it.
//
//	PUT    /beacon/<room>   set/overwrite (token-gated)   { ciphertext, ttl_seconds }
//	GET    /beacon/<room>   read (no auth)                -> { ciphertext, updated_at } | 404
//	DELETE /beacon/<room>   clear (token-gated)
//
// Writes require the room's beacon_token (or its webhook_token as a fallback); a
// room configured with neither cannot have a beacon — strictly opt-in.

const maxBeaconBlob = 16 << 10 // generous cap for an encrypted status line

// beaconPut stores (overwriting) a room's beacon ciphertext with a clamped TTL.
func (a *API) beaconPut(w http.ResponseWriter, r *http.Request) {
	room := r.PathValue("room")
	policy := a.cfg.Room(room)
	want, enabled := policy.BeaconAuth()
	if !enabled {
		http.Error(w, "beacon is not enabled for this room", http.StatusNotFound)
		return
	}
	if !beaconAuthorized(r, want) {
		a.rejectBeaconWrite(w, r, room)
		return
	}

	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBeaconBlob+1<<10))
	if err != nil {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	var body struct {
		Ciphertext string `json:"ciphertext"`
		TTLSeconds int    `json:"ttl_seconds"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		http.Error(w, `expected JSON {"ciphertext":"<base64>","ttl_seconds":N}`, http.StatusBadRequest)
		return
	}
	ct, err := base64.StdEncoding.DecodeString(body.Ciphertext)
	if err != nil || len(ct) == 0 {
		http.Error(w, "ciphertext must be non-empty base64", http.StatusBadRequest)
		return
	}
	if len(ct) > maxBeaconBlob {
		http.Error(w, "ciphertext too large", http.StatusRequestEntityTooLarge)
		return
	}

	ttl := policy.BeaconLifetime(body.TTLSeconds)
	a.beacons.Set(room, ct, ttl)
	a.log.Info("beacon set", "room", room, "ttl", ttl.String(), "bytes", len(ct))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// beaconGet returns a room's current beacon ciphertext, or 404 if none/expired. No
// auth: the blob is opaque without the beacon key, which the server never holds. A
// permissive CORS header lets a beacon page served from another origin read it.
func (a *API) beaconGet(w http.ResponseWriter, r *http.Request) {
	room := r.PathValue("room")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	e, ok := a.beacons.Get(room)
	if !ok {
		http.Error(w, "no beacon set for this room", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ciphertext": base64.StdEncoding.EncodeToString(e.Ciphertext),
		"updated_at": e.UpdatedAt.UTC().Format(time.RFC3339),
	})
}

// beaconDelete clears a room's beacon (the /beacon clear command).
func (a *API) beaconDelete(w http.ResponseWriter, r *http.Request) {
	room := r.PathValue("room")
	want, enabled := a.cfg.Room(room).BeaconAuth()
	if !enabled {
		http.Error(w, "beacon is not enabled for this room", http.StatusNotFound)
		return
	}
	if !beaconAuthorized(r, want) {
		a.rejectBeaconWrite(w, r, room)
		return
	}
	a.beacons.Delete(room)
	a.log.Info("beacon cleared", "room", room)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// rejectBeaconWrite refuses an unauthorized PUT/DELETE and records the attempt,
// following the "<endpoint> rejected: <reason>" convention the webhook receiver
// and the alert socket use for theirs. Without it a run of guesses against a
// room's beacon token leaves no trace at all in the relay's logs.
//
// METADATA ONLY: the room and the method, never the presented token or any part
// of it. A log line that echoed a guess back would put candidate secrets — and,
// on a near miss, most of a real one — into a file with none of the protections
// the token itself gets, which is also why the reason is fixed text rather than
// anything derived from what the caller sent.
func (a *API) rejectBeaconWrite(w http.ResponseWriter, r *http.Request, room string) {
	a.log.Warn("beacon rejected: invalid or missing token", "room", room, "method", r.Method)
	http.Error(w, "invalid or missing beacon token", http.StatusUnauthorized)
}

// beaconAuthorized reports whether r carries the token that authorizes beacon
// writes for the room. The compare is constant-time, matching the webhook
// receiver above and the alert socket (internal/alert): BeaconAuth deliberately
// lets a room reuse its webhook_token for the beacon, so the very same secret is
// checked by both endpoints and must not be checked two different ways depending
// on which one the caller reaches for.
//
// An empty want never authorizes. BeaconAuth reports enabled only when a token is
// configured, so want is non-empty at both call sites today; not leaning on that
// is what keeps a missing header from ever comparing equal to an unset token.
func beaconAuthorized(r *http.Request, want string) bool {
	return want != "" && subtle.ConstantTimeCompare([]byte(beaconToken(r)), []byte(want)) == 1
}

// beaconToken extracts the auth token from the X-Netherchat-Token header or the
// ?token= query param (mirrors the webhook receiver).
func beaconToken(r *http.Request) string {
	if t := r.Header.Get("X-Netherchat-Token"); t != "" {
		return t
	}
	return r.URL.Query().Get("token")
}
