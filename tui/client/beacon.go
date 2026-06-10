package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// This file holds the client-side Status Beacon machinery (§1.2): publish a single
// mutable status line to out-of-band stakeholders through a short-TTL link,
// encrypted to a beacon key DERIVED from but DISTINCT from the room message key.
// The content travels over REST (PUT/GET/DELETE /beacon/<room>) as opaque
// ciphertext — the relay never sees the status; a separate, metadata-only OpControl
// broadcast lets a `tail --json` observer record the change. A reader who holds the
// beacon key (handed out in the beacon link) can read the status but NEVER the room
// messages.

// beaconHTTP is the bounded HTTP client for the beacon REST calls.
var beaconHTTP = &http.Client{Timeout: 10 * time.Second}

// UseBeaconToken sets the per-room token used to authorize beacon writes
// (PUT/DELETE). Read-only GETs need no token. Configured from netherchat.toml.
func (c *Client) UseBeaconToken(token string) { c.beaconToken = token }

// BeaconKeyB64 returns the base64 beacon key derived from the current room key —
// the value embedded in a beacon link, which is all a reader needs to decrypt the
// status (and nothing else). ok is false before the room key is established.
func (c *Client) BeaconKeyB64() (string, bool) {
	c.mu.Lock()
	rk := c.rk
	c.mu.Unlock()
	if rk == nil {
		return "", false
	}
	bk := crypto.BeaconKey(*rk)
	return base64.StdEncoding.EncodeToString(bk[:]), true
}

// SetBeacon encrypts status under the beacon key and stores it on the relay (PUT),
// then broadcasts a metadata-only beacon_set notice so observers log it. Async:
// the result arrives as EvBeaconResult.
func (c *Client) SetBeacon(status string, ttlSeconds int) {
	c.mu.Lock()
	rk := c.rk
	c.mu.Unlock()
	if rk == nil {
		c.emit(EvBeaconResult{Action: "set", Err: "room key not established yet"})
		return
	}
	blob, err := crypto.SealBeacon(crypto.BeaconKey(*rk), status)
	if err != nil {
		c.emit(EvBeaconResult{Action: "set", Err: err.Error()})
		return
	}
	go func() {
		if err := c.beaconPut(blob, ttlSeconds); err != nil {
			c.emit(EvBeaconResult{Action: "set", Err: err.Error()})
			return
		}
		c.enqueue(protocol.OpControl, protocol.Control{Action: protocol.ActionBeaconSet, ByName: c.name, TTLSeconds: ttlSeconds})
		c.emit(EvBeaconResult{Action: "set", OK: true})
	}()
}

// ClearBeacon deletes this room's beacon (DELETE) and announces it. Async.
func (c *Client) ClearBeacon() {
	go func() {
		if err := c.beaconDelete(); err != nil {
			c.emit(EvBeaconResult{Action: "clear", Err: err.Error()})
			return
		}
		c.enqueue(protocol.OpControl, protocol.Control{Action: protocol.ActionBeaconCleared, ByName: c.name})
		c.emit(EvBeaconResult{Action: "clear", OK: true})
	}()
}

// FetchBeaconStatus reads the room's beacon (GET) and decrypts it locally with the
// beacon key. Async: the result arrives as EvBeaconStatus (Set=false if none).
func (c *Client) FetchBeaconStatus() {
	c.mu.Lock()
	rk := c.rk
	c.mu.Unlock()
	if rk == nil {
		c.emit(EvBeaconStatus{Err: "room key not established yet"})
		return
	}
	bk := crypto.BeaconKey(*rk)
	go func() {
		resp, err := beaconHTTP.Get(c.beaconURL())
		if err != nil {
			c.emit(EvBeaconStatus{Err: err.Error()})
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			c.emit(EvBeaconStatus{Set: false})
			return
		}
		if resp.StatusCode != http.StatusOK {
			c.emit(EvBeaconStatus{Err: "server returned " + resp.Status})
			return
		}
		var body struct {
			Ciphertext string `json:"ciphertext"`
			UpdatedAt  string `json:"updated_at"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			c.emit(EvBeaconStatus{Err: err.Error()})
			return
		}
		blob, err := base64.StdEncoding.DecodeString(body.Ciphertext)
		if err != nil {
			c.emit(EvBeaconStatus{Err: "bad ciphertext: " + err.Error()})
			return
		}
		text, err := crypto.OpenBeacon(bk, blob)
		if err != nil {
			c.emit(EvBeaconStatus{Err: err.Error()})
			return
		}
		ts, _ := time.Parse(time.RFC3339, body.UpdatedAt)
		c.emit(EvBeaconStatus{Set: true, Text: text, UpdatedAt: ts})
	}()
}

// --- REST plumbing ----------------------------------------------------------

func (c *Client) beaconURL() string {
	return c.httpBase() + "/beacon/" + url.PathEscape(c.room)
}

func (c *Client) beaconPut(blob []byte, ttlSeconds int) error {
	body, _ := json.Marshal(map[string]any{
		"ciphertext":  base64.StdEncoding.EncodeToString(blob),
		"ttl_seconds": ttlSeconds,
	})
	req, err := http.NewRequest(http.MethodPut, c.beaconURL(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Netherchat-Token", c.beaconToken)
	return doBeacon(req)
}

func (c *Client) beaconDelete() error {
	req, err := http.NewRequest(http.MethodDelete, c.beaconURL(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Netherchat-Token", c.beaconToken)
	return doBeacon(req)
}

func doBeacon(req *http.Request) error {
	resp, err := beaconHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("beacon %s failed: server returned %s", req.Method, resp.Status)
	}
	return nil
}

// httpBase derives the relay's http(s):// origin from its ws(s):// URL.
func (c *Client) httpBase() string {
	u, err := url.Parse(c.url)
	if err != nil {
		return c.url
	}
	switch u.Scheme {
	case "ws":
		u.Scheme = "http"
	case "wss":
		u.Scheme = "https"
	}
	u.Path, u.RawQuery, u.Fragment = "", "", ""
	return u.String()
}
