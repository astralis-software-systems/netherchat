// Package bridge implements the Two-Way Bridge (§1.6): a DECRYPTING room member
// that turns typed in-room events (decision/action/ack/seal/vanish/scuttle) into
// templated, provenance-carrying HTTP callbacks to the operator's OWN system.
//
// The honesty constraint is the whole point. The relay is blind — it cannot read
// a decision to act on it — so the bridge cannot be a server-side component. It
// joins as an ordinary client (reusing tui/client), decrypts the events it is
// subscribed to, and fires callbacks from the edge. Because the trigger is a real
// decrypted, signature-verified in-room frame, the callback can carry the
// ORIGINAL Ed25519 signature (X-Netherchat-Sig): provenance that a receiver can
// attribute to a specific key, not a server's say-so.
//
// EPHEMERALITY GUARD: callbacks are fire-and-forget with IN-MEMORY retry only
// (bounded exponential backoff). If the bridge process dies, undelivered
// callbacks die with it. This is intentional — a durable on-disk queue would
// re-introduce persistence and violate the product's zero-persistence constraint.
// For reliable delivery, run the bridge on stable infrastructure and make the
// receiver idempotent.
package bridge

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/record"
)

// StreamVersion is the "v" field of every --json bridge event. It is a stability
// contract for the bridge ndjson stream, bumped only on a breaking change.
const StreamVersion = 1

// DefaultEvents is the --on default: the three typed, per-event-signed actions
// (decision/action/ack). These are exactly the events that carry a clean,
// forwardable Ed25519 signature, which is why they are the default and seal /
// vanish / scuttle are opt-in.
const DefaultEvents = "decision,action,ack"

// defaultBackoff is the in-memory retry schedule: a first attempt, then up to
// three retries spaced 1s, 2s, 4s. Bounded and in-memory by design — see the
// package-level ephemerality guard.
var defaultBackoff = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}

// validEvents is the closed set of event types the bridge understands.
var validEvents = map[string]bool{
	"decision": true, "action": true, "ack": true,
	"seal": true, "vanish": true, "scuttle": true,
}

// Config configures a Bridge. The zero value is not usable; build one with New,
// which fills the operational defaults (HTTP client, backoff, output sink, clock).
type Config struct {
	Room     string             // room to watch (for headers / the .Room template var)
	On       map[string]bool    // subscribed event types (see validEvents)
	PostURL  string             // the operator's own callback endpoint
	Template *template.Template // POST-body template (DefaultTemplate if nil)

	// Operational knobs, all injectable for tests.
	HTTPClient *http.Client     // default: 10s-timeout client
	Backoff    []time.Duration  // retry schedule; default {1s,2s,4s}
	JSON       bool             // emit the ndjson stream instead of human lines
	Out        io.Writer        // where stream/human lines go; default os.Stdout
	Now        func() time.Time // clock; default time.Now
}

// Bridge maps client events to outbound callbacks and delivers them. It is safe
// for concurrent Fire calls — output writes are serialized by outMu so ndjson /
// human lines from concurrent deliveries never interleave.
type Bridge struct {
	cfg   Config
	outMu sync.Mutex
}

// New returns a Bridge, filling any unset operational defaults. PostURL and a
// non-empty On set are required.
func New(cfg Config) (*Bridge, error) {
	if cfg.PostURL == "" {
		return nil, errors.New("bridge: --post URL is required")
	}
	if len(cfg.On) == 0 {
		return nil, errors.New("bridge: at least one --on event type is required")
	}
	if cfg.Template == nil {
		t, err := ParseTemplate(DefaultTemplate)
		if err != nil {
			return nil, err
		}
		cfg.Template = t
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Backoff == nil {
		cfg.Backoff = defaultBackoff
	}
	if cfg.Out == nil {
		cfg.Out = os.Stdout
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Bridge{cfg: cfg}, nil
}

// Callback is a single matched, ready-to-deliver event. It carries everything a
// template and the provenance headers need — and nothing more: no room key, no
// room secret, no private material ever reaches this struct.
type Callback struct {
	Room     string
	Event    string    // decision | action | ack | seal | vanish | scuttle
	Actor    string    // display name of the person who triggered the event
	ActorFpr string    // Ed25519 fingerprint of the actor (SHA256:...)
	Text     string    // human-readable description (see §1.6 .Text rules)
	When     time.Time // event time (the .Ts template var, RFC3339)

	// Provenance. Sig is the actor's raw Ed25519 signature over the original
	// in-room frame; SignBytes is the exact protocol.SigningBytes(...) it covers,
	// so a verifier can check ed25519.Verify(actorPub, SignBytes, Sig). Both are
	// empty for events that travel as unsigned relay control frames (vanish,
	// scuttle) or that have no single per-event signature (seal). Raw is the raw
	// decrypted event JSON (for advanced templates via .Raw).
	Sig       []byte
	SignBytes []byte
	Raw       []byte
}

// Subscribed reports whether the bridge is configured to fire on event type.
func (b *Bridge) Subscribed(event string) bool { return b.cfg.On[event] }

// Match converts a client event into a Callback if the bridge is subscribed to
// its type. It returns (Callback{}, false) for events that are not bridgeable, not
// subscribed, or are this bridge's own echo (Self) — a bridge never fires on its
// own actions.
func (b *Bridge) Match(ev client.Event) (Callback, bool) {
	switch e := ev.(type) {
	case client.EvRecordEntry:
		if e.Self || e.Replayed {
			return Callback{}, false
		}
		switch e.Kind {
		case record.KindDecision:
			if !b.cfg.On["decision"] {
				return Callback{}, false
			}
			return b.build("decision", e.AuthorName, e.AuthorFpr, e.Body, e.At, e.Sig, e.SignBytes, e.Raw), true
		case record.KindAction:
			if !b.cfg.On["action"] {
				return Callback{}, false
			}
			// .Text for an action is "@handle: action text".
			text := "@" + e.Actionee + ": " + e.Body
			return b.build("action", e.AuthorName, e.AuthorFpr, text, e.At, e.Sig, e.SignBytes, e.Raw), true
		}
		return Callback{}, false // note (/mark) is not a bridge event type

	case client.EvAck:
		if e.Self || !b.cfg.On["ack"] {
			return Callback{}, false
		}
		// .Text for an ack is the tag text.
		return b.build("ack", e.Actor, e.Fpr, e.Tag, e.At, e.Sig, e.SignBytes, e.Raw), true

	case client.EvSealComplete:
		if !b.cfg.On["seal"] {
			return Callback{}, false
		}
		text := fmt.Sprintf("room sealed, %d decisions recorded", e.Entries)
		// A seal is multi-party co-signed; there is no single per-event signature to
		// forward. The actor is the sealer; its fingerprint is on the record.
		var fpr string
		if e.Record != nil {
			fpr = e.Record.SealedBy
		}
		return b.build("seal", "", fpr, text, b.cfg.Now(), nil, nil, nil), true

	case client.EvControl:
		switch e.Action {
		case protocol.ActionVanish:
			if e.Self || !b.cfg.On["vanish"] {
				return Callback{}, false
			}
			text := "room keys rotated by @" + e.ByName
			// Control frames are unsigned relay actions: no per-event signature, no fpr.
			return b.build("vanish", e.ByName, "", text, b.cfg.Now(), nil, nil, nil), true
		case protocol.ActionScuttle:
			if e.Self || !b.cfg.On["scuttle"] {
				return Callback{}, false
			}
			text := "room scuttled, reason: " + e.Reason
			return b.build("scuttle", e.ByName, "", text, b.cfg.Now(), nil, nil, nil), true
		}
		return Callback{}, false
	}
	return Callback{}, false
}

// build assembles a Callback for the bridge's room.
func (b *Bridge) build(event, actor, fpr, text string, when time.Time, sig, signBytes, raw []byte) Callback {
	return Callback{
		Room: b.cfg.Room, Event: event, Actor: actor, ActorFpr: fpr,
		Text: text, When: when, Sig: sig, SignBytes: signBytes, Raw: raw,
	}
}

// label is the short tag used in the human output line. Acks carry their tag so
// distinct acks are distinguishable at a glance (e.g. "ack:drain-complete").
func (cb Callback) label() string {
	if cb.Event == "ack" && cb.Text != "" {
		return "ack:" + cb.Text
	}
	return cb.Event
}

// sigB64 is the base64 of the original Ed25519 signature, or "" when the event
// carries none (unsigned control frames / seal).
func (cb Callback) sigB64() string {
	if len(cb.Sig) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(cb.Sig)
}

// ParseEvents parses a comma-separated --on list into a subscription set,
// rejecting unknown types. An empty/whitespace-only list is an error.
func ParseEvents(s string) (map[string]bool, error) {
	out := make(map[string]bool)
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !validEvents[p] {
			return nil, fmt.Errorf("unknown event type %q (valid: decision, action, ack, seal, vanish, scuttle)", p)
		}
		out[p] = true
	}
	if len(out) == 0 {
		return nil, errors.New("no event types given to --on")
	}
	return out, nil
}

// DefaultTemplate is the built-in POST body used when --template is not given. It
// is the §1.6 default made injection-safe: each value is rendered through the
// `json` helper so a decision/ack containing a quote or newline still produces
// valid JSON. For clean inputs the output is byte-for-byte the documented shape.
//
// .RoomSecret is deliberately NOT a template variable — key material can never be
// exfiltrated through a template.
const DefaultTemplate = `{
  "room":      {{json .Room}},
  "event":     {{json .Event}},
  "actor":     {{json .Actor}},
  "actor_fpr": {{json .ActorFpr}},
  "text":      {{json .Text}},
  "ts":        {{json .Ts}},
  "sig":       {{json .Sig}}
}
`

// tmplFuncs are available to every template. `json` marshals a value to a JSON
// literal (a quoted, escaped string for strings) so a template can embed
// arbitrary text safely.
var tmplFuncs = template.FuncMap{
	"json": func(v any) (string, error) {
		b, err := json.Marshal(v)
		return string(b), err
	},
}

// ParseTemplate compiles a POST-body template with the bridge helper functions.
func ParseTemplate(text string) (*template.Template, error) {
	return template.New("bridge").Funcs(tmplFuncs).Parse(text)
}

// tmplData is what a POST-body template renders against. The field set is the
// §1.6 contract; note the absence of any key material.
//
// Raw is a string (not json.RawMessage) so `{{.Raw}}` inserts the decrypted event
// JSON verbatim — text/template does not escape, and a named []byte would render
// as its byte values, not its text. It is "" for events with no decrypted body
// (unsigned control frames / seal).
type tmplData struct {
	Room     string
	Event    string
	Actor    string
	ActorFpr string
	Text     string
	Ts       string // RFC3339
	Sig      string // base64 of the original Ed25519 signature ("" if none)
	Raw      string // the raw decrypted event JSON (for advanced templates)
}
