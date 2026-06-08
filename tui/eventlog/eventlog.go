// Package eventlog defines Netherchat's structured event stream (§1.7): a
// versioned, stable, metadata-only JSON schema emitted by `netherchat tail
// --json` and `netherchat agent --json`. Engineers pipe it into jq / Vector /
// Loki to build an auditable incident timeline with zero content leakage —
// message bodies are NEVER included unless --include-bodies is passed.
//
// The schema (schema.json, embedded) is the contract; `netherchat schema` prints
// it. The "v" field is the schema version and is bumped only on a breaking
// change.
package eventlog

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"time"
)

// SchemaVersion is the value of every event's "v" field.
const SchemaVersion = 1

//go:embed schema.json
var schemaJSON []byte

// SchemaJSON returns the embedded JSON Schema (draft-07) for v1 events.
func SchemaJSON() string { return string(schemaJSON) }

// Event is one line of the ndjson stream. Optional fields are omitempty;
// booleans and ints that must be explicit when present (e.g. signed=false,
// body_len=0) use pointers so they are emitted rather than dropped.
type Event struct {
	V        int    `json:"v"`
	TS       string `json:"ts"`
	Type     string `json:"type"`
	Room     string `json:"room,omitempty"`
	Actor    string `json:"actor,omitempty"`
	Fpr      string `json:"fpr,omitempty"`
	Verified *bool  `json:"verified,omitempty"`
	Signed   *bool  `json:"signed,omitempty"`
	BodyLen  *int   `json:"body_len,omitempty"`
	BodyHash string `json:"body_hash,omitempty"`
	Body     string `json:"body,omitempty"`
	Tag      string `json:"tag,omitempty"`
	Quorum   string `json:"quorum,omitempty"` // "<acked>/<members>" for ack events

	Target    string `json:"target,omitempty"`
	TargetFpr string `json:"target_fpr,omitempty"`
	OK        *bool  `json:"ok,omitempty"`

	// Handoff (§2.2): the incident-commander token moved from -> to.
	From    string `json:"from,omitempty"`
	FromFpr string `json:"from_fpr,omitempty"`
	To      string `json:"to,omitempty"`
	ToFpr   string `json:"to_fpr,omitempty"`

	Cmd     string `json:"cmd,omitempty"`
	Allowed *bool  `json:"allowed,omitempty"`
	Exit    *int   `json:"exit,omitempty"`

	// Auto-war-room (§1.3): an alert route fired and spawned an incident room.
	TriggerRule *int     `json:"trigger_rule,omitempty"`
	Invitees    []string `json:"invitees,omitempty"`
	TTLSeconds  int      `json:"ttl_seconds,omitempty"`

	// Auto-scuttle (§1.6): the room burned its keys and closed. Reason is why;
	// TTLRemaining is always 0 (the room is gone) and is a pointer so it emits.
	Reason       string `json:"reason,omitempty"`
	TTLRemaining *int   `json:"ttl_remaining,omitempty"`

	// Ephemeral artifact relay (§2.3): a transfer was offered / completed. The
	// filename and size are metadata the receiving client decrypted — the relay
	// never saw them. OK (reused) reports the integrity result on file_complete.
	Filename   string `json:"filename,omitempty"`
	SizeBytes  int64  `json:"size_bytes,omitempty"`
	TransferID string `json:"transfer_id,omitempty"`

	Epoch   *uint64 `json:"epoch,omitempty"`
	Message string  `json:"message,omitempty"`
}

// Bool / Int return pointers, for setting optional pointer fields inline.
func Bool(b bool) *bool { return &b }
func Int(i int) *int    { return &i }

// HashBody returns the SHA-256 of a plaintext body as "sha256:<hex>".
func HashBody(body string) string {
	sum := sha256.Sum256([]byte(body))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// nowUTC is overridable in tests for deterministic timestamps.
var nowUTC = func() string { return time.Now().UTC().Format(time.RFC3339) }

func base(typ, room string) Event {
	return Event{V: SchemaVersion, TS: nowUTC(), Type: typ, Room: room}
}

// --- constructors -----------------------------------------------------------

func Join(room, actor, fpr string, verified bool) Event {
	e := base("join", room)
	e.Actor, e.Fpr, e.Verified = actor, fpr, Bool(verified)
	return e
}

func Leave(room, actor, fpr string) Event {
	e := base("leave", room)
	e.Actor, e.Fpr = actor, fpr
	return e
}

// Message builds a message event. The body is hashed (always) and length-counted
// (always); the body itself is included ONLY when includeBody is true.
func Message(room, actor, fpr string, signed, verified bool, body string, includeBody bool) Event {
	e := base("message", room)
	e.Actor, e.Fpr = actor, fpr
	e.Signed, e.Verified = Bool(signed), Bool(verified)
	e.BodyLen = Int(len(body))
	e.BodyHash = HashBody(body)
	if includeBody {
		e.Body = body
	}
	return e
}

func Vanish(room, actor, fpr string) Event {
	e := base("vanish", room)
	e.Actor, e.Fpr = actor, fpr
	return e
}

// Scuttle builds a dead-man's-switch event (§1.6). reason is one of
// protocol.Scuttle* (idle | owner_loss | manual | armed). ttl_remaining is always
// 0 — the room is gone — and is emitted explicitly as the auditable record that
// the room scuttled (never any content).
func Scuttle(room, reason string) Event {
	e := base("scuttle", room)
	e.Reason = reason
	e.TTLRemaining = Int(0)
	return e
}

// Ack builds an ack event (§2.2). quorum is the "<acked>/<members>" count at the
// moment the ack was counted, from the emitting client's view.
func Ack(room, actor, fpr, tag, quorum string) Event {
	e := base("ack", room)
	e.Actor, e.Fpr, e.Tag, e.Quorum = actor, fpr, tag, quorum
	return e
}

// Handoff builds an incident-commander handoff event (§2.2).
func Handoff(room, from, fromFpr, to, toFpr string) Event {
	e := base("handoff", room)
	e.From, e.FromFpr, e.To, e.ToFpr = from, fromFpr, to, toFpr
	return e
}

// RouteFired builds an auto-war-room event (§1.3). room is the spawned incident
// room (not the intake room the rule matched on).
func RouteFired(room string, triggerRule int, invitees []string, ttlSeconds int) Event {
	e := base("route_fired", room)
	e.TriggerRule = Int(triggerRule)
	e.Invitees = invitees
	e.TTLSeconds = ttlSeconds
	return e
}

func Verify(room, actor, fpr, target, targetFpr string, ok bool) Event {
	e := base("verify", room)
	e.Actor, e.Fpr, e.Target, e.TargetFpr, e.OK = actor, fpr, target, targetFpr, Bool(ok)
	return e
}

// ExecRequest builds an exec_request event. allowed is nil for a passive tail
// observer (which can't know the agent's decision) and set for an agent's own
// stream.
func ExecRequest(room, actor, fpr, cmd string, allowed *bool) Event {
	e := base("exec_request", room)
	e.Actor, e.Fpr, e.Cmd, e.Allowed = actor, fpr, cmd, allowed
	return e
}

func ExecResult(room, actor, fpr, cmd string, allowed bool, exit int) Event {
	e := base("exec_result", room)
	e.Actor, e.Fpr, e.Cmd, e.Allowed, e.Exit = actor, fpr, cmd, Bool(allowed), Int(exit)
	return e
}

// FileOffer builds a file_offer event (§2.3): a receiver decrypted an artifact
// transfer offer. The filename/size are metadata the relay never saw.
func FileOffer(room, actor, fpr, filename string, size int64, transferID string) Event {
	e := base("file_offer", room)
	e.Actor, e.Fpr, e.Filename, e.SizeBytes, e.TransferID = actor, fpr, filename, size, transferID
	return e
}

// FileComplete builds a file_complete event: a transfer finished. ok is true when
// the artifact verified (sha256) and was written; false on integrity/abort/error.
func FileComplete(room, actor, fpr, filename string, size int64, transferID string, ok bool) Event {
	e := base("file_complete", room)
	e.Actor, e.Fpr, e.Filename, e.SizeBytes, e.TransferID, e.OK = actor, fpr, filename, size, transferID, Bool(ok)
	return e
}

func KeyReady(room string, epoch uint64) Event {
	e := base("key_ready", room)
	e.Epoch = &epoch
	return e
}

func ErrorEvent(room, message string) Event {
	e := base("error", room)
	e.Message = message
	return e
}

func Disconnect(room, message string) Event {
	e := base("disconnect", room)
	e.Message = message
	return e
}
