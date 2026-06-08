package client

import (
	"time"

	"github.com/salehkreiner/netherchat/tui/record"
)

// Event is something the client core surfaces to its consumer (the TUI or a
// test). Consumers receive these on Events() and stop when Done() is closed.
type Event interface{ isEvent() }

// ConnMember identifies an already-present room member.
type ConnMember struct {
	ID          string
	Name        string
	Fingerprint string // ssh-keygen-format fingerprint of the member's identity key
}

// EvConnected is emitted once, after the server's Welcome is processed.
type EvConnected struct {
	SelfID      string
	YouAreFirst bool
	Members     []ConnMember // members already present
	InviteOnly  bool
	Webhook     bool
	TTLSeconds  int
}

// EvServerMessage is a plaintext, server-originated message (webhook/system/exec
// output). It is NOT end-to-end encrypted; the UI marks it as such.
type EvServerMessage struct {
	Kind string // "webhook" | "system" | "exec"
	From string
	Text string
	At   time.Time
}

// EvControl is a relayed room control action (vanish/ttl/scuttle/scuttle_arm).
type EvControl struct {
	Action     string
	ByName     string
	Self       bool   // true if this client initiated it
	TTLSeconds int    // ttl seconds, or the scuttle_arm countdown
	Reason     string // for scuttle: why (idle | owner_loss | manual | armed)
}

// EvExecRequest is a decrypted, signature-verified edge-exec request seen in the
// room (someone ran /exec). The TUI shows it; a netherchat agent acts on it.
type EvExecRequest struct {
	ID              string
	Cmd             string
	FromID          string
	FromName        string
	FromFingerprint string // ssh fingerprint of the requester's identity key
	Self            bool   // true for our own request (local echo)
	Signed          bool   // true if the request carried a valid Ed25519 signature
	At              time.Time
}

// EvExecResult is a decrypted, signature-verified edge-exec result posted by an
// agent. FromFingerprint identifies the host identity that ran the command.
type EvExecResult struct {
	ID              string
	Cmd             string
	Allowed         bool
	ExitCode        int
	Output          string
	FromName        string
	FromFingerprint string
	At              time.Time
}

// EvInvite carries a minted invite token in response to /invite.
type EvInvite struct {
	Room    string
	Token   string
	Expires time.Time
}

// BreakGlassInvite pairs an invited person with their one-time token.
type BreakGlassInvite struct {
	Name  string
	Token string
}

// EvBreakGlass is emitted in response to /break-glass: a freshly created
// ephemeral war room, its hard expiry, a host token for the creator to join with,
// and one-time tokens for each invited person.
type EvBreakGlass struct {
	Room       string
	TTLSeconds int
	Expires    time.Time
	HostToken  string
	Invites    []BreakGlassInvite
}

// EvRouteFired is emitted to members of a webhook (intake) room when an inbound
// alert matched a [[route]] rule and the server spawned an incident war room
// (§1.3). Room is the NEW incident room. It is informational — the invitees
// receive their join links out of band (the webhook response / reply_url).
type EvRouteFired struct {
	Room        string
	TriggerRule int
	Invitees    []string
	TTLSeconds  int
	At          time.Time
}

// EvKeyReady is emitted when this client holds the room key for an epoch and can
// send and receive messages.
type EvKeyReady struct{ Epoch uint64 }

// EvAck is a decrypted, signature-verified coordination ack (§2.2): someone ran
// /ack <tag>. Quorum is the running "<acked>/<members>" count from THIS client's
// view of the room at the moment the ack was counted. Self marks our own echo.
type EvAck struct {
	Tag    string
	Actor  string // display name of the acker
	Fpr    string // ssh fingerprint of the acker's identity key
	Quorum string // e.g. "3/6"
	Self   bool
	At     time.Time
}

// EvHandoff is a decrypted, signature-verified incident-commander handoff (§2.2):
// the IC token moved from one identity to another. Self marks our own echo.
type EvHandoff struct {
	FromName string
	FromFpr  string
	ToName   string
	ToFpr    string
	Self     bool
	At       time.Time
}

// EvRecordEntry is a decrypted, signature-verified sealed-record entry (§1.4):
// someone ran /decide, /action, or /mark, and the entry was appended to this
// client's chain. Self marks our own echo; Replayed marks an entry streamed in
// from a prior record during a retro (§2.7).
type EvRecordEntry struct {
	Seq        uint64
	Kind       string // decision | action | note
	AuthorName string
	AuthorFpr  string
	Actionee   string
	Body       string
	Self       bool
	Replayed   bool
	At         time.Time
}

// EvSealRequest is emitted when a seal of the record is proposed (§1.4): either
// by us (Self) or by another participant. Matches reports whether the proposer's
// chain head equals ours — only then can we honestly co-sign. NumEntries is the
// chain length at the proposed head.
type EvSealRequest struct {
	ByName     string
	Matches    bool
	NumEntries int
	Self       bool
}

// EvSealAck is emitted as co-signatures arrive during a seal we initiated:
// ByName co-signed, bringing the running total to Count of Total present members.
// Self marks our own co-signature when acking someone else's request.
type EvSealAck struct {
	ByName string
	Count  int
	Total  int
	Self   bool
}

// EvSealComplete is emitted to the sealer (the participant who initiated and
// collected signatures) when the record is finalized — all present members
// co-signed, or the 30s window elapsed. Record is ready to write to disk.
type EvSealComplete struct {
	Record  *record.SealedRecord
	Entries int
	Signers int
}

// EvMessage is a decrypted chat message (Self is true for the local echo of our
// own outgoing messages). Signed reports whether a valid Ed25519 signature was
// present (§3.3); unsigned legacy messages still arrive (Signed=false).
type EvMessage struct {
	FromID   string
	FromName string
	Text     string
	Self     bool
	Signed   bool
	At       time.Time
}

// EvMemberJoined / EvMemberLeft track room membership.
type EvMemberJoined struct{ ID, Name, Fingerprint string }
type EvMemberLeft struct{ ID, Name string }

// EvError is a non-fatal error (e.g. a single message failed to decrypt).
type EvError struct{ Err error }

// --- Ephemeral artifact relay (§2.3) ----------------------------------------

// EvFileOffer is emitted to a RECEIVER when a verified transfer offer arrives:
// someone is sending an artifact. Filename is the sanitized basename.
type EvFileOffer struct {
	From       string
	Fpr        string
	Filename   string
	Size       int64
	TransferID string
	At         time.Time
}

// EvFileProgress is emitted on the SENDER as chunks go out (throttled).
type EvFileProgress struct {
	Filename    string
	TransferID  string
	SentChunks  int
	TotalChunks int
	SentBytes   int64
	TotalBytes  int64
}

// EvFileSent is emitted on the SENDER when the artifact has been fully streamed.
type EvFileSent struct {
	Filename   string
	TransferID string
	Size       int64
	Elapsed    time.Duration
}

// EvFileFailed is emitted on the SENDER when a transfer it started fails.
type EvFileFailed struct {
	Filename   string
	TransferID string
	Reason     string
}

// EvFileComplete is emitted on a RECEIVER when a transfer finishes. OK is true and
// Path is set when the artifact verified and was written; otherwise Err explains
// the failure (integrity, abort, or write error).
type EvFileComplete struct {
	From       string
	Filename   string
	Path       string
	Size       int64
	TransferID string
	OK         bool
	Err        string
	At         time.Time
}

// EvDisconnected is emitted once when the connection ends; Done() closes after it.
type EvDisconnected struct{ Err error }

func (EvConnected) isEvent()     {}
func (EvRouteFired) isEvent()    {}
func (EvAck) isEvent()           {}
func (EvHandoff) isEvent()       {}
func (EvRecordEntry) isEvent()   {}
func (EvSealRequest) isEvent()   {}
func (EvSealAck) isEvent()       {}
func (EvSealComplete) isEvent()  {}
func (EvKeyReady) isEvent()      {}
func (EvMessage) isEvent()       {}
func (EvServerMessage) isEvent() {}
func (EvControl) isEvent()       {}
func (EvExecRequest) isEvent()   {}
func (EvExecResult) isEvent()    {}
func (EvInvite) isEvent()        {}
func (EvBreakGlass) isEvent()    {}
func (EvMemberJoined) isEvent()  {}
func (EvMemberLeft) isEvent()    {}
func (EvFileOffer) isEvent()     {}
func (EvFileProgress) isEvent()  {}
func (EvFileSent) isEvent()      {}
func (EvFileFailed) isEvent()    {}
func (EvFileComplete) isEvent()  {}
func (EvError) isEvent()         {}
func (EvDisconnected) isEvent()  {}
