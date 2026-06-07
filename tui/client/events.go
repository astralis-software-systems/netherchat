package client

import "time"

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

// EvControl is a relayed room control action (vanish/ttl).
type EvControl struct {
	Action     string
	ByName     string
	Self       bool // true if this client initiated it
	TTLSeconds int
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

// EvDisconnected is emitted once when the connection ends; Done() closes after it.
type EvDisconnected struct{ Err error }

func (EvConnected) isEvent()     {}
func (EvRouteFired) isEvent()    {}
func (EvAck) isEvent()           {}
func (EvHandoff) isEvent()       {}
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
func (EvError) isEvent()         {}
func (EvDisconnected) isEvent()  {}
