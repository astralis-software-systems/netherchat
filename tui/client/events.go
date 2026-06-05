package client

import "time"

// Event is something the client core surfaces to its consumer (the TUI or a
// test). Consumers receive these on Events() and stop when Done() is closed.
type Event interface{ isEvent() }

// EvConnected is emitted once, after the server's Welcome is processed.
type EvConnected struct {
	SelfID      string
	YouAreFirst bool
	Members     []string // display names already present
	InviteOnly  bool
	ExecEnabled bool
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

// EvExecResult is the result of an /exec request this client made.
type EvExecResult struct {
	Command string
	Allowed bool
	Output  string
	Err     string
}

// EvInvite carries a minted invite token in response to /invite.
type EvInvite struct {
	Room    string
	Token   string
	Expires time.Time
}

// EvKeyReady is emitted when this client holds the room key for an epoch and can
// send and receive messages.
type EvKeyReady struct{ Epoch uint64 }

// EvMessage is a decrypted chat message (Self is true for the local echo of our
// own outgoing messages).
type EvMessage struct {
	FromID   string
	FromName string
	Text     string
	Self     bool
	At       time.Time
}

// EvMemberJoined / EvMemberLeft track room membership.
type EvMemberJoined struct{ ID, Name string }
type EvMemberLeft struct{ ID, Name string }

// EvError is a non-fatal error (e.g. a single message failed to decrypt).
type EvError struct{ Err error }

// EvDisconnected is emitted once when the connection ends; Done() closes after it.
type EvDisconnected struct{ Err error }

func (EvConnected) isEvent()     {}
func (EvKeyReady) isEvent()      {}
func (EvMessage) isEvent()       {}
func (EvServerMessage) isEvent() {}
func (EvControl) isEvent()       {}
func (EvExecResult) isEvent()    {}
func (EvInvite) isEvent()        {}
func (EvMemberJoined) isEvent()  {}
func (EvMemberLeft) isEvent()    {}
func (EvError) isEvent()         {}
func (EvDisconnected) isEvent()  {}
