package protocol

// This file holds the v2 payload types. See protocol.go for the opcode set.

// Control action names carried by Control.Action.
const (
	ActionVanish = "vanish" // clear local history in the room (key rotation is separate, via KeyDeliver)
	ActionTTL    = "ttl"    // set a client-side message display TTL for the room
)

// Control is a room control action, relayed by the server to every member of
// the room. It carries no secrets.
type Control struct {
	Action     string `json:"action"`
	By         string `json:"by,omitempty"`          // member id that initiated it
	ByName     string `json:"by_name,omitempty"`     // display name, for UI
	TTLSeconds int    `json:"ttl_seconds,omitempty"` // for ActionTTL
}

// ServerMessage is a plaintext message that originates at the server (an inbound
// webhook, a system notice, or an /exec result broadcast). It is NOT end-to-end
// encrypted — it enters the system in plaintext at the server, so the server can
// read it by definition. Clients render it with a clear "not encrypted" marker.
type ServerMessage struct {
	Kind string `json:"kind"` // "webhook" | "system" | "exec"
	From string `json:"from"` // e.g. "ci-bot", "server"
	Text string `json:"text"`
	At   int64  `json:"at"` // unix seconds
}

// ExecRequest asks the server to run an allow-listed command. The command must
// exactly match an entry in the server's [exec].allow list, and the room must
// have exec_enabled. There is no shell; arguments are not interpreted.
type ExecRequest struct {
	Command string `json:"command"`
}

// ExecResult is the outcome of an ExecRequest.
type ExecResult struct {
	Command string `json:"command"`
	Allowed bool   `json:"allowed"`
	Output  string `json:"output,omitempty"`
	Err     string `json:"error,omitempty"`
}

// InviteRequest asks the server to mint a one-time invite token for the
// requester's current room.
type InviteRequest struct{}

// InviteResult carries a freshly minted one-time invite token.
type InviteResult struct {
	Room    string `json:"room"`
	Token   string `json:"token"`
	Expires int64  `json:"expires,omitempty"` // unix seconds, 0 = no expiry
}

// BreakGlass asks the server to stand up an ephemeral, invite-only war room with
// a hard time-to-live and one-time invite links for each named person. The room
// is created with a server-generated name and vanishes at the deadline whether or
// not it is still in use — the "incident war room that vanishes" use case. The
// server clamps TTLSeconds into a sane range and caps the number of invitees.
type BreakGlass struct {
	Invitees   []string `json:"invitees"`    // display names; one one-time link is minted per name
	TTLSeconds int      `json:"ttl_seconds"` // hard lifetime of the room
}

// BreakGlassInvite pairs a named person with their one-time token. The token is
// embedded in a /join?room=<room>&token=<token> link by the client.
type BreakGlassInvite struct {
	Name  string `json:"name"`
	Token string `json:"token"`
}

// BreakGlassResult is the server's reply to BreakGlass. HostToken is a one-time
// token for the creator to join their own room without racing the invitees for
// the invite-only bootstrap slot. Expires is the hard deadline (unix seconds).
type BreakGlassResult struct {
	Room       string             `json:"room"`
	TTLSeconds int                `json:"ttl_seconds"`
	Expires    int64              `json:"expires"`
	HostToken  string             `json:"host_token"`
	Invites    []BreakGlassInvite `json:"invites"`
}
