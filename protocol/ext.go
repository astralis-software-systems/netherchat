package protocol

// This file holds the v2 payload types. See protocol.go for the opcode set.

// Control action names carried by Control.Action.
const (
	ActionVanish = "vanish" // clear local history in the room (key rotation is separate, via KeyDeliver)
	ActionTTL    = "ttl"    // set a client-side message display TTL for the room

	// Dead-man's switch / auto-scuttle (§1.6). ActionScuttle is the server-to-room
	// burn notice: every client runs the /vanish key ratchet, renders the
	// attestation, and the room then closes. Reason carries why (idle | owner_loss
	// | manual | armed). ActionScuttleArm announces a visible countdown to all
	// participants (TTLSeconds) before an armed scuttle fires.
	ActionScuttle    = "scuttle"
	ActionScuttleArm = "scuttle_arm"

	// Status Beacon (§1.2): informational notices broadcast when a member sets or
	// clears the out-of-band beacon. The beacon CONTENT travels via REST (encrypted
	// to a separate beacon key the relay never holds); these control frames carry
	// only metadata — who acted, and the lifetime — so a `tail --json` observer can
	// record beacon changes in the structured event stream. They are pure relay
	// (the default broadcast path); the server takes no action on them.
	ActionBeaconSet     = "beacon_set"
	ActionBeaconCleared = "beacon_cleared"
)

// Scuttle reasons carried in Control.Reason for ActionScuttle.
const (
	ScuttleIdle      = "idle"       // no activity for the room's idle_after window
	ScuttleOwnerLoss = "owner_loss" // the first joiner disconnected (room non-empty)
	ScuttleManual    = "manual"     // a participant ran /scuttle now
	ScuttleArmed     = "armed"      // a /scuttle arm countdown reached zero
)

// Control is a room control action, relayed by the server to every member of
// the room. It carries no secrets.
type Control struct {
	Action     string `json:"action"`
	By         string `json:"by,omitempty"`          // member id that initiated it
	ByName     string `json:"by_name,omitempty"`     // display name, for UI
	TTLSeconds int    `json:"ttl_seconds,omitempty"` // for ActionTTL / ActionScuttleArm (countdown seconds)
	Reason     string `json:"reason,omitempty"`      // for ActionScuttle: why it scuttled
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

// ExecRequestBody and ExecResultBody are the END-TO-END-ENCRYPTED plaintexts of
// OpExecRequest / OpExecResult. Both opcodes carry a Message on the wire (sealed
// under the room key, Ed25519-signed); the relay only ever sees ciphertext and
// never runs anything. Execution happens at the edge: a `netherchat agent` on the
// operator's own host matches the request against its own allowlist, runs it, and
// posts a signed result back.

// ExecRequestBody names an action a room member is asking an agent to run. The
// agent maps Cmd to a concrete command via its local runbook — callers never
// supply a raw command line.
type ExecRequestBody struct {
	ID  string `json:"id"`  // correlates a result back to this request
	Cmd string `json:"cmd"` // the runbook action name, e.g. "drain"
}

// ExecResultBody is an agent's signed reply to an ExecRequestBody.
type ExecResultBody struct {
	ID       string `json:"id"`
	Cmd      string `json:"cmd"`
	Allowed  bool   `json:"allowed"`             // false = not in the agent's runbook (denied)
	ExitCode int    `json:"exit_code,omitempty"` // process exit code when run
	Output   string `json:"output,omitempty"`    // combined stdout/stderr (capped)
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

// RouteFired is broadcast by the server to every member of a webhook room when an
// inbound alert payload matched a [[route]] rule and a break-glass war room was
// spawned automatically (§1.3). It carries no secrets — only metadata about the
// new room — so observers (e.g. `netherchat tail #alerts --json`) can record the
// spawn in the structured event stream. Room is the NEW incident room's name.
type RouteFired struct {
	Room        string   `json:"room"`         // the spawned incident room (e.g. inc-3f9a2b71)
	TriggerRule int      `json:"trigger_rule"` // index of the matched [[route]] rule
	Invitees    []string `json:"invitees"`     // names the route invited
	TTLSeconds  int      `json:"ttl_seconds"`  // hard lifetime of the spawned room
	At          int64    `json:"at"`           // unix seconds
}

// AckBody is the END-TO-END-ENCRYPTED plaintext of an OpAck Message (§2.2). An
// /ack is a typed coordination primitive — it carries a tag that the room counts
// into a quorum (one ack per identity fingerprint per tag). It is deliberately
// NOT a reaction emoji: free-form reactions are a rejected feature. The acting
// identity is the signed Message's sender, so the body needs only the tag.
type AckBody struct {
	Tag string `json:"tag"`
}

// HandoffBody is the END-TO-END-ENCRYPTED plaintext of an OpHandoff Message
// (§2.2): it transfers the single incident-commander (IC) token to ToID. The
// sender is the signed Message's author; ToName is carried for display when a
// receiver does not (yet) know the target member.
type HandoffBody struct {
	ToID   string `json:"to_id"`
	ToName string `json:"to_name,omitempty"`
}

// SealRequestBody is the END-TO-END-ENCRYPTED plaintext of an OpSealRequest
// Message (§1.4): a sealer proposes sealing the record at HeadHash (the SHA-256
// of the chain's last entry). Members whose own chain head matches respond with
// an OpSealAck. HeadHash is the raw 32-byte hash (base64 on the wire).
type SealRequestBody struct {
	HeadHash []byte `json:"head_hash"`
}

// SealAckBody is the END-TO-END-ENCRYPTED plaintext of an OpSealAck Message
// (§1.4): a participant co-signs HeadHash. Sig is the Ed25519 signature over
// SealSigningBytes(room, HeadHash) (domain-separated and room-bound, see
// record_signing.go), verifiable against the sender's identity key.
type SealAckBody struct {
	HeadHash []byte `json:"head_hash"`
	Sig      []byte `json:"sig"`

	// Meaning, SignerName and SignedAt carry the declared electronic-signature
	// meaning (item 2). When Meaning is non-empty the co-signer signed the v2 seal
	// preimage (SealSigningBytesV2) over these three fields; when empty it is a bare
	// v1 co-signature (Sig over SealSigningBytes). They are reproduced into the
	// sealed record's Endorsements so a verifier reconstructs the same preimage.
	Meaning    string `json:"meaning,omitempty"`
	SignerName string `json:"signer_name,omitempty"`
	SignedAt   string `json:"signed_at,omitempty"`
}

// RosterRequestBody is the END-TO-END-ENCRYPTED plaintext of an OpRosterRequest
// Message (§1.4): an attester proposes attesting the room's membership set,
// identified by SetHash (SHA-256 of the sorted member fingerprints). Present
// members whose own view of the set and epoch matches co-sign with an
// OpRosterAck. SetHash is the raw 32-byte hash (base64 on the wire).
type RosterRequestBody struct {
	SetHash     []byte `json:"set_hash"`
	RoomID      string `json:"room_id"`
	Epoch       uint64 `json:"epoch"`
	ExpiresUnix int64  `json:"expires_unix"`
}

// RosterAckBody is the END-TO-END-ENCRYPTED plaintext of an OpRosterAck Message
// (§1.4): a member co-signs SetHash. Sig is Ed25519 over RosterSigningBytes(room,
// epoch, SetHash) (domain-separated, room- and epoch-bound), verifiable against
// the sender's identity key.
type RosterAckBody struct {
	SetHash   []byte `json:"set_hash"`
	SignerFpr string `json:"signer_fpr"`
	Sig       []byte `json:"sig"`
}

// ScuttleReceiptRequestBody is the END-TO-END-ENCRYPTED plaintext of an
// OpScuttleReceiptRequest Message (§1.5): a scuttling client proposes a receipt,
// identified by ReceiptHash (SHA-256 of the canonical receipt bytes). Present
// members co-sign with an OpScuttleReceiptAck before keys are zeroized. The
// remaining fields are context for display/sanity; ReceiptHash is what is signed.
type ScuttleReceiptRequestBody struct {
	ReceiptHash []byte `json:"receipt_hash"`
	RoomID      string `json:"room_id"`
	Reason      string `json:"reason"`
	TS          int64  `json:"ts"`
	EpochFirst  uint64 `json:"epoch_first"`
	EpochLast   uint64 `json:"epoch_last"`
}

// ScuttleReceiptAckBody is the END-TO-END-ENCRYPTED plaintext of an
// OpScuttleReceiptAck Message (§1.5): a member co-signs ReceiptHash. Sig is
// Ed25519 over ScuttleReceiptSigningBytes(ReceiptHash) (domain-separated),
// verifiable against the sender's identity key.
type ScuttleReceiptAckBody struct {
	ReceiptHash []byte `json:"receipt_hash"`
	SignerFpr   string `json:"signer_fpr"`
	Sig         []byte `json:"sig"`
}

// Action names carried by ActionRequestBody.Action (the Two-Person Rule, §1.3).
const (
	ActionScuttleAction = "scuttle"     // /scuttle now | /scuttle arm
	ActionBreakGlass    = "break_glass" // /break-glass
	ActionRunbook       = "runbook"     // netherchat agent runbook execution
)

// ActionRequestBody is the END-TO-END-ENCRYPTED plaintext of an OpActionRequest
// Message (§1.3): an initiator proposes a privileged action that does not fire
// until QuorumNeeded distinct authorized members (the requester counts as one,
// via this signed request) have endorsed it. Params is a human-readable, canonical
// description of exactly what will happen — NOT a raw command — and ParamsHash is
// the hex SHA-256 of Params, so an approver can independently verify the hash
// matches what is displayed and binds the approval to this exact action.
type ActionRequestBody struct {
	RequestID    string `json:"request_id"`    // random 16-char hex correlating approvals/vetoes
	Action       string `json:"action"`        // scuttle | break_glass | runbook
	ParamsHash   string `json:"params_hash"`   // hex SHA-256 of Params
	Params       string `json:"params"`        // human-readable description of what will happen
	RequesterFpr string `json:"requester_fpr"` // Ed25519 fingerprint of the initiator (endorser #1)
	Room         string `json:"room"`
	QuorumNeeded int    `json:"quorum_needed"` // distinct endorsers required before the action fires
	ExpiresUnix  int64  `json:"expires_unix"`  // the request is discarded after this (≈60s after issue)
	Nonce        string `json:"nonce"`         // random hex bound into every approval; prevents replay
}

// ActionApprovalBody is the END-TO-END-ENCRYPTED plaintext of an OpActionApproval
// Message (§1.3): an authorized member co-signs a pending request. Sig is the
// Ed25519 signature over ActionApprovalSigningBytes(RequestID, ParamsHash,
// ApproverFpr, Nonce) — domain-separated and bound to the request id, the exact
// action (via ParamsHash), the approver, and the request nonce, so an approval of
// one action can never be replayed to endorse a different one.
type ActionApprovalBody struct {
	RequestID   string `json:"request_id"`
	ParamsHash  string `json:"params_hash"`  // the approver independently verifies this matches the request
	ApproverFpr string `json:"approver_fpr"` // must equal the signing sender's fingerprint
	Sig         []byte `json:"sig"`

	// Meaning, Name and SignedAt carry the declared electronic-signature meaning of
	// this endorsement (item 2): why the member approved (e.g. "approved" or
	// "reviewed"), their printed name, and the UTC time. When Meaning is non-empty,
	// Sig is over ActionApprovalSigningBytesV2 (which binds all three); when empty,
	// it is the bare v1 ActionApprovalSigningBytes. Every counting client derives the
	// matching preimage from these fields, so the meaning cannot be altered in flight.
	Meaning  string `json:"meaning,omitempty"`
	Name     string `json:"name,omitempty"`
	SignedAt string `json:"signed_at,omitempty"`
}

// ActionVetoBody is the END-TO-END-ENCRYPTED plaintext of an OpActionVeto Message
// (§1.3): any present member can cancel a pending request immediately. The vetoer
// is the signed Message's sender; Reason is an optional human-readable note.
type ActionVetoBody struct {
	RequestID string `json:"request_id"`
	VetoerFpr string `json:"vetoer_fpr"`
	Reason    string `json:"reason,omitempty"`
}
