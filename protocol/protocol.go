// Package protocol defines the Netherchat wire format: the typed envelope and
// the payloads exchanged between clients and the server.
//
// This package is deliberately crypto-free. It describes only what travels on
// the wire — opaque ciphertext, wrapped key blobs, and routing metadata. The
// server imports this package; the server does NOT (and must not) import the
// client crypto package. That separation is what makes "the server cannot read
// your messages" a property of the build graph rather than a promise. See
// PROTOCOL.md and ARCHITECTURE_DECISION.md §3.
package protocol

import "encoding/json"

// Version is the protocol version advertised in Hello/Welcome. It exists from
// day one so a future MLS-based key-agreement scheme (ARCHITECTURE_DECISION.md
// §3) can be negotiated alongside the NaCl scheme during migration.
//
// v2 adds (additively, keeping the connection==room model): invite tokens on
// Hello, room policy on Welcome, server-originated plaintext messages
// (webhooks/system, OpServerMessage), control actions (OpControl), edge exec
// (OpExecRequest/Result), and invite generation (OpInviteRequest/Result).
//
// v3 adds room-bound, OPTIONAL per-message Ed25519 signatures (§3.3): the signed
// bytes now include the room id, and the signature rides in Message.Sig
// (sig,omitempty). It is additive — a message with no Sig is accepted as
// "unsigned" rather than rejected, so v2 senders still interoperate. The server
// therefore accepts any client in [MinVersion, Version].
const Version = 3

// MinVersion is the oldest protocol version the server still admits.
const MinVersion = 2

// Op is the discriminator on the outer Envelope.
type Op string

const (
	OpHello        Op = "hello"         // client -> server (first frame)
	OpWelcome      Op = "welcome"       // server -> client
	OpMemberJoined Op = "member_joined" // server -> clients
	OpMemberLeft   Op = "member_left"   // server -> clients
	OpKeyRequest   Op = "key_request"   // server -> designated distributor
	OpKeyDeliver   Op = "key_deliver"   // distributor -> server -> target member
	OpMessage      Op = "msg"           // sender -> server -> other members
	OpError        Op = "error"         // server -> client

	// v2 additions:
	OpServerMessage Op = "server_msg"     // server -> clients: plaintext (webhook/system), NOT E2E
	OpControl       Op = "control"        // bidirectional: room control actions (vanish, ttl)
	OpExecRequest   Op = "exec_request"   // member -> room: E2E-signed edge-exec request (carries a Message)
	OpExecResult    Op = "exec_result"    // agent -> room: E2E-signed edge-exec result (carries a Message)
	OpInviteRequest Op = "invite_request" // client -> server: mint an invite token for the room
	OpInviteResult  Op = "invite_result"  // server -> client: the minted token

	// break-glass (additive over v2): stand up an ephemeral, invite-only room with
	// a hard expiry and one-time links for named people — the incident war room
	// that vanishes. See server/internal/ephemeral and PROTOCOL.md §11.
	OpBreakGlass       Op = "break_glass"        // client -> server: create a war room + mint links
	OpBreakGlassResult Op = "break_glass_result" // server -> client: room name, links, host token, deadline

	// Auto-war-room (§1.3, additive): when an inbound webhook payload matches a
	// [[route]] rule the server spawns a break-glass room and notifies the webhook
	// room's members so the spawn is visible in the structured event stream
	// (route_fired). It carries no secrets — only metadata about an automatically
	// created room. See server/internal/api and PROTOCOL.md §12.
	OpRouteFired Op = "route_fired" // server -> clients: an alert route fired and spawned a war room

	// Coordination primitives (§2.2, additive). Both carry a Message envelope
	// (sealed under the room key, Ed25519-signed) exactly like OpExecRequest — the
	// relay only ever sees ciphertext. These are TYPED coordination state, not
	// social reactions (free-form emoji reactions are explicitly rejected). See
	// PROTOCOL.md §13.
	OpAck     Op = "ack"     // member -> room: a typed, countable ack of a tag
	OpHandoff Op = "handoff" // member -> room: transfer the incident-commander token

	// Sealed record (§1.4, additive). All three carry a Message envelope sealed
	// under the room key, exactly like OpAck/OpExecRequest — the relay only ever
	// sees ciphertext. They build a hash-chained, multi-party-signed artifact of
	// the decisions that mattered, so an ephemeral room can produce defensible
	// minutes without a transcript. See tui/record and PROTOCOL.md §14.
	OpRecordEntry Op = "record_entry" // member -> room: a new append-only chain entry (decision/action/note)
	OpSealRequest Op = "seal_request" // sealer -> room: { head_hash } — propose sealing the chain at this head
	OpSealAck     Op = "seal_ack"     // member -> room: { head_hash, sig } — co-sign the proposed head

	// Signed roster attestation (§1.4, additive). Like the seal frames, both carry
	// a Message envelope sealed under the room key — the relay only sees ciphertext.
	// A portable, co-signed answer to "who could decrypt this room at epoch N":
	// every present member signs the hash of the sorted member-fingerprint set.
	OpRosterRequest Op = "roster_request" // attester -> room: { set_hash, room_id, epoch, expires_unix }
	OpRosterAck     Op = "roster_ack"     // member -> attester: { set_hash, signer_fpr, sig }

	// Scuttle receipt (§1.5, additive). Same E2E-Message envelope. Before keys are
	// zeroized, a scuttling client may collect co-signatures over a receipt hash so
	// the proof-of-destruction is multi-party. The relay only sees ciphertext.
	OpScuttleReceiptRequest Op = "scuttle_receipt_request" // scuttler -> room: { receipt_hash, room_id, reason, ts, epoch_range }
	OpScuttleReceiptAck     Op = "scuttle_receipt_ack"     // member -> scuttler: { receipt_hash, signer_fpr, sig }

	// Two-Person Rule (§1.3, additive). All three carry a Message envelope sealed
	// under the room key, exactly like OpAck/OpRoster — the relay only ever sees
	// ciphertext, never the action type or its parameters. They gate a dangerous
	// action (scuttle / break_glass / runbook) on N-of-M independent Ed25519
	// approvals: the initiator's signed request is endorser #1, and the action does
	// not fire until quorum DISTINCT signers (the requester plus quorum-1 approvers)
	// have endorsed the same request hash. The gate is enforced client-side over the
	// request hash; the relay cannot bypass or be coerced to bypass it. See
	// PROTOCOL.md §15.
	OpActionRequest  Op = "action_request"  // initiator -> room: a privileged action awaiting quorum
	OpActionApproval Op = "action_approval" // approver -> room: a signed approval of a request hash
	OpActionVeto     Op = "action_veto"     // member -> room: cancel a pending request immediately

	// Agent-decision attestation (NC-W1, additive). All three carry a Message
	// envelope sealed under the room key, exactly like the Two-Person Rule frames —
	// the relay only ever sees ciphertext. An agent (or a human acting for one)
	// PROPOSES an artifact it produced; one or more named humans APPROVE it under the
	// existing Two-Person Rule; on quorum the artifact becomes a signed, hash-chained
	// "artifact" record entry. The proposer can never count toward its own quorum
	// (the second law: an agent proposes, it can never self-approve). See
	// tui/client/artifact.go and docs/agent-attestation.md.
	OpArtifactProposal  Op = "artifact_proposal"  // proposer -> room: an agent-produced artifact awaiting human approval
	OpArtifactApproval  Op = "artifact_approval"  // approver -> room: a signed human approval of a proposal
	OpArtifactRejection Op = "artifact_rejection" // member -> room: reject a pending proposal (no record entry)
)

// Envelope is the outer frame for every message on the wire. Data holds the
// JSON-encoded payload whose shape is determined by Type.
type Envelope struct {
	Type Op              `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
}

// Encode wraps a payload struct into an Envelope of the given op.
func Encode(op Op, payload any) (Envelope, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{Type: op, Data: b}, nil
}

// Decode unmarshals the envelope's payload into v.
func (e Envelope) Decode(v any) error {
	return json.Unmarshal(e.Data, v)
}

// Member identifies a participant in a room. The two keys are PUBLIC keys; the
// []byte fields are base64-encoded by encoding/json. The server stores these
// purely to route wrapped key blobs — it never holds any private key.
type Member struct {
	ID          string `json:"id"`           // server-assigned, unique within the connection's lifetime
	DisplayName string `json:"name"`         // cosmetic only; not authenticated
	IdentityKey []byte `json:"identity_key"` // Ed25519 public key (32 bytes) — signature verification + fingerprint
	KXKey       []byte `json:"kx_key"`       // X25519 public key (32 bytes) — recipient of wrapped room keys
}

// Hello is the first frame a client sends after the WebSocket opens.
type Hello struct {
	ProtocolVersion int    `json:"protocol_version"`
	Room            string `json:"room"`
	DisplayName     string `json:"name"`
	IdentityKey     []byte `json:"identity_key"`
	KXKey           []byte `json:"kx_key"`
	InviteToken     string `json:"invite_token,omitempty"` // required to join an invite-only room
}

// RoomPolicy is the server-advertised capability set for a room, sent in Welcome
// so the client can tailor its UI. There is deliberately no exec capability here:
// command execution is an edge concern, never a server policy (§0.1).
type RoomPolicy struct {
	InviteOnly bool `json:"invite_only"`
	Webhook    bool `json:"webhook"`
	TTLSeconds int  `json:"ttl_seconds,omitempty"`
}

// Welcome is the server's reply to Hello. Members lists everyone already in the
// room (excluding the recipient). YouAreFirst is true when the room was empty,
// meaning this client must mint the initial room key for epoch 0.
type Welcome struct {
	ProtocolVersion int        `json:"protocol_version"`
	YourID          string     `json:"your_id"`
	Room            string     `json:"room"`
	Members         []Member   `json:"members"`
	YouAreFirst     bool       `json:"you_are_first"`
	Policy          RoomPolicy `json:"policy"`
}

// MemberJoined is broadcast when a new member enters the room.
type MemberJoined struct {
	Member Member `json:"member"`
}

// MemberLeft is broadcast when a member disconnects.
type MemberLeft struct {
	ID string `json:"id"`
}

// KeyRequest is sent by the server to exactly one existing member (the
// "designated distributor", chosen deterministically as the oldest member) when
// a new member joins. It asks that member to wrap the current room key for the
// newcomer and return it via KeyDeliver.
type KeyRequest struct {
	ForMember Member `json:"for_member"`
}

// KeyDeliver carries a room key wrapped with nacl/box to the target member's
// X25519 key. The server routes it by ToID but cannot open it: the box is
// sealed to the recipient's public key. See tui/internal/crypto.
type KeyDeliver struct {
	ToID       string `json:"to_id"`
	FromID     string `json:"from_id"`
	Epoch      uint64 `json:"epoch"`
	Nonce      []byte `json:"nonce"`       // 24-byte nacl/box nonce
	WrappedKey []byte `json:"wrapped_key"` // box(roomKey) — opaque to the server
}

// Message is an end-to-end encrypted chat message (also the envelope for exec
// request/result frames). The server fans it out to every other member of the
// room verbatim; Ciphertext is never decryptable by the server.
//
// Sig is the OPTIONAL Ed25519 signature over SigningBytes(...) (§3.3). It is
// omitempty: a frame with no Sig is treated as unsigned (not invalid), which is
// how pre-v3 senders — who used a different field — interoperate and appear
// unsigned rather than failing verification.
type Message struct {
	FromID     string `json:"from_id"`
	Epoch      uint64 `json:"epoch"`
	Nonce      []byte `json:"nonce"`      // 24-byte XChaCha20-Poly1305 nonce
	Ciphertext []byte `json:"ciphertext"` // XChaCha20-Poly1305(roomKey, plaintext)
	Sig        []byte `json:"sig,omitempty"`
}

// Error is a server-to-client error notification.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
