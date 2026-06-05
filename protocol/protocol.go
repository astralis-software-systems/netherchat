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
// §3) can be negotiated alongside the v1 NaCl scheme during migration.
const Version = 1

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
}

// Welcome is the server's reply to Hello. Members lists everyone already in the
// room (excluding the recipient). YouAreFirst is true when the room was empty,
// meaning this client must mint the initial room key for epoch 0.
type Welcome struct {
	ProtocolVersion int      `json:"protocol_version"`
	YourID          string   `json:"your_id"`
	Room            string   `json:"room"`
	Members         []Member `json:"members"`
	YouAreFirst     bool     `json:"you_are_first"`
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

// Message is an end-to-end encrypted chat message. The server fans it out to
// every other member of the room verbatim; Ciphertext is never decryptable by
// the server.
type Message struct {
	FromID     string `json:"from_id"`
	Epoch      uint64 `json:"epoch"`
	Nonce      []byte `json:"nonce"`      // 24-byte XChaCha20-Poly1305 nonce
	Ciphertext []byte `json:"ciphertext"` // XChaCha20-Poly1305(roomKey, plaintext)
	Signature  []byte `json:"signature"`  // Ed25519 over SigningBytes(...)
}

// Error is a server-to-client error notification.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
