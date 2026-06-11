package duress

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// BeaconVersion is the value of Beacon.Version — a stability contract for the
// on-disk/over-the-wire duress-beacon shape.
const BeaconVersion = "v1"

const nonceLen = 16

// Beacon is a signed, offline-verifiable attestation that a duress credential was
// entered and a safe response was taken (C2). It is delivered OUT-OF-BAND to a
// trusted monitor — deliberately not through the relay the coercer can observe —
// and is signed with the actor's own identity key so the monitor can attribute it,
// not merely receive an anonymous, forgeable ping.
//
// It carries metadata only: the actor fingerprint, the mode, an optional
// non-sensitive context label, a timestamp, and an anti-replay nonce. It never
// carries room content or secrets.
type Beacon struct {
	Version  string `json:"netherchat_duress"` // BeaconVersion ("v1")
	Actor    string `json:"actor"`             // SHA256:... fingerprint of the signer
	ActorKey []byte `json:"actor_key"`         // Ed25519 public key (base64); must hash to Actor
	Mode     string `json:"mode"`              // silent_scuttle | decoy_view
	Context  string `json:"context,omitempty"` // optional, non-sensitive label (e.g. a site/room); NO secrets
	IssuedAt string `json:"issued_at"`         // RFC3339 UTC
	Nonce    string `json:"nonce"`             // base64 random, anti-replay
	Sig      []byte `json:"sig"`               // Ed25519 over protocol.DuressBeaconSigningBytes(...)
}

// SignBeacon builds and signs a duress beacon for the given identity and mode.
// context is an optional, non-sensitive label and MUST NOT contain secrets.
func SignBeacon(id *crypto.Identity, mode Mode, context string) (*Beacon, error) {
	if err := mode.Valid(); err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("duress: generate beacon nonce: %w", err)
	}
	nonceB64 := base64.StdEncoding.EncodeToString(nonce)
	issuedAt := time.Now().UTC().Format(time.RFC3339)
	fpr := id.Fingerprint()

	preimage := protocol.DuressBeaconSigningBytes(fpr, string(mode), context, issuedAt, nonceB64)
	sig, err := id.Sign(preimage)
	if err != nil {
		return nil, fmt.Errorf("duress: sign beacon: %w", err)
	}
	return &Beacon{
		Version:  BeaconVersion,
		Actor:    fpr,
		ActorKey: append([]byte(nil), id.SignPub...),
		Mode:     string(mode),
		Context:  context,
		IssuedAt: issuedAt,
		Nonce:    nonceB64,
		Sig:      sig,
	}, nil
}

// Verify checks a duress beacon entirely offline: the version is known, the mode is
// valid, the embedded public key hashes to the claimed actor fingerprint (binding
// the two), and the signature verifies against the domain-separated preimage. It
// needs nothing but the beacon itself.
func (b *Beacon) Verify() error {
	if b.Version != BeaconVersion {
		return fmt.Errorf("duress beacon: unsupported version %q (want %q)", b.Version, BeaconVersion)
	}
	if err := Mode(b.Mode).Valid(); err != nil {
		return err
	}
	if len(b.ActorKey) != ed25519.PublicKeySize {
		return fmt.Errorf("duress beacon: actor_key is %d bytes, want %d", len(b.ActorKey), ed25519.PublicKeySize)
	}
	pub := ed25519.PublicKey(b.ActorKey)
	if fpr := crypto.Fingerprint(pub); fpr != b.Actor {
		return fmt.Errorf("duress beacon: actor_key fingerprint %s does not match actor %s", fpr, b.Actor)
	}
	preimage := protocol.DuressBeaconSigningBytes(b.Actor, b.Mode, b.Context, b.IssuedAt, b.Nonce)
	if !ed25519.Verify(pub, preimage, b.Sig) {
		return errors.New("duress beacon: signature does not verify")
	}
	return nil
}

// Marshal renders the beacon as indented JSON suitable for writing to disk.
func (b *Beacon) Marshal() ([]byte, error) { return json.MarshalIndent(b, "", "  ") }

// ParseBeacon decodes a beacon, rejecting unknown fields so a different/forward
// shape fails loudly rather than verifying something we do not fully understand.
func ParseBeacon(data []byte) (*Beacon, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var b Beacon
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("parse duress beacon: %w", err)
	}
	if dec.More() {
		return nil, errors.New("parse duress beacon: trailing data after JSON object")
	}
	return &b, nil
}

// EmitBeacon resolves the actor's identity via the standard BYO-key cascade
// (explicit path → ssh-agent → ~/.ssh/id_ed25519 → generated) and returns a signed
// duress beacon. It is the high-level entry point the CLI uses so that callers
// outside tui/ need not touch the (internal) crypto package directly.
func EmitBeacon(identityPath string, mode Mode, context string) (*Beacon, error) {
	id, err := crypto.ResolveIdentity(identityPath)
	if err != nil {
		return nil, err
	}
	return SignBeacon(id, mode, context)
}
