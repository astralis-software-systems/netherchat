package attest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// RosterVersion is the value of RosterAttestation.Version — a stability contract
// for the on-disk roster.json shape, bumped only on a breaking change.
const RosterVersion = "v1"

// RosterMember is one entry in a roster attestation: a member's display name,
// identity fingerprint, and whether the attester had SAS-verified them at the
// time. Only the fingerprint is authenticated; name and verified are
// informational (and are NOT part of the signed set hash).
type RosterMember struct {
	Name     string `json:"name"`
	Fpr      string `json:"fpr"`
	Verified bool   `json:"verified"`
}

// RosterAttestation is the artifact written by /roster --signed (§1.4): the
// membership set that held the room key at a given epoch, co-signed by the
// present members. It answers "who could decrypt this conversation at time T" as
// a cryptographic fact rather than a server-side ACL.
//
// SignerKeys carries the Ed25519 public keys needed to verify Signatures
// offline. It is not in the illustrative spec shape, but it is required: a
// fingerprint is a hash of a key, so a verifier cannot recover the key from it.
// This mirrors record.SealedRecord.SignerKeys, and each key is checked to hash
// back to its fingerprint, binding the two.
type RosterAttestation struct {
	Version    string            `json:"netherchat_roster"` // RosterVersion ("v1")
	Room       string            `json:"room"`
	Epoch      uint64            `json:"epoch"`
	AttestedAt string            `json:"attested_at"` // RFC3339 UTC
	AttestedBy string            `json:"attested_by"` // fingerprint of the member who ran /roster --signed
	Members    []RosterMember    `json:"members"`
	SetHash    string            `json:"set_hash"`    // hex SHA-256 of the sorted member fingerprints
	Signatures map[string]string `json:"signatures"`  // fpr -> base64 Ed25519 sig over RosterSigningBytes(room, epoch, set_hash)
	SignerKeys map[string]string `json:"signer_keys"` // fpr -> base64 Ed25519 public key (to verify Signatures)
}

// SetHash is the deterministic membership-set hash: SHA-256 over the sorted
// fingerprints joined by newline. Sorting makes it independent of join order.
func SetHash(fprs []string) []byte {
	sorted := append([]string(nil), fprs...)
	sort.Strings(sorted)
	h := sha256.Sum256([]byte(strings.Join(sorted, "\n")))
	return h[:]
}

// NewRoster assembles a roster attestation from the collected co-signatures.
// members is the full membership set (sorted by fingerprint here); sigs and keys
// are keyed by fingerprint and hold raw bytes (base64-encoded into the artifact).
func NewRoster(room string, epoch uint64, attestedBy string, members []RosterMember, sigs, keys map[string][]byte) *RosterAttestation {
	ms := append([]RosterMember(nil), members...)
	sort.Slice(ms, func(i, j int) bool { return ms[i].Fpr < ms[j].Fpr })
	fprs := make([]string, len(ms))
	for i, m := range ms {
		fprs[i] = m.Fpr
	}
	return &RosterAttestation{
		Version:    RosterVersion,
		Room:       room,
		Epoch:      epoch,
		AttestedAt: nowRFC3339(),
		AttestedBy: attestedBy,
		Members:    ms,
		SetHash:    hex.EncodeToString(SetHash(fprs)),
		Signatures: b64map(sigs),
		SignerKeys: b64map(keys),
	}
}

// Marshal renders the attestation as indented JSON suitable for writing to disk.
func (r *RosterAttestation) Marshal() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }

// ParseRoster decodes a roster.json, rejecting unknown fields so a differently
// shaped artifact fails loudly rather than verifying something we do not fully
// understand.
func ParseRoster(b []byte) (*RosterAttestation, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var r RosterAttestation
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("parse roster: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("parse roster: trailing data after JSON object")
	}
	return &r, nil
}

// RosterResult summarizes a roster verification.
type RosterResult struct {
	Valid   bool     `json:"valid"`
	Room    string   `json:"room"`
	Epoch   uint64   `json:"epoch"`
	Members int      `json:"members"`
	Signers []string `json:"signers"` // fingerprints whose signature verified
	SetHash string   `json:"set_hash"`
	Reason  string   `json:"reason,omitempty"`
}

// VerifyRoster checks that (1) set_hash matches the sorted member fingerprints,
// and (2) every signature is a valid Ed25519 signature over the domain-separated,
// room- and epoch-bound set-hash preimage, by a key that itself hashes to its
// fingerprint. Any failure yields Valid=false with a specific Reason; err is
// non-nil only for malformed inputs that prevent verification entirely.
func VerifyRoster(r *RosterAttestation) (*RosterResult, error) {
	res := &RosterResult{Room: r.Room, Epoch: r.Epoch, Members: len(r.Members), SetHash: r.SetHash}

	if r.Version != RosterVersion {
		res.Reason = fmt.Sprintf("unsupported roster version %q (want %q)", r.Version, RosterVersion)
		return res, nil
	}

	// 1: the listed members must hash to the stored set_hash.
	fprs := make([]string, len(r.Members))
	for i, m := range r.Members {
		fprs[i] = m.Fpr
	}
	want := hex.EncodeToString(SetHash(fprs))
	if want != r.SetHash {
		res.Reason = fmt.Sprintf("set_hash %s does not match the listed members (recomputed %s)", r.SetHash, want)
		return res, nil
	}
	setHash, err := hex.DecodeString(r.SetHash)
	if err != nil {
		return res, fmt.Errorf("set_hash is not valid hex: %w", err)
	}

	// 2: every signature verifies over the room/epoch-bound set hash.
	if len(r.Signatures) == 0 {
		res.Reason = "roster has no signatures"
		return res, nil
	}
	preimage := protocol.RosterSigningBytes(r.Room, r.Epoch, setHash)
	signers := make([]string, 0, len(r.Signatures))
	// Iterate the fingerprints in sorted order, not the map. The VERDICT is
	// deterministic either way — every signature has to verify, so any failure is
	// fatal whichever one is met first — but the loop returns on the first
	// failure, so the fingerprint named in Reason was a function of Go's
	// randomized map order. A roster with two bad signatures blamed a different
	// one on each run, which is not something an operator can act on or a test
	// can assert.
	for _, fpr := range sortedKeys(r.Signatures) {
		sigB64 := r.Signatures[fpr]
		keyB64, ok := r.SignerKeys[fpr]
		if !ok {
			res.Reason = fmt.Sprintf("no signer key for %s (cannot verify its signature)", fpr)
			return res, nil
		}
		key, err := base64.StdEncoding.DecodeString(keyB64)
		if err != nil || len(key) != ed25519.PublicKeySize {
			res.Reason = fmt.Sprintf("signer key for %s is malformed", fpr)
			return res, nil
		}
		if crypto.Fingerprint(ed25519.PublicKey(key)) != fpr {
			res.Reason = fmt.Sprintf("signer key for %s does not match its fingerprint", fpr)
			return res, nil
		}
		sig, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			res.Reason = fmt.Sprintf("signature for %s is not valid base64", fpr)
			return res, nil
		}
		if !ed25519.Verify(ed25519.PublicKey(key), preimage, sig) {
			res.Reason = fmt.Sprintf("signature for %s does not verify over the set hash", fpr)
			return res, nil
		}
		signers = append(signers, fpr)
	}
	sort.Strings(signers)
	res.Signers = signers
	res.Valid = true
	return res, nil
}
