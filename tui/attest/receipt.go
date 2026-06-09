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

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// ReceiptVersion is the value of ScuttleReceipt.Version — a stability contract
// for the on-disk receipt.json shape.
const ReceiptVersion = "v1"

// EpochRange is the inclusive span of epochs the scuttled room lived through.
type EpochRange struct {
	First uint64 `json:"first"`
	Last  uint64 `json:"last"`
}

// ReceiptCore is the hashable content of a scuttle receipt: every field EXCEPT
// the signatures, signer_keys, and the receipt_hash itself. The receipt hash is
// SHA-256 over the canonical (deterministic, compact) JSON of this struct, so a
// signature over the hash commits to all of it.
type ReceiptCore struct {
	Version      string     `json:"netherchat_receipt"`
	Room         string     `json:"room"`
	EpochRange   EpochRange `json:"epoch_range"`
	Reason       string     `json:"reason"` // manual | idle | owner_loss | armed
	ScuttledAt   string     `json:"scuttled_at"`
	ScuttledBy   string     `json:"scuttled_by"`
	MemberFprs   []string   `json:"member_fprs"`
	KeysZeroized bool       `json:"keys_zeroized"`
}

// Hash returns the receipt hash: SHA-256 over the canonical JSON of the core.
// member_fprs is sorted first so the hash is independent of the order the caller
// supplied them; struct field order makes the rest deterministic. The signer and
// every verifier call this same function, so the bytes always agree.
func (c ReceiptCore) Hash() [32]byte {
	cc := c
	cc.Version = ReceiptVersion
	cc.MemberFprs = append([]string(nil), c.MemberFprs...)
	sort.Strings(cc.MemberFprs)
	b, _ := json.Marshal(cc)
	return sha256.Sum256(b)
}

// ScuttleReceipt is the artifact emitted when a room is scuttled (§1.5): a
// signed statement that the room and its keys were destroyed, carrying nothing
// about the content. It is the only surviving output — the liability (a record)
// replaced by an asset (proof there is no record).
//
// ScuttleReceipt embeds ReceiptCore so the hashed fields and the wire fields are
// one source of truth. SignerKeys carries the Ed25519 public keys needed to
// verify Signatures offline (a fingerprint is a hash of a key, so a verifier
// cannot recover the key from it); each key is checked to hash back to its
// fingerprint, exactly as for the sealed record and roster.
type ScuttleReceipt struct {
	ReceiptCore
	ReceiptHash string            `json:"receipt_hash"` // hex SHA-256 of the canonical core
	Signatures  map[string]string `json:"signatures"`   // fpr -> base64 Ed25519 sig over ScuttleReceiptSigningBytes(receipt_hash)
	SignerKeys  map[string]string `json:"signer_keys"`  // fpr -> base64 Ed25519 public key
}

// NewReceipt assembles a receipt from its core and the collected co-signatures.
// sigs and keys are keyed by fingerprint and hold raw bytes.
func NewReceipt(core ReceiptCore, sigs, keys map[string][]byte) *ScuttleReceipt {
	core.Version = ReceiptVersion
	core.MemberFprs = append([]string(nil), core.MemberFprs...)
	sort.Strings(core.MemberFprs)
	h := core.Hash()
	return &ScuttleReceipt{
		ReceiptCore: core,
		ReceiptHash: hex.EncodeToString(h[:]),
		Signatures:  b64map(sigs),
		SignerKeys:  b64map(keys),
	}
}

// Marshal renders the receipt as indented JSON suitable for writing to disk.
func (r *ScuttleReceipt) Marshal() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }

// ParseReceipt decodes a receipt.json, rejecting unknown fields.
func ParseReceipt(b []byte) (*ScuttleReceipt, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var r ScuttleReceipt
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("parse receipt: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("parse receipt: trailing data after JSON object")
	}
	return &r, nil
}

// ReceiptResult summarizes a receipt verification.
type ReceiptResult struct {
	Valid       bool     `json:"valid"`
	Room        string   `json:"room"`
	Reason      string   `json:"reason"` // the scuttle reason
	ScuttledAt  string   `json:"scuttled_at"`
	Signers     []string `json:"signers"`
	ReceiptHash string   `json:"receipt_hash"`
	Error       string   `json:"error,omitempty"` // failure detail when !Valid
}

// VerifyReceipt checks that (1) receipt_hash matches the canonical core bytes,
// (2) keys_zeroized is true, and (3) every signature is a valid Ed25519 signature
// over the domain-separated receipt-hash preimage, by a key that hashes to its
// fingerprint. Any failure yields Valid=false with a specific Error; err is
// non-nil only for malformed inputs that prevent verification entirely.
func VerifyReceipt(r *ScuttleReceipt) (*ReceiptResult, error) {
	res := &ReceiptResult{Room: r.Room, Reason: r.Reason, ScuttledAt: r.ScuttledAt, ReceiptHash: r.ReceiptHash}

	if r.Version != ReceiptVersion {
		res.Error = fmt.Sprintf("unsupported receipt version %q (want %q)", r.Version, ReceiptVersion)
		return res, nil
	}
	if !r.KeysZeroized {
		res.Error = "keys_zeroized is not true — receipt does not attest destruction"
		return res, nil
	}

	// 1: the core must hash to the stored receipt_hash.
	h := r.ReceiptCore.Hash()
	if hex.EncodeToString(h[:]) != r.ReceiptHash {
		res.Error = fmt.Sprintf("receipt_hash %s does not match the canonical receipt bytes (recomputed %s)", r.ReceiptHash, hex.EncodeToString(h[:]))
		return res, nil
	}
	hashBytes, err := hex.DecodeString(r.ReceiptHash)
	if err != nil {
		return res, fmt.Errorf("receipt_hash is not valid hex: %w", err)
	}

	// 2: every signature verifies over the receipt hash.
	if len(r.Signatures) == 0 {
		res.Error = "receipt has no signatures"
		return res, nil
	}
	preimage := protocol.ScuttleReceiptSigningBytes(hashBytes)
	signers := make([]string, 0, len(r.Signatures))
	for fpr, sigB64 := range r.Signatures {
		keyB64, ok := r.SignerKeys[fpr]
		if !ok {
			res.Error = fmt.Sprintf("no signer key for %s (cannot verify its signature)", fpr)
			return res, nil
		}
		key, err := base64.StdEncoding.DecodeString(keyB64)
		if err != nil || len(key) != ed25519.PublicKeySize {
			res.Error = fmt.Sprintf("signer key for %s is malformed", fpr)
			return res, nil
		}
		if crypto.Fingerprint(ed25519.PublicKey(key)) != fpr {
			res.Error = fmt.Sprintf("signer key for %s does not match its fingerprint", fpr)
			return res, nil
		}
		sig, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			res.Error = fmt.Sprintf("signature for %s is not valid base64", fpr)
			return res, nil
		}
		if !ed25519.Verify(ed25519.PublicKey(key), preimage, sig) {
			res.Error = fmt.Sprintf("signature for %s does not verify over the receipt hash", fpr)
			return res, nil
		}
		signers = append(signers, fpr)
	}
	sort.Strings(signers)
	res.Signers = signers
	res.Valid = true
	return res, nil
}
