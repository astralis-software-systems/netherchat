package record

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// FormatVersion is the value of SealedRecord.Version. It is a stability contract
// for the on-disk record.json shape, bumped only on a breaking change.
const FormatVersion = "v1"

// SealedRecord is the machine-readable artifact written by /seal: the entire
// entry chain plus, for each participant who co-signed, an Ed25519 signature over
// the chain head (§1.4). It is self-verifying — SignerKeys carries the public
// keys needed to check the seal signatures, and each entry carries the key needed
// to check its own — so `netherchat verify` needs nothing but the file.
type SealedRecord struct {
	Version    string            `json:"netherchat_record"` // FormatVersion ("v1")
	Room       string            `json:"room"`
	SealedAt   string            `json:"sealed_at"` // RFC3339 UTC
	SealedBy   string            `json:"sealed_by"` // fingerprint of the participant who ran /seal
	Entries    []Entry           `json:"entries"`
	HeadHash   string            `json:"head_hash"`   // hex SHA-256 of the last entry's canonical bytes
	Signatures map[string]string `json:"signatures"`  // fingerprint -> base64 Ed25519 sig over SealSigningBytes(room, head)
	SignerKeys map[string]string `json:"signer_keys"` // fingerprint -> base64 Ed25519 public key (to verify Signatures)
}

// NewSealedRecord assembles a record from a finished chain and the collected seal
// signatures. sealerSigs and sealerKeys are keyed by fingerprint and hold raw
// bytes; they are base64-encoded here.
func NewSealedRecord(room, sealedBy string, entries []Entry, head []byte, sealerSigs, sealerKeys map[string][]byte) *SealedRecord {
	sigs := make(map[string]string, len(sealerSigs))
	for fpr, sig := range sealerSigs {
		sigs[fpr] = base64.StdEncoding.EncodeToString(sig)
	}
	keys := make(map[string]string, len(sealerKeys))
	for fpr, k := range sealerKeys {
		keys[fpr] = base64.StdEncoding.EncodeToString(k)
	}
	return &SealedRecord{
		Version:    FormatVersion,
		Room:       room,
		SealedAt:   time.Now().UTC().Format(time.RFC3339),
		SealedBy:   sealedBy,
		Entries:    entries,
		HeadHash:   hex.EncodeToString(head),
		Signatures: sigs,
		SignerKeys: keys,
	}
}

// Marshal renders the record as indented JSON suitable for writing to disk.
func (r *SealedRecord) Marshal() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }

// Parse decodes a record.json, rejecting unknown fields so a record with extra or
// renamed keys (a different/forward format) fails loudly rather than verifying a
// shape we do not fully understand.
func Parse(b []byte) (*SealedRecord, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var r SealedRecord
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("parse record: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("parse record: trailing data after JSON object")
	}
	return &r, nil
}

// VerifyResult summarizes a verification. Valid is true only if the chain links,
// every entry signature, the head hash, and every seal signature all check out.
type VerifyResult struct {
	Valid    bool     `json:"valid"`
	Room     string   `json:"room"`
	Entries  int      `json:"entries"`
	Signers  []string `json:"signers"`          // fingerprints whose seal signature verified
	HeadHash string   `json:"head_hash"`        // recomputed, hex
	Reason   string   `json:"reason,omitempty"` // failure detail when !Valid
}

// Verify recomputes the chain from scratch and checks every integrity property
// (§1.4):
//
//  1. each entry's Seq is its index and PrevHash links to the prior entry's hash;
//  2. each entry's Ed25519 signature verifies against its author (and the author
//     key hashes to the claimed AuthorID);
//  3. the recomputed head equals the stored head_hash;
//  4. every seal signature verifies against the signer's key over the
//     domain-separated, room-bound head preimage, and the signer key hashes to
//     its fingerprint.
//
// Any failure yields Valid=false with a specific Reason; err is non-nil only for
// malformed inputs (e.g. a non-hex head_hash) that prevent verification entirely.
func Verify(r *SealedRecord) (*VerifyResult, error) {
	res := &VerifyResult{Room: r.Room, Entries: len(r.Entries)}

	if r.Version != FormatVersion {
		res.Reason = fmt.Sprintf("unsupported record version %q (want %q)", r.Version, FormatVersion)
		return res, nil
	}

	// 1 + 2: walk the chain.
	prev := zeroHash()
	for i, e := range r.Entries {
		if e.Seq != uint64(i) {
			res.Reason = fmt.Sprintf("entry %d has seq %d (chain reordered or entries removed)", i, e.Seq)
			return res, nil
		}
		if !bytes.Equal(e.PrevHash, prev) {
			res.Reason = fmt.Sprintf("entry %d prev_hash does not link to the previous entry (chain tampered)", i)
			return res, nil
		}
		if err := VerifyEntry(e); err != nil {
			res.Reason = err.Error()
			return res, nil
		}
		h := e.Hash()
		prev = h[:]
	}

	// 3: the head the sealers signed must be the recomputed head.
	res.HeadHash = hex.EncodeToString(prev)
	storedHead, err := hex.DecodeString(r.HeadHash)
	if err != nil {
		return res, fmt.Errorf("head_hash is not valid hex: %w", err)
	}
	if !bytes.Equal(storedHead, prev) {
		res.Reason = fmt.Sprintf("head_hash %s does not match the recomputed chain head %s", r.HeadHash, res.HeadHash)
		return res, nil
	}

	// 4: seal signatures.
	if len(r.Signatures) == 0 {
		res.Reason = "record has no seal signatures"
		return res, nil
	}
	preimage := protocol.SealSigningBytes(r.Room, prev)
	signers := make([]string, 0, len(r.Signatures))
	for fpr, sigB64 := range r.Signatures {
		keyB64, ok := r.SignerKeys[fpr]
		if !ok {
			res.Reason = fmt.Sprintf("no signer key for %s (cannot verify its seal signature)", fpr)
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
			res.Reason = fmt.Sprintf("seal signature for %s is not valid base64", fpr)
			return res, nil
		}
		if !ed25519.Verify(ed25519.PublicKey(key), preimage, sig) {
			res.Reason = fmt.Sprintf("seal signature for %s does not verify against the head", fpr)
			return res, nil
		}
		signers = append(signers, fpr)
	}
	sort.Strings(signers)
	res.Signers = signers
	res.Valid = true
	return res, nil
}

// nameByFingerprint builds a fingerprint -> display name map from entry authors,
// for rendering signer names in the minutes (names are cosmetic; the fingerprint
// is the authenticated identity).
func (r *SealedRecord) nameByFingerprint() map[string]string {
	m := make(map[string]string)
	for _, e := range r.Entries {
		if _, ok := m[e.AuthorID]; !ok && e.AuthorName != "" {
			m[e.AuthorID] = e.AuthorName
		}
	}
	return m
}

// RenderMinutes produces the human-readable minutes.md (§1.4): decisions, action
// items, and notes grouped under headings, with a participant line and a verify
// hint. It does not re-verify — call Verify first.
func RenderMinutes(r *SealedRecord) string {
	names := r.nameByFingerprint()
	var b strings.Builder

	room := r.Room
	if room == "" {
		room = "(unnamed)"
	}
	fmt.Fprintf(&b, "# Incident Record — %s\n", room)
	fmt.Fprintf(&b, "Sealed: %s\n", r.SealedAt)

	// Participants: every fingerprint that co-signed, by display name where known.
	signers := make([]string, 0, len(r.Signatures))
	for fpr := range r.Signatures {
		signers = append(signers, fpr)
	}
	sort.Strings(signers)
	parts := make([]string, 0, len(signers))
	for _, fpr := range signers {
		who := names[fpr]
		if who == "" {
			who = shortFpr(fpr)
		}
		parts = append(parts, who+" (✓)")
	}
	fmt.Fprintf(&b, "Participants: %s\n", strings.Join(parts, ", "))

	var decisions, actions, notes []Entry
	for _, e := range r.Entries {
		switch e.Kind {
		case KindDecision:
			decisions = append(decisions, e)
		case KindAction:
			actions = append(actions, e)
		case KindNote:
			notes = append(notes, e)
		}
	}

	if len(decisions) > 0 {
		b.WriteString("\n## Decisions\n")
		for i, e := range decisions {
			fmt.Fprintf(&b, "%d. [%s] **%s**: %s\n", i+1, hhmmUTC(e.TS), e.AuthorName, e.Body)
		}
	}
	if len(actions) > 0 {
		b.WriteString("\n## Actions\n")
		for _, e := range actions {
			fmt.Fprintf(&b, "- [ ] **%s**: %s (assigned by %s)\n", e.Actionee, e.Body, e.AuthorName)
		}
	}
	if len(notes) > 0 {
		b.WriteString("\n## Notes\n")
		for _, e := range notes {
			fmt.Fprintf(&b, "- [%s] **%s**: %s\n", hhmmUTC(e.TS), e.AuthorName, e.Body)
		}
	}

	fmt.Fprintf(&b, "\n---\n*Sealed by %d participant(s). Verify: netherchat verify record.json*\n", len(r.Signatures))
	return b.String()
}

// hhmmUTC formats a unix timestamp as "15:04 UTC", matching the minutes example.
func hhmmUTC(ts int64) string { return time.Unix(ts, 0).UTC().Format("15:04") + " UTC" }

// shortFpr abbreviates a long "SHA256:…" fingerprint for display when no name is
// known. Falls back to the full string if it is unexpectedly short.
func shortFpr(fpr string) string {
	const n = 16
	if len(fpr) <= n {
		return fpr
	}
	return fpr[:n] + "…"
}
