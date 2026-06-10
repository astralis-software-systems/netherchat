package sneakernet

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// blobVersion is the wire version of an offer/answer blob.
const blobVersion = 1

// BlobTTL bounds how long a pairing blob is valid after it is minted (§1.1). A
// short window means a copied-and-pasted offer cannot be replayed hours later.
const BlobTTL = 300 * time.Second

const (
	offerBegin  = "----BEGIN NETHERCHAT OFFER----"
	offerEnd    = "----END NETHERCHAT OFFER----"
	answerBegin = "----BEGIN NETHERCHAT ANSWER----"
	answerEnd   = "----END NETHERCHAT ANSWER----"
)

// Blob is a signed pairing token exchanged out of band (read aloud, pasted into a
// chat) to bootstrap a relay-less connection — manual pairing for when there is no
// shared LAN to discover on (§1.1). An OFFER advertises the listening host; an
// ANSWER carries the responder's identity back so the host can confirm who joined.
// Both have the identical shape; only the armor header differs.
//
// The Ed25519 signature (over every other field) proves the blob came from the
// holder of Fpr's key — a tampered address list or substituted key fails Verify.
// The 300s expiry bounds replay.
type Blob struct {
	V       int      `json:"v"`
	Pub     string   `json:"pub"`     // base64 Ed25519 public key (verifies Sig; Fpr is its fingerprint)
	Fpr     string   `json:"fpr"`     // SHA256:… fingerprint, for human cross-check
	KXPub   string   `json:"kx_pub"`  // base64 X25519 key-agreement public key (room-key wrapping)
	Addrs   []string `json:"addrs"`   // host:port addresses the offerer's listener is reachable at
	Room    string   `json:"room"`    //
	Nonce   string   `json:"nonce"`   // 16 hex chars, anti-replay
	Expires int64    `json:"expires"` // unix seconds
	Sig     string   `json:"sig"`     // base64 Ed25519 over signingBytes()
}

// blobCore is the signed portion of a Blob (everything but Sig), marshaled
// deterministically so signer and verifier derive identical bytes.
type blobCore struct {
	V       int      `json:"v"`
	Pub     string   `json:"pub"`
	KXPub   string   `json:"kx_pub"`
	Addrs   []string `json:"addrs"`
	Room    string   `json:"room"`
	Nonce   string   `json:"nonce"`
	Expires int64    `json:"expires"`
}

func (b *Blob) signingBytes() []byte {
	j, _ := json.Marshal(blobCore{b.V, b.Pub, b.KXPub, b.Addrs, b.Room, b.Nonce, b.Expires})
	return j
}

// NewBlob mints and signs a pairing blob for room, advertising addrs as the
// offerer's reachable listener addresses.
func NewBlob(id *crypto.Identity, room string, addrs []string) (*Blob, error) {
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	b := &Blob{
		V:       blobVersion,
		Pub:     base64.StdEncoding.EncodeToString(id.SignPub),
		Fpr:     id.Fingerprint(),
		KXPub:   base64.StdEncoding.EncodeToString(id.KXPub[:]),
		Addrs:   addrs,
		Room:    room,
		Nonce:   hex.EncodeToString(nonce),
		Expires: time.Now().Add(BlobTTL).Unix(),
	}
	sig, err := id.Sign(b.signingBytes())
	if err != nil {
		return nil, fmt.Errorf("sign blob: %w", err)
	}
	b.Sig = base64.StdEncoding.EncodeToString(sig)
	return b, nil
}

// PublicKey returns the verified Ed25519 public key carried by the blob.
func (b *Blob) PublicKey() (ed25519.PublicKey, error) {
	pub, err := base64.StdEncoding.DecodeString(b.Pub)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("invalid public key in blob")
	}
	return ed25519.PublicKey(pub), nil
}

// Verify checks the blob's version, that its fingerprint matches its public key,
// that the signature is valid, and that it has not expired. A blob that fails any
// of these is never acted on.
func (b *Blob) Verify() error {
	if b.V != blobVersion {
		return fmt.Errorf("unsupported blob version %d", b.V)
	}
	pub, err := b.PublicKey()
	if err != nil {
		return err
	}
	if crypto.Fingerprint(pub) != b.Fpr {
		return errors.New("blob fingerprint does not match its public key")
	}
	sig, err := base64.StdEncoding.DecodeString(b.Sig)
	if err != nil {
		return errors.New("invalid signature encoding in blob")
	}
	if !ed25519.Verify(pub, b.signingBytes(), sig) {
		return errors.New("blob signature verification failed")
	}
	if time.Now().Unix() > b.Expires {
		return fmt.Errorf("blob expired at %s (offers are valid for %s)", time.Unix(b.Expires, 0).Format(time.RFC3339), BlobTTL)
	}
	return nil
}

// Armor renders the blob as a copy-pasteable, base64-armored block. kind is
// "offer" or "answer" and only selects the header text.
func (b *Blob) Armor(kind string) string {
	begin, end := offerBegin, offerEnd
	if kind == "answer" {
		begin, end = answerBegin, answerEnd
	}
	j, _ := json.Marshal(b)
	enc := base64.StdEncoding.EncodeToString(j)
	var sb strings.Builder
	sb.WriteString(begin)
	sb.WriteByte('\n')
	for i := 0; i < len(enc); i += 64 {
		stop := i + 64
		if stop > len(enc) {
			stop = len(enc)
		}
		sb.WriteString(enc[i:stop])
		sb.WriteByte('\n')
	}
	sb.WriteString(end)
	return sb.String()
}

// ParseBlob decodes and VERIFIES an armored offer/answer block. Surrounding text,
// the BEGIN/END lines, and whitespace are tolerated, so a user can paste the block
// with a little slop. A blob that fails verification (bad signature, wrong
// fingerprint, or expired) returns an error and must not be used.
func ParseBlob(armored string) (*Blob, error) {
	var b64 strings.Builder
	for _, ln := range strings.Split(armored, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "----") {
			continue
		}
		b64.WriteString(ln)
	}
	raw, err := base64.StdEncoding.DecodeString(b64.String())
	if err != nil {
		return nil, fmt.Errorf("decode pairing blob: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var blob Blob
	if err := dec.Decode(&blob); err != nil {
		return nil, fmt.Errorf("parse pairing blob: %w", err)
	}
	if err := blob.Verify(); err != nil {
		return nil, err
	}
	return &blob, nil
}
