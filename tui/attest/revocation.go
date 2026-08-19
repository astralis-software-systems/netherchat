package attest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// This file holds the revocation half of identity/v1: an issuer-signed statement
// naming the serials it has withdrawn. Serial is the unit of revocation for a
// reason — withdrawing a binding by naming the SUBJECT key would also withdraw
// every other statement about that key, including a later, corrected one.
//
// THE HONEST LIMIT, up front, because the format cannot fix it. Offline
// verification cannot consult a fresh list. There is no OCSP and no CRL fetch,
// and there must not be: this artifact's defining property is that it needs no
// network. So the provable claim is exactly "at time T, serial N was not listed
// as revoked by statement R (number K, issued at I) from issuer J" — never "N is
// not revoked". Between R and the moment anyone reads it, the issuer may have
// revoked N a hundred times. Which means the claim is only provable if the
// statement's identifier and the outcome are recorded in the evidence, and
// recording a claim into a record is the consumer's decision: this package
// surfaces the check in IdentityResult.Revocation and writes nothing anywhere.

// RevocationVersion is the value of RevocationStatement.Version — a stability
// contract for the on-disk shape, and the artifact-type discriminator.
const RevocationVersion = "v1"

// RevokedSerial is one withdrawn statement: which serial, when, and — opaquely —
// why. Reason is the issuer's own text and is never compared to anything here.
type RevokedSerial struct {
	Serial    string `json:"serial"`
	RevokedAt string `json:"revoked_at"`       // RFC3339
	Reason    string `json:"reason,omitempty"` // opaque issuer-supplied cause
}

// RevocationStatement is an issuer's signed list of withdrawn serials.
//
// Signatures and SignerKeys carry the same meaning and the same warning as on
// IdentityAttestation: the map is plural so a statement may carry an outgoing
// and an incoming authority's signature at once, and an embedded key is checked
// for consistency and never trusted as an anchor.
//
// Number and NextUpdate are reported and never enforced. Whether a statement is
// fresh enough to act on is a policy question, and policy lives on the consumer
// side of this seam.
type RevocationStatement struct {
	Version     string            `json:"netherchat_revocation"` // RevocationVersion ("v1")
	Issuer      string            `json:"issuer"`                // whose serials these are
	StatementID string            `json:"statement_id"`          // stable id, recorded in evidence
	Number      uint64            `json:"number"`                // monotonic; a higher number supersedes
	IssuedAt    string            `json:"issued_at"`             // RFC3339
	NextUpdate  string            `json:"next_update,omitempty"` // when the issuer intends to publish a fresher one
	Revoked     []RevokedSerial   `json:"revoked"`
	Signatures  map[string]string `json:"signatures"`  // issuer fpr -> base64 Ed25519 sig over RevocationSigningBytes
	SignerKeys  map[string]string `json:"signer_keys"` // issuer fpr -> base64 Ed25519 public key
}

// RevocationSpec is the unsigned input to NewRevocation. The constructor
// supplies Version and stamps IssuedAt; everything else is the issuer's.
type RevocationSpec struct {
	Issuer      string
	StatementID string
	Number      uint64
	NextUpdate  string
	Revoked     []RevokedSerial
}

// NewRevocation assembles a revocation statement from its spec and the collected
// issuer signatures. Entry order is preserved exactly as the issuer supplied it,
// because the order is inside the signed bytes; sorting here would change what a
// signature means. Like NewIdentityAttestation this is a clock-reading
// constructor, and like it a signing tool builds unsigned, derives the preimage,
// signs, and calls WithSignatures.
func NewRevocation(spec RevocationSpec, sigs, keys map[string][]byte) *RevocationStatement {
	return &RevocationStatement{
		Version:     RevocationVersion,
		Issuer:      spec.Issuer,
		StatementID: spec.StatementID,
		Number:      spec.Number,
		IssuedAt:    nowRFC3339(),
		NextUpdate:  spec.NextUpdate,
		Revoked:     append([]RevokedSerial(nil), spec.Revoked...),
		Signatures:  b64map(sigs),
		SignerKeys:  b64map(keys),
	}
}

// WithSignatures returns a copy of the statement carrying the given issuer
// signatures and public keys, leaving every signed field exactly as it was when
// the preimage was derived.
func (s *RevocationStatement) WithSignatures(sigs, keys map[string][]byte) *RevocationStatement {
	out := *s
	out.Revoked = append([]RevokedSerial(nil), s.Revoked...)
	out.Signatures = b64map(sigs)
	out.SignerKeys = b64map(keys)
	return &out
}

// RevocationSigningBytes re-exports the canonical revocation layout from the
// protocol package so an external issuer tool can derive the exact bytes through
// the sealedrecord façade. It unpacks the statement and calls the protocol
// function; it writes no bytes of its own.
func RevocationSigningBytes(s *RevocationStatement) []byte {
	if s == nil {
		return nil
	}
	serials := make([]string, len(s.Revoked))
	revokedAt := make([]string, len(s.Revoked))
	reasons := make([]string, len(s.Revoked))
	for i, r := range s.Revoked {
		serials[i], revokedAt[i], reasons[i] = r.Serial, r.RevokedAt, r.Reason
	}
	return protocol.RevocationSigningBytes(s.Issuer, s.StatementID, s.Number, s.IssuedAt, s.NextUpdate,
		serials, revokedAt, reasons)
}

// Marshal renders the statement as indented JSON suitable for writing to disk.
func (s *RevocationStatement) Marshal() ([]byte, error) { return json.MarshalIndent(s, "", "  ") }

// ParseRevocation decodes a revocation.json, rejecting unknown fields so a
// differently shaped artifact fails loudly rather than verifying something we do
// not fully understand.
func ParseRevocation(b []byte) (*RevocationStatement, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var s RevocationStatement
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("parse revocation: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("parse revocation: trailing data after JSON object")
	}
	return &s, nil
}

// RevocationResult summarizes a revocation-statement verification. It reuses
// IdentityReason so a consumer branches on one code vocabulary rather than two.
type RevocationResult struct {
	Valid       bool                `json:"valid"`
	Issuer      string              `json:"issuer"`
	StatementID string              `json:"statement_id"`
	Number      uint64              `json:"number"`
	IssuedAt    string              `json:"issued_at"`
	NextUpdate  string              `json:"next_update,omitempty"`
	Serials     int                 `json:"serials"`     // how many entries the statement lists
	VerifiedBy  []string            `json:"verified_by"` // pinned issuer fingerprints whose signature verified, sorted
	Reason      IdentityReason      `json:"reason,omitempty"`
	ReasonClass IdentityReasonClass `json:"reason_class,omitempty"`
	Detail      string              `json:"detail,omitempty"`
}

// RevocationCheck is what one supplied statement contributed to an identity
// verdict. It is reported per statement so a consumer can see exactly which
// statements were consulted, and record that in its evidence.
//
// CoversIssuer is the load-bearing one: a statement from a different authority
// says nothing about this serial, and must never be read as clearing it. Stale
// is a fact and nothing more — it does not change Valid, because whether a
// statement is fresh enough is policy.
//
// An EMPTY IdentityResult.Revocation slice means no statement was supplied. It
// does not mean "not revoked". A consumer that treats the empty slice as a clean
// bill of health has made a policy decision, and it will be visible in its code
// that it did.
type RevocationCheck struct {
	StatementID  string `json:"statement_id"`
	Number       uint64 `json:"number"`
	IssuedAt     string `json:"issued_at"`
	NextUpdate   string `json:"next_update,omitempty"`
	Issuer       string `json:"issuer"`
	CoversIssuer bool   `json:"covers_issuer"`
	Listed       bool   `json:"listed"`
	Stale        bool   `json:"stale"`
}

// VerifyRevocation checks a statement against the caller's pinned issuer keys.
// It mirrors VerifyIdentity's signature loop exactly, including its tolerance:
// it iterates the CALLER's keys, collects per-key outcomes instead of returning
// on the first failure, and treats any one verifying signature as enough to
// anchor the statement. A statement carrying a stale signature under a
// rotated-out key must not be rejected because that key happened to be listed
// first.
//
// As everywhere here, err means the call was unusable and Reason means the
// artifact did not verify.
func VerifyRevocation(s *RevocationStatement, issuerKeys []ed25519.PublicKey) (*RevocationResult, error) {
	if s == nil {
		return nil, fmt.Errorf("verify revocation: statement is nil")
	}
	for i, k := range issuerKeys {
		if len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("verify revocation: issuer key %d is %d bytes, want %d", i, len(k), ed25519.PublicKeySize)
		}
	}
	res := &RevocationResult{
		Issuer:      s.Issuer,
		StatementID: s.StatementID,
		Number:      s.Number,
		IssuedAt:    s.IssuedAt,
		NextUpdate:  s.NextUpdate,
		Serials:     len(s.Revoked),
	}
	revFail := func(r IdentityReason, detail string) *RevocationResult {
		res.Valid = false
		res.Reason = r
		res.ReasonClass = ClassOf(r)
		res.Detail = detail
		return res
	}

	if s.Version != RevocationVersion {
		return revFail(ReasonUnsupportedVersion,
			fmt.Sprintf("unsupported revocation version %q (this build reads %q)", s.Version, RevocationVersion)), nil
	}
	if !isFingerprint(s.Issuer) {
		return revFail(ReasonMalformedIssuer,
			fmt.Sprintf("issuer %q is not an SSH SHA-256 fingerprint", s.Issuer)), nil
	}
	if s.StatementID == "" {
		return revFail(ReasonMalformedSerial, "statement_id must not be empty"), nil
	}
	if _, err := time.Parse(time.RFC3339, s.IssuedAt); err != nil {
		return revFail(ReasonMalformedTime,
			fmt.Sprintf("issued_at %q does not parse as RFC3339", s.IssuedAt)), nil
	}
	if s.NextUpdate != "" {
		if _, err := time.Parse(time.RFC3339, s.NextUpdate); err != nil {
			return revFail(ReasonMalformedTime,
				fmt.Sprintf("next_update %q does not parse as RFC3339", s.NextUpdate)), nil
		}
	}
	for i, r := range s.Revoked {
		if r.Serial == "" {
			return revFail(ReasonMalformedSerial, fmt.Sprintf("revoked entry %d has an empty serial", i)), nil
		}
		if _, err := time.Parse(time.RFC3339, r.RevokedAt); err != nil {
			return revFail(ReasonMalformedTime,
				fmt.Sprintf("revoked entry %d: revoked_at %q does not parse as RFC3339", i, r.RevokedAt)), nil
		}
	}
	if _, ok := s.Signatures[s.Issuer]; !ok {
		return revFail(ReasonIssuerDidNotSign,
			fmt.Sprintf("no signature under the named issuer %s", s.Issuer)), nil
	}
	if len(issuerKeys) == 0 {
		return revFail(ReasonNoIssuerPinned,
			"no issuer key was supplied, so nothing about this statement was checked"), nil
	}

	preimage := RevocationSigningBytes(s)
	var outcomes []keyOutcome
	for _, pinned := range issuerKeys {
		fpr := crypto.Fingerprint(pinned)
		sigB64, named := s.Signatures[fpr]
		if !named {
			continue
		}
		if keyB64, present := s.SignerKeys[fpr]; present {
			embedded, derr := base64.StdEncoding.DecodeString(keyB64)
			if derr != nil || len(embedded) != ed25519.PublicKeySize {
				outcomes = append(outcomes, keyOutcome{fpr, ReasonSignerKeyMalformed})
				continue
			}
			if crypto.Fingerprint(ed25519.PublicKey(embedded)) != fpr {
				outcomes = append(outcomes, keyOutcome{fpr, ReasonSignerKeyMismatch})
				continue
			}
		}
		sig, derr := base64.StdEncoding.DecodeString(sigB64)
		if derr != nil {
			outcomes = append(outcomes, keyOutcome{fpr, ReasonSignatureMalformed})
			continue
		}
		if !ed25519.Verify(pinned, preimage, sig) {
			outcomes = append(outcomes, keyOutcome{fpr, ReasonSignatureInvalid})
			continue
		}
		res.VerifiedBy = append(res.VerifiedBy, fpr)
	}
	sort.Strings(res.VerifiedBy)
	sort.Slice(outcomes, func(i, j int) bool { return outcomes[i].fpr < outcomes[j].fpr })

	if len(res.VerifiedBy) == 0 {
		if len(outcomes) == 0 {
			return revFail(ReasonNoPinnedIssuerVerified,
				fmt.Sprintf("none of the %d pinned issuer key(s) signed this statement", len(issuerKeys))), nil
		}
		worst := outcomes[0]
		for _, o := range outcomes[1:] {
			if severity(o.reason) > severity(worst.reason) {
				worst = o
			}
		}
		return revFail(worst.reason, describeOutcomes(outcomes)), nil
	}
	if len(outcomes) > 0 {
		res.Detail = fmt.Sprintf("verified by %d of %d pinned issuer(s); %s",
			len(res.VerifiedBy), len(res.VerifiedBy)+len(outcomes), describeOutcomes(outcomes))
	}
	res.Valid = true
	return res, nil
}

// checkRevocations runs VerifyIdentity's step 8 over the supplied statements. It
// returns one RevocationCheck per statement, the id of the first covering,
// verified statement that lists the serial, and the id of the first statement
// that did not itself verify.
//
// A statement that does not verify is a loud failure rather than a shrug: it was
// handed to a verifier as evidence about an issuer's intent, and evidence that
// does not verify is the one case where saying nothing would be worse than
// saying no.
func checkRevocations(a *IdentityAttestation, opts IdentityOptions) (checks []RevocationCheck, revokedBy, unverifiable string) {
	for _, s := range opts.Revocations {
		if s == nil {
			continue
		}
		id := s.StatementID
		if id == "" {
			id = "(unnamed statement)"
		}
		res, err := VerifyRevocation(s, opts.IssuerKeys)
		if err != nil || !res.Valid {
			if unverifiable == "" {
				unverifiable = id
			}
			continue
		}
		check := RevocationCheck{
			StatementID:  s.StatementID,
			Number:       s.Number,
			IssuedAt:     s.IssuedAt,
			NextUpdate:   s.NextUpdate,
			Issuer:       s.Issuer,
			CoversIssuer: s.Issuer == a.Issuer,
		}
		if s.NextUpdate != "" {
			if next, perr := time.Parse(time.RFC3339, s.NextUpdate); perr == nil {
				check.Stale = opts.At.After(next)
			}
		}
		if check.CoversIssuer {
			for _, r := range s.Revoked {
				if r.Serial == a.Serial {
					check.Listed = true
					if revokedBy == "" {
						revokedBy = id
					}
					break
				}
			}
		}
		checks = append(checks, check)
	}
	return checks, revokedBy, unverifiable
}
