package attest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// This file holds identity/v1: an issuer-signed, offline-verifiable statement
// binding a key fingerprint to a principal and a set of roles, for a stated
// window of time. It is the third trust mechanism in Netherchat and replaces
// neither of the other two — SAS peer verification answers "is this key the
// human I already know?" from the operator's own side channel, and the roster
// attestation answers "who held the room key at this epoch" while deliberately
// signing no names at all.
//
// WHAT THIS LAYER SAYS, AND WHERE IT STOPS. A verified binding means: the issuer
// key YOU supplied signed a statement about this fingerprint, and that
// statement's window contained the time YOU supplied. It does not mean the
// principal is entitled to anything. Netherchat holds no trust anchors: issuer
// keys and the evaluation time are parameters on every call, there is no issuer
// configuration to read, and with no key supplied the answer is a legible
// "nobody was asked", never a verdict about the subject.

// IdentityVersion is the value of IdentityAttestation.Version — a stability
// contract for the on-disk identity.json shape, bumped only on a breaking
// change. It doubles as the artifact-type discriminator: the JSON key
// netherchat_identity is what a verifier sniffs to tell this file from a record,
// a roster, or a receipt.
const IdentityVersion = "v1"

// AlgorithmEd25519 is the only signature algorithm this version verifies. It is
// inside the signing preimage, so an attestation cannot be relabelled to steer a
// later multi-algorithm verifier onto a different path.
const AlgorithmEd25519 = "ed25519"

// IdentitySchema is the opaque record.Entry.Schema tag of an embedded
// attestation entry — the exact string, and part of the entry's signed bytes.
const IdentitySchema = "netherchat.identity/v1"

// fingerprintPrefix and fingerprintBodyLen describe the SSH SHA-256 fingerprint
// dialect this package accepts: ssh.FingerprintSHA256 renders "SHA256:" followed
// by unpadded standard base64 of a 32-byte digest, which is 43 characters. Any
// other shape is a differently-made identifier and is rejected rather than
// compared loosely.
const (
	fingerprintPrefix  = "SHA256:"
	fingerprintBodyLen = 43
)

// IdentityAttestation is an issuer's signed statement about one key (identity
// v1): this fingerprint belongs to this principal, in these roles, between these
// times.
//
// Signatures and SignerKeys are both keyed by ISSUER fingerprint and do two
// different jobs. Signatures is what gets checked. SignerKeys is what makes the
// artifact self-describing — a person handed an identity.json can read which key
// signed it and go pin that key, and a verifier can name the issuer without any
// pin at all — because a fingerprint is a hash of a key, so a verifier cannot
// recover the key from it. SignerKeys is NEVER a trust anchor: verification is
// driven entirely by the caller's pinned keys, and an embedded key is only
// cross-checked for internal consistency. "The file carries the key that
// verifies it" is exactly the circular trust this design refuses.
//
// Both maps are plural rather than scalar so issuer key ROTATION and dual
// issuance work: an attestation may carry the outgoing and the incoming
// authority's signatures at once, and a verifier that has pinned either one is
// satisfied.
type IdentityAttestation struct {
	Version       string            `json:"netherchat_identity"` // IdentityVersion ("v1")
	Serial        string            `json:"serial"`              // issuer-unique id for THIS statement; the unit of revocation
	Subject       string            `json:"subject"`             // "SHA256:…" fingerprint of the subject's Ed25519 identity key
	Principal     string            `json:"principal"`           // the enterprise-shaped identifier: a UPN, an email, an employee id
	PrincipalType string            `json:"principal_type"`      // opaque; conventionally person | service | agent
	Roles         []string          `json:"roles"`               // opaque role strings, byte-for-byte as the issuer wrote them
	IssuedAt      string            `json:"issued_at"`           // RFC3339
	ExpiresAt     string            `json:"expires_at"`          // RFC3339
	Algorithm     string            `json:"algorithm"`           // AlgorithmEd25519
	Issuer        string            `json:"issuer"`              // "SHA256:…" fingerprint of the issuing authority
	Signatures    map[string]string `json:"signatures"`          // issuer fpr -> base64 Ed25519 sig over IdentitySigningBytes
	SignerKeys    map[string]string `json:"signer_keys"`         // issuer fpr -> base64 Ed25519 public key
}

// IdentitySpec is the unsigned input to NewIdentityAttestation: everything an
// issuer decides, with nothing derived. The constructor supplies Version and
// stamps IssuedAt, so a signing tool never has to assemble a half-populated
// artifact by hand.
//
// Roles are sorted by the constructor and then signed in that order. Nothing
// else about them is touched: they are not trimmed, not case-folded, and not
// checked against any vocabulary, because they are matched byte-for-byte
// downstream and normalizing here would silently change what a signature means.
type IdentitySpec struct {
	Serial        string
	Subject       string
	Principal     string
	PrincipalType string
	Roles         []string
	ExpiresAt     string // RFC3339; must not be empty — an unbounded binding can never be retired except by revocation
	Algorithm     string // AlgorithmEd25519
	Issuer        string
}

// NewIdentityAttestation assembles an attestation from its spec and the
// collected issuer signatures. It sorts roles, stamps issued_at, and base64s the
// two maps. This is the only place in this package that reads a clock, which is
// what keeps verification clock-free.
//
// An issuer tool signs in two steps, because a signature cannot be inside the
// bytes it covers:
//
//	unsigned := attest.NewIdentityAttestation(spec, nil, nil)
//	sig := ed25519.Sign(priv, attest.IdentitySigningBytes(unsigned))
//	att := unsigned.WithSignatures(map[string][]byte{fpr: sig}, map[string][]byte{fpr: pub})
//
// Going through WithSignatures rather than calling this constructor twice is
// what keeps issued_at identical between the bytes that were signed and the
// artifact that ships.
func NewIdentityAttestation(spec IdentitySpec, sigs, keys map[string][]byte) *IdentityAttestation {
	roles := append([]string(nil), spec.Roles...)
	sort.Strings(roles)
	return &IdentityAttestation{
		Version:       IdentityVersion,
		Serial:        spec.Serial,
		Subject:       spec.Subject,
		Principal:     spec.Principal,
		PrincipalType: spec.PrincipalType,
		Roles:         roles,
		IssuedAt:      nowRFC3339(),
		ExpiresAt:     spec.ExpiresAt,
		Algorithm:     spec.Algorithm,
		Issuer:        spec.Issuer,
		Signatures:    b64map(sigs),
		SignerKeys:    b64map(keys),
	}
}

// WithSignatures returns a copy of the attestation carrying the given issuer
// signatures and public keys, leaving every signed field — issued_at included —
// exactly as it was when the preimage was derived. sigs and keys are keyed by
// issuer fingerprint and hold raw bytes.
func (a *IdentityAttestation) WithSignatures(sigs, keys map[string][]byte) *IdentityAttestation {
	out := *a
	out.Roles = append([]string(nil), a.Roles...)
	out.Signatures = b64map(sigs)
	out.SignerKeys = b64map(keys)
	return &out
}

// IdentitySigningBytes re-exports the canonical issuer-signature layout from the
// protocol package so an external issuer tool — an enterprise CA integration
// signing attestations outside this module — can derive the exact bytes through
// the sealedrecord façade, without importing protocol. It unpacks the
// attestation and calls the protocol function; it writes no bytes of its own.
// One place decides what the bytes are; this one only decides who may reach
// them. Same argument as record.Fingerprint.
func IdentitySigningBytes(a *IdentityAttestation) []byte {
	if a == nil {
		return nil
	}
	return protocol.IdentitySigningBytes(a.Serial, a.Subject, a.Principal, a.PrincipalType,
		a.Roles, a.IssuedAt, a.ExpiresAt, a.Algorithm, a.Issuer)
}

// Marshal renders the attestation as indented JSON suitable for writing to disk.
// These are the bytes every carrier moves: the standalone file, the body of a
// netherchat.identity/v1 record entry, and (from Phase 3b) the wire field are the
// same bytes, so one parser and one verifier serve all three.
func (a *IdentityAttestation) Marshal() ([]byte, error) { return json.MarshalIndent(a, "", "  ") }

// ParseIdentity decodes an identity.json, rejecting unknown fields so a
// differently shaped artifact fails loudly rather than verifying something we do
// not fully understand.
func ParseIdentity(b []byte) (*IdentityAttestation, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var a IdentityAttestation
	if err := dec.Decode(&a); err != nil {
		return nil, fmt.Errorf("parse identity: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("parse identity: trailing data after JSON object")
	}
	return &a, nil
}

// IdentityReason is a stable, machine-branchable outcome code. It is a typed
// code rather than a formatted sentence — a deliberate deviation from the roster
// and receipt artifacts, whose Reason is a fmt.Sprintf result — because a
// consumer has to branch on the outcome: a lapsed credential and a forged one
// drive different screens and different operator instructions, and branching on
// a formatted string is a bug factory. The human sentence moves to Detail.
type IdentityReason string

// Every outcome this verifier can report. Empty exactly when Valid is true.
const (
	ReasonNoIssuerPinned         IdentityReason = "no_issuer_pinned"          // the caller supplied no issuer keys — the standalone-inert outcome
	ReasonNoPinnedIssuerVerified IdentityReason = "no_pinned_issuer_verified" // keys were pinned; none of them signed this attestation
	ReasonNotYetValid            IdentityReason = "not_yet_valid"             // the window begins after the evaluation time
	ReasonExpired                IdentityReason = "expired"                   // the window ended before the evaluation time
	ReasonRevoked                IdentityReason = "revoked"                   // the serial appears in a supplied, verified revocation statement
	ReasonUnsupportedVersion     IdentityReason = "unsupported_version"       // netherchat_identity is not IdentityVersion
	ReasonUnsupportedAlgorithm   IdentityReason = "unsupported_algorithm"     // algorithm is not ed25519
	ReasonMalformedSerial        IdentityReason = "malformed_serial"
	ReasonMalformedSubject       IdentityReason = "malformed_subject"
	ReasonMalformedPrincipal     IdentityReason = "malformed_principal"
	ReasonMalformedPrincipalType IdentityReason = "malformed_principal_type"
	ReasonMalformedRoles         IdentityReason = "malformed_roles"
	ReasonMalformedIssuer        IdentityReason = "malformed_issuer"
	ReasonMalformedTime          IdentityReason = "malformed_time"
	ReasonInvertedWindow         IdentityReason = "inverted_window"
	ReasonIssuerDidNotSign       IdentityReason = "issuer_did_not_sign"
	ReasonSignerKeyMalformed     IdentityReason = "signer_key_malformed"
	ReasonSignerKeyMismatch      IdentityReason = "signer_key_mismatch"
	ReasonSignatureMalformed     IdentityReason = "signature_malformed"
	ReasonSignatureInvalid       IdentityReason = "signature_invalid"
	ReasonRevocationUnverifiable IdentityReason = "revocation_unverifiable"
)

// IdentityReasonClass says what KIND of outcome a Reason is. It exists because
// Valid=false was carrying two incompatible meanings: "configure a pin" and
// "someone forged a credential" both yielded false, and nothing structural told
// them apart, so a screen would have shown an unconfigured install the same red
// as an attack.
//
// The precedent for keeping these distinct is one repository over, where a
// consumer's approval-policy state is already split three ways — configured,
// unconfigured, malformed — for the same reason, and says so in a comment: "no
// policy configured" is a deliberate state, not a failed one.
type IdentityReasonClass string

const (
	// ClassUnconfigured: this verifier has no trust anchor. The outcome says
	// nothing whatever about the artifact or its subject.
	ClassUnconfigured IdentityReasonClass = "unconfigured"
	// ClassUnanchored: a well-formed attestation signed by an authority this
	// verifier has not pinned. A statement about the trust relationship, not
	// about the subject.
	ClassUnanchored IdentityReasonClass = "unanchored"
	// ClassLifecycle: the issuer's own statement does not cover the evaluation
	// time. A normal state in the life of a credential.
	ClassLifecycle IdentityReasonClass = "lifecycle"
	// ClassMalformed: the artifact is not well-formed enough for its fields to
	// mean anything.
	ClassMalformed IdentityReasonClass = "malformed"
	// ClassForged: a signature that should have verified did not.
	ClassForged IdentityReasonClass = "forged"
)

// ClassOf maps an outcome code to its class. It is total over the constants
// above; an unknown code classes as malformed, which is the safe default for a
// value this version does not recognize.
//
// THE RENDERING RULE, AND IT IS NORMATIVE. ClassUnconfigured and ClassUnanchored
// must never render as a credential failure, in any surface, in either
// repository. They are facts about the VERIFIER's configuration, not about the
// subject. A screen that shows "Rosa Alvarez — identity could not be verified"
// because nobody has configured an issuer pin is making a claim about Rosa that
// the software did not check. The correct rendering for both is the
// asserted-not-verified state: the local name, labelled as asserted, with the
// reason for the absence of a verified one available but not dressed as a
// finding about the person.
func ClassOf(r IdentityReason) IdentityReasonClass {
	switch r {
	case "":
		return ""
	case ReasonNoIssuerPinned:
		return ClassUnconfigured
	case ReasonNoPinnedIssuerVerified:
		return ClassUnanchored
	case ReasonNotYetValid, ReasonExpired, ReasonRevoked:
		return ClassLifecycle
	case ReasonSignatureInvalid, ReasonRevocationUnverifiable:
		return ClassForged
	default:
		return ClassMalformed
	}
}

// IdentityOptions carries everything verification needs from outside the
// artifact. Both fields that matter are parameters on purpose: this package
// holds no trust anchors and reads no clock.
type IdentityOptions struct {
	// IssuerKeys are the trust anchors, supplied by the caller. Netherchat holds
	// none of its own and reads no issuer configuration. An empty slice is a legal
	// call and yields ReasonNoIssuerPinned, never an error.
	IssuerKeys []ed25519.PublicKey

	// At is the evaluation time. Verification asks whether the validity window
	// CONTAINED this instant — never whether it contains now, which is what makes
	// an old record re-verifiable forever. This package never calls time.Now(), so
	// the value must be set: a zero At is an error, never a verdict. Returning
	// "not yet valid" because the CALLER omitted a parameter would put a sentence
	// in the issuer's mouth, and it would look identical on screen to a genuinely
	// premature credential.
	//
	// Where At should come from is the consumer's decision and a load-bearing one:
	// every candidate inside a record is a self-reported clock, and the one that
	// looks most attractive — the approver's own decision timestamp — is circular,
	// because the approver signs the value that decides whether the approver's own
	// credential had lapsed. A consumer that cares brackets it between two
	// independently-signed timestamps. This function takes the time it is given
	// and asks one question about it.
	At time.Time

	// Revocations are issuer-signed revocation statements to check the serial
	// against. Empty means no statement was supplied — which is reported in the
	// result, not silently treated as "not revoked".
	Revocations []*RevocationStatement
}

// IdentityResult is the verdict on one attestation, for one pin set, at one
// time. All three are inputs, so the same artifact can legitimately produce
// different results on two machines; that is why nothing here is allowed to make
// a sealed record itself invalid.
type IdentityResult struct {
	Valid         bool                `json:"valid"`
	Subject       string              `json:"subject"`
	Principal     string              `json:"principal"`
	PrincipalType string              `json:"principal_type"`
	Roles         []string            `json:"roles"`
	Serial        string              `json:"serial"`
	Issuer        string              `json:"issuer"`      // as stated in the artifact, and tamper-evident: it is inside the preimage
	VerifiedBy    []string            `json:"verified_by"` // pinned issuer fingerprints whose signature verified, sorted
	NotBefore     string              `json:"not_before"`
	NotAfter      string              `json:"not_after"`
	EvaluatedAt   string              `json:"evaluated_at"`           // RFC3339 of opts.At, echoed so a result is self-describing
	Revocation    []RevocationCheck   `json:"revocation,omitempty"`   // one entry per supplied statement; empty means none was supplied
	Reason        IdentityReason      `json:"reason,omitempty"`       // stable code; empty exactly when Valid
	ReasonClass   IdentityReasonClass `json:"reason_class,omitempty"` // what KIND of outcome Reason is; a consumer branches on this, never on Valid alone
	Detail        string              `json:"detail,omitempty"`       // human sentence naming the offending value
}

// keyOutcome is one pinned key's result inside the signature loop.
type keyOutcome struct {
	fpr    string
	reason IdentityReason
}

// severity orders per-key failures so the reported Reason is deterministic
// rather than a function of which key the caller happened to list first.
// ReasonSignatureInvalid wins because it is the only one classed forged: if any
// pinned issuer's key failed to verify bytes it named, that is the fact worth
// surfacing, even beside three other signatures that were merely unreadable.
func severity(r IdentityReason) int {
	switch r {
	case ReasonSignatureInvalid:
		return 4
	case ReasonSignerKeyMismatch:
		return 3
	case ReasonSignerKeyMalformed:
		return 2
	case ReasonSignatureMalformed:
		return 1
	default:
		return 0
	}
}

// VerifyIdentity checks one attestation against the caller's pinned issuer keys,
// at the caller's evaluation time.
//
// The split between err and Reason is a rule, not a habit: a non-nil error means
// the CALL is unusable — a nil attestation, a pinned key of the wrong size, or a
// zero opts.At — and a Reason means the ARTIFACT does not verify. A consumer
// must never have to tell "bad attestation" from "bad call" by reading a
// message.
//
// Order, and the ordering is the argument (identity spec §5.3):
//
//  0. caller input                 -> error, nil result
//  1. version                      -> ReasonUnsupportedVersion
//  2. algorithm                    -> ReasonUnsupportedAlgorithm
//  3. structural well-formedness   -> the malformed_* reasons
//  4. the issuer named must have signed -> ReasonIssuerDidNotSign
//  5. a trust anchor must exist    -> ReasonNoIssuerPinned
//  6. signatures, against the PINNED keys (this step collects; it does not short-circuit)
//  7. validity-window containment  -> ReasonNotYetValid / ReasonExpired
//  8. revocation, if statements were supplied
//
// Signatures precede the window check on purpose. Until an issuer signature
// verifies, none of the fields mean anything, and reporting "expired" about an
// unsigned blob would state a fact about an issuer's intent that no issuer
// expressed. Steps 1-4 are safe before verification because "malformed" claims
// nothing about intent; "expired" and "revoked" do.
func VerifyIdentity(a *IdentityAttestation, opts IdentityOptions) (*IdentityResult, error) {
	// 0: facts about the call. Nothing about the artifact is read here.
	if a == nil {
		return nil, fmt.Errorf("verify identity: attestation is nil")
	}
	for i, k := range opts.IssuerKeys {
		if len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("verify identity: issuer key %d is %d bytes, want %d", i, len(k), ed25519.PublicKeySize)
		}
	}
	if opts.At.IsZero() {
		return nil, fmt.Errorf("verify identity: evaluation time must be set (opts.At is the zero time)")
	}

	res := &IdentityResult{
		Subject:       a.Subject,
		Principal:     a.Principal,
		PrincipalType: a.PrincipalType,
		Roles:         append([]string(nil), a.Roles...),
		Serial:        a.Serial,
		Issuer:        a.Issuer,
		NotBefore:     a.IssuedAt,
		NotAfter:      a.ExpiresAt,
		EvaluatedAt:   opts.At.UTC().Format(time.RFC3339),
	}

	// 1: version, so nothing else is interpreted under a shape we do not know.
	if a.Version != IdentityVersion {
		return fail(res, ReasonUnsupportedVersion,
			fmt.Sprintf("unsupported identity version %q (this build reads %q)", a.Version, IdentityVersion)), nil
	}
	// 2: algorithm, before any signature work, so we never verify with a scheme
	// the artifact did not declare.
	if a.Algorithm != AlgorithmEd25519 {
		return fail(res, ReasonUnsupportedAlgorithm,
			fmt.Sprintf("unsupported algorithm %q (this build reads %q)", a.Algorithm, AlgorithmEd25519)), nil
	}

	// 3: structural well-formedness. Timestamps are parsed here but not evaluated.
	if a.Serial == "" {
		return fail(res, ReasonMalformedSerial, "serial must not be empty"), nil
	}
	if !isFingerprint(a.Subject) {
		return fail(res, ReasonMalformedSubject,
			fmt.Sprintf("subject %q is not an SSH SHA-256 fingerprint", a.Subject)), nil
	}
	if a.Principal == "" {
		return fail(res, ReasonMalformedPrincipal, "principal must not be empty"), nil
	}
	if a.PrincipalType == "" {
		return fail(res, ReasonMalformedPrincipalType, "principal_type must not be empty"), nil
	}
	if detail := rolesProblem(a.Roles); detail != "" {
		return fail(res, ReasonMalformedRoles, detail), nil
	}
	if !isFingerprint(a.Issuer) {
		return fail(res, ReasonMalformedIssuer,
			fmt.Sprintf("issuer %q is not an SSH SHA-256 fingerprint", a.Issuer)), nil
	}
	notBefore, err := time.Parse(time.RFC3339, a.IssuedAt)
	if err != nil {
		return fail(res, ReasonMalformedTime,
			fmt.Sprintf("issued_at %q does not parse as RFC3339", a.IssuedAt)), nil
	}
	notAfter, err := time.Parse(time.RFC3339, a.ExpiresAt)
	if err != nil {
		return fail(res, ReasonMalformedTime,
			fmt.Sprintf("expires_at %q does not parse as RFC3339", a.ExpiresAt)), nil
	}
	if notAfter.Before(notBefore) {
		return fail(res, ReasonInvertedWindow,
			fmt.Sprintf("expires_at %s precedes issued_at %s", a.ExpiresAt, a.IssuedAt)), nil
	}

	// 4: the artifact must be self-consistent about whose statement it is. This
	// does NOT ask the named issuer to be the pinned one — see step 6 on rotation.
	if _, ok := a.Signatures[a.Issuer]; !ok {
		return fail(res, ReasonIssuerDidNotSign,
			fmt.Sprintf("no signature under the named issuer %s", a.Issuer)), nil
	}

	// 5: a trust anchor must exist. Not an error: a caller with no pin has made a
	// legal call and gets a legible answer. This is what standalone-inert rests on.
	if len(opts.IssuerKeys) == 0 {
		return fail(res, ReasonNoIssuerPinned,
			"no issuer key was supplied, so nothing about this attestation was checked"), nil
	}

	// 6: signatures, against the CALLER's keys — never the artifact's map, so
	// there is no path in which a self-signed artifact verifies and a later
	// branch decides whether to care. This step collects every pinned key's
	// outcome instead of returning on the first failure, because short-circuiting
	// would make the verdict a function of the caller's slice order: an
	// attestation carrying a corrupt signature under a rotated-out key and a good
	// one under the current key would verify or fail depending on which the
	// caller listed first, and rotation is the exact case the plural maps exist for.
	preimage := IdentitySigningBytes(a)
	var outcomes []keyOutcome
	for _, pinned := range opts.IssuerKeys {
		fpr := crypto.Fingerprint(pinned)
		sigB64, named := a.Signatures[fpr]
		if !named {
			continue // a pinned issuer that did not sign this one is normal
		}
		if keyB64, present := a.SignerKeys[fpr]; present {
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
			return fail(res, ReasonNoPinnedIssuerVerified,
				fmt.Sprintf("none of the %d pinned issuer key(s) signed this attestation", len(opts.IssuerKeys))), nil
		}
		worst := outcomes[0]
		for _, o := range outcomes[1:] {
			if severity(o.reason) > severity(worst.reason) {
				worst = o
			}
		}
		return fail(res, worst.reason, describeOutcomes(outcomes)), nil
	}
	// At least one pinned issuer signed this, so the attestation verifies. Any
	// per-key failure is reported and changes no verdict.
	if len(outcomes) > 0 {
		res.Detail = fmt.Sprintf("verified by %d of %d pinned issuer(s); %s",
			len(res.VerifiedBy), len(res.VerifiedBy)+len(outcomes), describeOutcomes(outcomes))
	}

	// 7: window containment — a closed interval on both ends. The question is
	// whether the window CONTAINED opts.At, which is what lets a credential that
	// lapsed last year still verify when a record from before it lapsed is re-read.
	if opts.At.Before(notBefore) {
		return fail(res, ReasonNotYetValid,
			fmt.Sprintf("the window opens at %s, after the evaluation time %s", a.IssuedAt, res.EvaluatedAt)), nil
	}
	if opts.At.After(notAfter) {
		return fail(res, ReasonExpired,
			fmt.Sprintf("the window closed at %s, before the evaluation time %s", a.ExpiresAt, res.EvaluatedAt)), nil
	}

	// 8: revocation, if statements were supplied. The check lives here rather
	// than in the caller so it cannot be forgotten by omitting a call.
	if len(opts.Revocations) > 0 {
		checks, revokedBy, unverifiable := checkRevocations(a, opts)
		res.Revocation = checks
		if unverifiable != "" {
			return fail(res, ReasonRevocationUnverifiable,
				fmt.Sprintf("revocation statement %s did not verify against the pinned issuer key(s)", unverifiable)), nil
		}
		if revokedBy != "" {
			return fail(res, ReasonRevoked,
				fmt.Sprintf("serial %s is listed in revocation statement %s", a.Serial, revokedBy)), nil
		}
	}

	res.Valid = true
	return res, nil
}

// fail stamps an outcome code, its class, and a human sentence onto a result and
// returns it. Reason and ReasonClass are set together and only together, so
// "empty exactly when Valid" holds for both.
func fail(res *IdentityResult, r IdentityReason, detail string) *IdentityResult {
	res.Valid = false
	res.Reason = r
	res.ReasonClass = ClassOf(r)
	res.Detail = detail
	return res
}

// describeOutcomes renders every per-key failure, in fingerprint order, so the
// reported Reason is never the whole story and never hides one. Sorting by
// fingerprint rather than by the caller's slice order means two callers with the
// same pin set in a different order produce identical output.
func describeOutcomes(outcomes []keyOutcome) string {
	parts := make([]string, len(outcomes))
	for i, o := range outcomes {
		parts[i] = o.fpr + ": " + string(o.reason)
	}
	return strings.Join(parts, "; ")
}

// rolesProblem describes what is wrong with a role list, or "" when nothing is.
// The list must not be empty, no element may be empty, and no element may repeat
// exactly. Whitespace padding is deliberately left alone: roles are matched
// byte-for-byte downstream and are inside the signed bytes, so trimming here
// would change what a signature means.
func rolesProblem(roles []string) string {
	if len(roles) == 0 {
		return "roles must not be empty"
	}
	seen := make(map[string]bool, len(roles))
	for i, r := range roles {
		if r == "" {
			return fmt.Sprintf("role %d must not be empty", i)
		}
		if seen[r] {
			return fmt.Sprintf("role %q appears more than once", r)
		}
		seen[r] = true
	}
	return ""
}

// isFingerprint reports whether s is the SSH SHA-256 fingerprint dialect this
// package uses everywhere else: "SHA256:" followed by unpadded standard base64
// of a 32-byte digest. Checked rather than assumed, because a subject that is
// not this shape is an identifier from somewhere else and comparing it loosely
// to an AuthorID would be the kind of near-match that hides a mismatch.
func isFingerprint(s string) bool {
	if !strings.HasPrefix(s, fingerprintPrefix) {
		return false
	}
	body := s[len(fingerprintPrefix):]
	if len(body) != fingerprintBodyLen {
		return false
	}
	raw, err := base64.RawStdEncoding.DecodeString(body)
	return err == nil && len(raw) == sha256.Size
}
