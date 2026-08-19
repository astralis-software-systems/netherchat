// Package sealedrecord is the public, network-free API for Netherchat's
// tamper-evident sealed records: Ed25519-signed, SHA-256 hash-chained,
// append-only artifacts that any program can create and verify offline — with no
// running relay and no network.
//
// It is a thin façade over the implementation packages under tui/ (record,
// report, attest). Those packages live under tui/ deliberately: that subtree is
// the only one Go's internal/ rule permits to import Netherchat's internal crypto
// helpers, which is what keeps "the blind relay cannot read message content" a
// property of the build graph rather than a promise. This façade re-exports their
// public surface at a stable, relay-free import path
// (github.com/salehkreiner/netherchat/sealedrecord) so an external consumer never
// has to reach into any internal package.
//
// The names here mirror the implementation packages one-for-one; a guard test
// (surface_test.go) fails the build if a new exported symbol is added to record,
// report, or attest without being re-exported here, so the façade can never
// silently drift out of sync.
//
// VALIDITY IS NOT POLICY. A VerifyResult.Valid of true means the record is
// cryptographically SOUND — the hash chain links, and every entry, seal, and
// artifact-approval signature verifies. It does NOT mean any policy is satisfied,
// in particular the two-person rule. To treat an agent-produced artifact as
// two-person approved, read VerifyResult.ArtifactApprovers (or the helper
// VerifiedArtifactApprovers): it surfaces, per artifact proposal, the set of
// DISTINCT cryptographically verified approver fingerprints, excluding the entry
// author and the proposer. Apply your own policy over that set — at least N
// distinct fingerprints, each a reviewer you recognize/pinned. A record sealed
// before this feature carries no approval proofs and is surfaced with an empty
// ArtifactApprovers: it is a single attested approver and is NOT offline-provable
// as two-person — verify it byte-for-byte, but do not treat it as a quorum.
//
// See the package example for the full offline lifecycle (create → seal → verify
// → render) written with only this package and the standard library.
package sealedrecord

import (
	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/record"
	"github.com/salehkreiner/netherchat/tui/report"
)

// --- Sealed records (tui/record) -------------------------------------------

// Record building blocks: an Entry is one link in the hash chain, a Chain is the
// append-only sequence, a Sealer collects seal co-signatures, and SealedRecord is
// the finished, self-verifying artifact. VerifyResult is the verdict.
type (
	Entry            = record.Entry
	Author           = record.Author
	Chain            = record.Chain
	EntrySpec        = record.EntrySpec
	Link             = record.Link
	Sealer           = record.Sealer
	SealedRecord     = record.SealedRecord
	Endorsement      = record.Endorsement
	ApprovalProof    = record.ApprovalProof
	VerifyResult     = record.VerifyResult
	ArtifactMeta     = record.ArtifactMeta
	VerifiedApprover = record.VerifiedApprover
	VerifiedIdentity = record.VerifiedIdentity
	IdentityOutcome  = record.IdentityOutcome
)

// On-disk schema versions and the built-in entry kinds. KindTyped marks a
// consumer-defined typed entry whose real type is the opaque Entry.Schema tag.
const (
	FormatVersion   = record.FormatVersion
	FormatVersionV2 = record.FormatVersionV2
	KindDecision    = record.KindDecision
	KindAction      = record.KindAction
	KindNote        = record.KindNote
	KindArtifact    = record.KindArtifact
	KindTyped       = record.KindTyped
)

// Built-in electronic-signature meanings (item 2). The set is extensible — a
// consumer may declare additional meanings — but these four ship as defaults.
const (
	MeaningAuthored = record.MeaningAuthored
	MeaningReviewed = record.MeaningReviewed
	MeaningApproved = record.MeaningApproved
	MeaningRejected = record.MeaningRejected
)

// Record constructors, verification, the public fingerprint helper, and the
// artifact-body codecs.
var (
	NewChain                      = record.NewChain
	NewSealer                     = record.NewSealer
	NewSealedRecord               = record.NewSealedRecord
	Parse                         = record.Parse
	Verify                        = record.Verify
	VerifyBytes                   = record.VerifyBytes
	VerifyEntry                   = record.VerifyEntry
	VerifiedArtifactApprovers     = record.VerifiedArtifactApprovers
	VerifiedArtifactApproverRoles = record.VerifiedArtifactApproverRoles
	Fingerprint                   = record.Fingerprint
	ArtifactOf                    = record.ArtifactOf
	MarshalArtifactBody           = record.MarshalArtifactBody
	ParseArtifactBody             = record.ParseArtifactBody
	RenderMinutes                 = record.RenderMinutes
	VerifyWithIdentity            = record.VerifyWithIdentity
	VerifyBytesWithIdentity       = record.VerifyBytesWithIdentity
	IsIdentityEntry               = record.IsIdentityEntry
	IdentityEntrySpec             = record.IdentityEntrySpec
	VerifiedIdentitiesOf          = record.VerifiedIdentitiesOf
)

// ReasonMalformedArtifact is the identity outcome for an attestation entry whose
// body does not parse as an identity artifact at all — the one outcome only the
// record carrier can reach, since an entry body is an opaque signed string.
const ReasonMalformedArtifact = record.ReasonMalformedArtifact

// --- Reports (tui/report) --------------------------------------------------

// Options controls report rendering (title and executive mode).
type Options = report.Options

// Report renderers: a standalone HTML timeline, GitHub-flavored Markdown, and the
// inline-SVG QR helper they embed.
var (
	RenderHTML     = report.RenderHTML
	RenderMarkdown = report.RenderMarkdown
	QRSVG          = report.QRSVG
)

// --- Roster & receipt attestations (tui/attest) ----------------------------

// Roster and scuttle-receipt artifacts, which share the sealed record's
// offline-verifiable, Ed25519 co-signed design.
type (
	RosterAttestation = attest.RosterAttestation
	RosterMember      = attest.RosterMember
	RosterResult      = attest.RosterResult
	EpochRange        = attest.EpochRange
	ReceiptCore       = attest.ReceiptCore
	ScuttleReceipt    = attest.ScuttleReceipt
	ReceiptResult     = attest.ReceiptResult
)

// On-disk schema versions for the roster and receipt artifacts.
const (
	RosterVersion  = attest.RosterVersion
	ReceiptVersion = attest.ReceiptVersion
)

// Roster and receipt constructors and verifiers, plus the membership-set hash.
var (
	SetHash       = attest.SetHash
	NewRoster     = attest.NewRoster
	ParseRoster   = attest.ParseRoster
	VerifyRoster  = attest.VerifyRoster
	NewReceipt    = attest.NewReceipt
	ParseReceipt  = attest.ParseReceipt
	VerifyReceipt = attest.VerifyReceipt
)

// --- Identity attestations (tui/attest) ------------------------------------

// Issuer-signed, offline-verifiable bindings of a key fingerprint to a principal
// and roles, plus the revocation statement they are checked against. Netherchat
// holds no trust anchors: issuer keys and the evaluation time are parameters on
// every call, and with none supplied the answer says so rather than judging the
// subject.
type (
	IdentityAttestation = attest.IdentityAttestation
	IdentitySpec        = attest.IdentitySpec
	IdentityOptions     = attest.IdentityOptions
	IdentityResult      = attest.IdentityResult
	IdentityReason      = attest.IdentityReason
	IdentityReasonClass = attest.IdentityReasonClass
	RevocationStatement = attest.RevocationStatement
	RevocationSpec      = attest.RevocationSpec
	RevokedSerial       = attest.RevokedSerial
	RevocationResult    = attest.RevocationResult
	RevocationCheck     = attest.RevocationCheck
)

// The on-disk schema versions, the typed-entry schema tag, and the algorithm the
// v1 verifier accepts.
const (
	IdentityVersion   = attest.IdentityVersion
	RevocationVersion = attest.RevocationVersion
	IdentitySchema    = attest.IdentitySchema
	AlgorithmEd25519  = attest.AlgorithmEd25519
)

// The outcome classes. A consumer branches on these, never on Valid alone:
// ClassUnconfigured and ClassUnanchored are facts about the VERIFIER's setup and
// must never render as a credential failure, because neither says anything about
// the subject.
const (
	ClassUnconfigured = attest.ClassUnconfigured
	ClassUnanchored   = attest.ClassUnanchored
	ClassLifecycle    = attest.ClassLifecycle
	ClassMalformed    = attest.ClassMalformed
	ClassForged       = attest.ClassForged
)

// Every outcome code the identity verifier can report. They are listed rather
// than hidden behind an accessor because this façade mirrors the implementation
// packages one-for-one, and because a consumer switching on an outcome wants the
// compiler to tell it when a case disappears.
const (
	ReasonNoIssuerPinned         = attest.ReasonNoIssuerPinned
	ReasonNoPinnedIssuerVerified = attest.ReasonNoPinnedIssuerVerified
	ReasonNotYetValid            = attest.ReasonNotYetValid
	ReasonExpired                = attest.ReasonExpired
	ReasonRevoked                = attest.ReasonRevoked
	ReasonUnsupportedVersion     = attest.ReasonUnsupportedVersion
	ReasonUnsupportedAlgorithm   = attest.ReasonUnsupportedAlgorithm
	ReasonMalformedSerial        = attest.ReasonMalformedSerial
	ReasonMalformedSubject       = attest.ReasonMalformedSubject
	ReasonMalformedPrincipal     = attest.ReasonMalformedPrincipal
	ReasonMalformedPrincipalType = attest.ReasonMalformedPrincipalType
	ReasonMalformedRoles         = attest.ReasonMalformedRoles
	ReasonMalformedIssuer        = attest.ReasonMalformedIssuer
	ReasonMalformedTime          = attest.ReasonMalformedTime
	ReasonInvertedWindow         = attest.ReasonInvertedWindow
	ReasonIssuerDidNotSign       = attest.ReasonIssuerDidNotSign
	ReasonSignerKeyMalformed     = attest.ReasonSignerKeyMalformed
	ReasonSignerKeyMismatch      = attest.ReasonSignerKeyMismatch
	ReasonSignatureMalformed     = attest.ReasonSignatureMalformed
	ReasonSignatureInvalid       = attest.ReasonSignatureInvalid
	ReasonRevocationUnverifiable = attest.ReasonRevocationUnverifiable
)

// Identity constructors, parsers, verifiers, the outcome classifier, and the
// issuer-side signing bytes. The two SigningBytes helpers exist so an external
// issuer tool — an enterprise CA integration outside this module — can derive
// the exact preimage through this façade instead of importing protocol.
var (
	NewIdentityAttestation = attest.NewIdentityAttestation
	ParseIdentity          = attest.ParseIdentity
	VerifyIdentity         = attest.VerifyIdentity
	ClassOf                = attest.ClassOf
	IdentitySigningBytes   = attest.IdentitySigningBytes
	NewRevocation          = attest.NewRevocation
	ParseRevocation        = attest.ParseRevocation
	VerifyRevocation       = attest.VerifyRevocation
	RevocationSigningBytes = attest.RevocationSigningBytes
)
