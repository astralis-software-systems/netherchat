package record

import (
	"crypto/ed25519"
	"fmt"
	"sort"

	"github.com/salehkreiner/netherchat/tui/attest"
)

// This file carries identity/v1 attestations inside a sealed record, and
// surfaces what verified.
//
// An attestation travels as ONE ORDINARY TYPED ENTRY per attestation: Kind
// KindTyped, Schema attest.IdentitySchema, Body the standalone artifact's JSON.
// No new kind, no new record-level field, no FormatVersionV3 — a record carrying
// attestations is labelled v2 for the same reason any record with a typed entry
// already is, and it parses on an older build because the entry fields it uses
// have existed since v2.
//
// TWO SIGNATURES, AND CONFLATING THEM IS THE EASIEST MISTAKE HERE. The entry's
// author signature says "this attestation was placed in this chain, at this
// position, at this time, by this key" and is checked against AuthorKey. The
// issuer signature inside the body says "this key belongs to this principal, in
// these roles, between these times" and is checked against a key the VERIFIER
// pinned. The entry author need not be the issuer and usually is not: anyone may
// carry an attestation — the subject, an approver attaching their own credential
// to a decision, an administrator batching credentials into a record. That is
// safe because the artifact grants nothing and its trust comes entirely from an
// issuer signature checked against a pinned key. Placing a stranger's
// attestation into your record proves only that you placed it there.
//
// So: author identity is not part of the binding's trust chain. What the author
// signature DOES buy is that the attestation's presence is tamper-evident —
// removing or altering the entry breaks the chain, and thus the head, and thus
// every seal co-signature over it.
//
// TIMING IS NOT A CHOICE. An attestation entry must be in the chain when the
// record is sealed. The amend path admits a co-signature over an unchanged head
// and nothing else, so appending an entry afterwards is structurally impossible:
// it would move the head, and every co-signature already collected is over the
// old one. "Re-seal this decision with the approver's credentials attached" is
// therefore not an operation; it is a second record about the same decision,
// with a different id. The model is provisioning-first — an operator is given a
// credential before they act, exactly as they are given a key before they sign.

// AppendIdentity appends an identity attestation to the chain as a typed entry
// and returns it, signed by a, ready to broadcast.
//
// The Body is exactly what (*attest.IdentityAttestation).Marshal() produces, so
// it is byte-identical to the standalone identity.json an operator was handed
// and the two can be compared with a hash. Verification must not depend on that:
// the verifier parses the body and works from the parsed struct, and every
// canonical-bytes claim rests on the length-prefixed issuer preimage, never on
// JSON layout. Byte-identity is an operator convenience, not a protocol property.
//
// Position in the chain is a readability choice and nothing depends on it — any
// position verifies identically — so a consumer that pins entry 0 to something
// else should append attestations after the entry they are evidence about.
func (c *Chain) AppendIdentity(a Author, att *attest.IdentityAttestation) (Entry, error) {
	spec, err := IdentityEntrySpec(att)
	if err != nil {
		return Entry{}, err
	}
	return c.Append(a, spec)
}

// IdentityEntrySpec renders an attestation as the entry that carries it. It is
// the single place that decides what an identity entry looks like — the kind,
// the schema tag, and the body bytes — so a live client broadcasting one and an
// offline program building a chain produce the same entry rather than two
// dialects of it.
func IdentityEntrySpec(att *attest.IdentityAttestation) (EntrySpec, error) {
	if att == nil {
		return EntrySpec{}, fmt.Errorf("identity entry: attestation is nil")
	}
	body, err := att.Marshal()
	if err != nil {
		return EntrySpec{}, fmt.Errorf("identity entry: %w", err)
	}
	return EntrySpec{Kind: KindTyped, Schema: attest.IdentitySchema, Body: string(body)}, nil
}

// IsIdentityEntry reports whether an entry carries an identity/v1 attestation.
// It is the one place the schema tag is compared, so a consumer walking a chain
// does not have to hold the string.
func IsIdentityEntry(e Entry) bool {
	return e.Kind == KindTyped && e.Schema == attest.IdentitySchema
}

// VerifiedIdentity is one issuer-signed binding that verified.
//
// THE CONTRACT, in the words it has to carry. IdentityBindings is absent on
// every record produced before this feature existed, absent on every record
// whose verifier pinned no issuer, and absent whenever no attestation in the
// record verified. Its presence means: the named issuer key, WHICH YOU SUPPLIED,
// signed a statement binding this fingerprint to this principal, and that
// statement's window contained the time YOU supplied. It does not mean the
// principal is entitled to anything.
//
// That sentence is the identity-layer twin of the "IMPORTANT (GAP-5)" paragraph
// on VerifyResult and of the façade's "VALIDITY IS NOT POLICY", and it is here
// for the same reason both of those are: the distance between "this verified"
// and "this is enough" is where every one of these systems goes wrong.
//
// Issuer and VerifiedBy need not match, and the library does not require them
// to. Issuer is the authority the artifact names; VerifiedBy is which of the
// caller's pinned keys actually verified a signature. Requiring them to be the
// same would break issuer key rotation, which is what the plural signature maps
// exist for. A consumer that cares compares them itself.
type VerifiedIdentity struct {
	Subject       string   `json:"subject"`
	Principal     string   `json:"principal"`
	PrincipalType string   `json:"principal_type"`
	Roles         []string `json:"roles"`
	Issuer        string   `json:"issuer"`
	VerifiedBy    []string `json:"verified_by"`
	Serial        string   `json:"serial"`
	NotBefore     string   `json:"not_before"`
	NotAfter      string   `json:"not_after"`
}

// IdentityOutcome is what happened to one attestation entry, verified or not.
//
// ReasonClass is carried so a consumer never branches on Valid alone: an
// unconfigured verifier and a forged signature both yield Valid=false, and only
// the class tells them apart. A screen that renders those two the same way is
// making a claim about a person that the software did not check.
type IdentityOutcome struct {
	Seq         uint64                     `json:"seq"` // the entry that carried it
	Subject     string                     `json:"subject,omitempty"`
	Serial      string                     `json:"serial,omitempty"`
	Valid       bool                       `json:"valid"`
	Reason      attest.IdentityReason      `json:"reason,omitempty"`
	ReasonClass attest.IdentityReasonClass `json:"reason_class,omitempty"`
	Detail      string                     `json:"detail,omitempty"`
}

// ReasonMalformedArtifact is the outcome for an attestation entry whose body
// does not parse as an identity artifact at all.
//
// It is an addition to the outcome codes the format specification enumerates,
// and it is here because that list assumes a parsed artifact while this walk
// cannot: an entry body is an opaque signed string, so "the bytes in this entry
// are not an identity.json" is a state only the carrier can reach. It classes as
// malformed, which is what it is: the file is broken or from a shape this
// version does not know.
const ReasonMalformedArtifact attest.IdentityReason = "malformed_artifact"

// VerifyWithIdentity verifies a sealed record and, when the caller has pinned an
// issuer, additionally surfaces the identity bindings its attestation entries
// carry. It is an additive sibling of Verify rather than a change to it, because
// Verify takes no parameters by design — everything the artifact approvals need
// is inside the record, and identity bindings need a trust anchor and a time
// from outside it.
//
// Behaviour, precisely:
//
//  1. Verify(r) unchanged. On error, or Valid==false, the result is returned
//     untouched: bindings are not surfaced for a record that is not
//     cryptographically sound.
//  2. With no issuer key supplied, the result is returned untouched — no third
//     map, byte-identical to Verify. This check PRECEDES the opts.At check, and
//     that ordering is load-bearing: it is what keeps a caller with no pin and an
//     unset time on the byte-identical path, which is the standalone-inert
//     guarantee.
//  3. Otherwise the options the identity path needs are validated. A zero
//     opts.At is an error here, not a record whose bindings silently failed: a
//     caller that pinned an issuer has asked for the identity path and must
//     supply the time that path is defined in terms of.
//  4. Every netherchat.identity/v1 entry is parsed and verified; each yields an
//     IdentityOutcome, and the ones that verified are added to IdentityBindings,
//     deduplicated by the (subject, issuer, serial) triple.
//  5. res.Valid is NEVER modified.
//
// Step 5 is a deliberate asymmetry with the approvals block, and it is the load-
// bearing one. A bad approval proof makes a record invalid because it is a
// self-contained inconsistency: the record contradicts itself, and every
// verifier on earth reaches that verdict with no external input. A failing
// attestation is not that. It may fail only because YOU pinned a different
// issuer, or evaluated at a different time. Letting it flip Valid would make
// record validity depend on the verifier's configuration, and "VALID" would mean
// different things on different machines.
//
// The same attestation may legitimately appear twice — two entries, or one entry
// plus a copy. Two DIFFERENT serials for one subject, an old and a renewed
// credential or two issuers' views, are both surfaced. The library does not
// adjudicate between them; which one wins is consumer policy.
func VerifyWithIdentity(r *SealedRecord, opts attest.IdentityOptions) (*VerifyResult, error) {
	res, err := Verify(r)
	if err != nil || res == nil || !res.Valid {
		return res, err
	}
	if len(opts.IssuerKeys) == 0 {
		return res, nil
	}
	for i, k := range opts.IssuerKeys {
		if len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("verify with identity: issuer key %d is %d bytes, want %d", i, len(k), ed25519.PublicKeySize)
		}
	}
	if opts.At.IsZero() {
		return nil, fmt.Errorf("verify with identity: evaluation time must be set (opts.At is the zero time)")
	}

	type bindingKey struct{ subject, issuer, serial string }
	seen := map[bindingKey]bool{}
	bindings := map[string][]VerifiedIdentity{}
	var outcomes []IdentityOutcome

	for _, e := range r.Entries {
		if !IsIdentityEntry(e) {
			continue
		}
		att, perr := attest.ParseIdentity([]byte(e.Body))
		if perr != nil {
			outcomes = append(outcomes, IdentityOutcome{
				Seq:         e.Seq,
				Valid:       false,
				Reason:      ReasonMalformedArtifact,
				ReasonClass: attest.ClassOf(ReasonMalformedArtifact),
				Detail:      perr.Error(),
			})
			continue
		}
		ires, ierr := attest.VerifyIdentity(att, opts)
		if ierr != nil {
			// An error from the verifier is a fact about the CALL, not about this
			// entry, so it propagates rather than being recorded as an outcome.
			return nil, fmt.Errorf("verify with identity: entry %d: %w", e.Seq, ierr)
		}
		outcomes = append(outcomes, IdentityOutcome{
			Seq:         e.Seq,
			Subject:     ires.Subject,
			Serial:      ires.Serial,
			Valid:       ires.Valid,
			Reason:      ires.Reason,
			ReasonClass: ires.ReasonClass,
			Detail:      ires.Detail,
		})
		if !ires.Valid {
			continue
		}
		k := bindingKey{ires.Subject, ires.Issuer, ires.Serial}
		if seen[k] {
			continue
		}
		seen[k] = true
		bindings[ires.Subject] = append(bindings[ires.Subject], VerifiedIdentity{
			Subject:       ires.Subject,
			Principal:     ires.Principal,
			PrincipalType: ires.PrincipalType,
			Roles:         append([]string(nil), ires.Roles...),
			Issuer:        ires.Issuer,
			VerifiedBy:    append([]string(nil), ires.VerifiedBy...),
			Serial:        ires.Serial,
			NotBefore:     ires.NotBefore,
			NotAfter:      ires.NotAfter,
		})
	}

	for subject := range bindings {
		vs := bindings[subject]
		sort.Slice(vs, func(i, j int) bool {
			if vs[i].Issuer != vs[j].Issuer {
				return vs[i].Issuer < vs[j].Issuer
			}
			return vs[i].Serial < vs[j].Serial
		})
	}
	if len(bindings) > 0 {
		res.IdentityBindings = bindings
	}
	if len(outcomes) > 0 {
		res.IdentityOutcomes = outcomes
	}
	return res, nil
}

// VerifyBytesWithIdentity parses a sealed record from its on-disk JSON and
// verifies it with identity surfacing in a single call — the network-free entry
// point an external consumer uses. It is VerifyBytes plus the third map, and it
// inherits every rule above, including that a failing attestation never makes
// the record invalid.
func VerifyBytesWithIdentity(b []byte, opts attest.IdentityOptions) (*VerifyResult, error) {
	rec, err := Parse(b)
	if err != nil {
		return nil, err
	}
	return VerifyWithIdentity(rec, opts)
}

// VerifiedIdentitiesOf returns the verified bindings for one subject
// fingerprint, or nil if there are none. It is a nil-safe accessor over
// VerifyResult.IdentityBindings, the identity-layer counterpart of
// VerifiedArtifactApprovers, and it reports what an issuer signed and nothing
// past that.
func VerifiedIdentitiesOf(res *VerifyResult, subject string) []VerifiedIdentity {
	if res == nil {
		return nil
	}
	return res.IdentityBindings[subject]
}
