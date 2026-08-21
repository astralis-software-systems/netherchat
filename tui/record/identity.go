package record

import (
	"crypto/ed25519"
	"fmt"
	"sort"

	"github.com/salehkreiner/netherchat/tui/attest"
)

// This file carries identity attestations inside a sealed record, and
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

// IsIdentityEntry reports whether an entry carries an identity attestation.
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
// DisplayName is the name an issuer signed for this principal, and it is empty
// when the issuer signed none. It is carried here so a consumer can render the
// name a person is known by instead of the identifier a directory files them
// under; Principal stays, because it is the identifier, and two people with one
// name are still two people. What a surface does with the pair is that surface's
// decision, not this struct's.
type VerifiedIdentity struct {
	Subject       string   `json:"subject"`
	Principal     string   `json:"principal"`
	DisplayName   string   `json:"display_name,omitempty"`
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
// because that list assumes a parsed artifact while a carrier cannot: an entry
// body is an opaque signed string, so "the bytes in this entry are not an
// identity.json" is a state only a carrier reaches. It classes as malformed,
// which is what it is: the file is broken or from a shape this version does not
// know.
//
// The definition moved to attest when the wire carrier arrived and there were
// two carriers able to reach it. This name stays, and delegates, so every
// existing reader of record.ReasonMalformedArtifact keeps working and there is
// still exactly one place the code is decided.
const ReasonMalformedArtifact = attest.ReasonMalformedArtifact

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
			DisplayName:   ires.DisplayName,
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

// IdentityDisplayForEntry renders D-I's attribution for ONE attestation entry in
// a record, so a renderer with a record in hand does not have to reassemble the
// decision from two structs shaped for two other jobs.
//
// It exists because VerifyWithIdentity deliberately surfaces bindings keyed by
// SUBJECT and outcomes keyed by SEQ — the right shapes for a consumer asking
// "what did the record establish about this key" — while attest.IdentityDisplayFor
// takes a parsed artifact and an attest.IdentityResult. Every renderer that wants
// a name and a mark had to bridge those, and the same bridge written twice is how
// two surfaces start disagreeing about what a mark means. Phase 3b §11.4 names
// this as the requirement a consumer must not get wrong; this is that requirement,
// implemented once.
//
// # WHAT IT DOES WITH res
//
//   - nil, or a plain Verify() result: nothing about identity was checked, and the
//     attribution is the CARRIED state — a claim the record carries, under the name
//     the caller supplied. This is what every renderer that takes no issuer key must
//     show, and it is what `netherchat report` and RenderMinutes show today.
//   - a VerifyWithIdentity result: this entry's IdentityOutcome (matched by Seq)
//     and, when it verified, its VerifiedIdentity (matched by subject+serial) are
//     reassembled into the result D-I's renderer takes. A verified entry then
//     renders as a verified entry, with the issuer-signed name.
//
// # THE JOIN, AND HOW IT DIFFERS FROM A ROSTER ROW
//
// A record entry is FILED by an author about a subject, and the two are routinely
// different people — an approval writer files every approver's credential. So the
// key this attribution is ABOUT is the artifact's own subject, and that is what is
// passed to IdentityDisplayFor.
//
// That is NOT the join a roster row needs. A Roster renders a key that is in front
// of you, and its join is "is this statement about THAT key" — it must pass the
// fingerprint it is rendering, never the artifact's own, or a credential copied
// from a public file would render an executive's name beside a stranger. Such a
// caller wants attest.IdentityDisplayFor directly (sealedrecord re-exports it).
//
// A renderer using THIS function owes its reader the subject: the name it produces
// is a statement about a fingerprint, and a surface that shows the name without the
// fingerprint has silently turned it into a statement about whoever filed it.
//
// asserted is the name to render when nothing verified. Empty means "this reader
// has no name for that key", and the artifact's subject fingerprint is used — the
// only name a key has before an authority gives it one.
//
// ok is false for any entry that does not carry an attestation.
func IdentityDisplayForEntry(res *VerifyResult, e Entry, asserted string) (attest.IdentityDisplay, bool) {
	if !IsIdentityEntry(e) {
		return attest.IdentityDisplay{}, false
	}
	att, err := attest.ParseIdentity([]byte(e.Body))
	if err != nil {
		// The one outcome only a carrier reaches, and the same one
		// VerifyWithIdentity records for these bytes.
		return attest.IdentityDisplayForBytes(asserted, "", []byte(e.Body), nil), true
	}
	if asserted == "" {
		asserted = att.Subject
	}
	return attest.IdentityDisplayFor(asserted, att.Subject, att, identityResultForEntry(res, e, att)), true
}

// identityResultForEntry rebuilds the attest.IdentityResult that produced this
// entry's outcome, or nil when the caller never ran the identity path.
//
// nil is not "it failed": it is "nobody was asked", which is the state a renderer
// that takes no issuer key is always in, and IdentityDisplayFor renders it as the
// carried claim rather than as a verdict about the subject.
func identityResultForEntry(res *VerifyResult, e Entry, att *attest.IdentityAttestation) *attest.IdentityResult {
	if res == nil {
		return nil
	}
	var outcome *IdentityOutcome
	for i := range res.IdentityOutcomes {
		if res.IdentityOutcomes[i].Seq == e.Seq {
			outcome = &res.IdentityOutcomes[i]
			break
		}
	}
	if outcome == nil {
		return nil
	}
	out := &attest.IdentityResult{
		Valid:       outcome.Valid,
		Subject:     att.Subject,
		Serial:      att.Serial,
		Reason:      outcome.Reason,
		ReasonClass: outcome.ReasonClass,
		Detail:      outcome.Detail,
	}
	if !outcome.Valid {
		return out
	}
	// A verified outcome has a binding beside it, and the binding is what carries
	// the fields an issuer SIGNED. They are read from there rather than from the
	// artifact, so a renderer shows the values the verifier actually stood behind.
	for _, b := range res.IdentityBindings[outcome.Subject] {
		if b.Serial != outcome.Serial || b.Issuer != att.Issuer {
			continue
		}
		out.Principal, out.DisplayName, out.PrincipalType = b.Principal, b.DisplayName, b.PrincipalType
		out.Roles = append([]string(nil), b.Roles...)
		out.Issuer, out.Serial = b.Issuer, b.Serial
		out.VerifiedBy = append([]string(nil), b.VerifiedBy...)
		out.NotBefore, out.NotAfter = b.NotBefore, b.NotAfter
		return out
	}
	// Valid with no binding to match cannot happen through VerifyWithIdentity —
	// every valid outcome adds one — but a caller may hand us any VerifyResult,
	// and claiming a verified row on fields nobody surfaced would be the renderer
	// inventing the evidence. Report what the outcome said and nothing more.
	out.Valid = false
	out.Reason, out.ReasonClass = attest.ReasonNoPinnedIssuerVerified, attest.ClassOf(attest.ReasonNoPinnedIssuerVerified)
	out.Detail = "this entry verified but its binding was not surfaced, so nothing here can name what verified"
	return out
}
