package attest

import "fmt"

// D-I, in one place: which name a surface puts where a person's name goes, and
// what mark stands beside it.
//
// The decision was taken once (roadmap v8 §2) precisely because taking it per
// surface is how the ✓ collision happened — the same glyph meaning two things
// two panes apart. There are four states on this axis and each says a different
// thing about the string being rendered:
//
//	verified_named    an issuer THIS READER PINNED signed a display name, and the
//	                  window it signed contained the time this reader supplied
//	verified_unnamed  the same, and the issuer named no display name. The
//	                  principal is what renders. This is the third VERIFIED path
//	verified_named    and verified_unnamed are peers, not a state and a fallback
//	carried           a credential arrived and nothing checked it. The name a
//	                  sender chose renders, and the claim is visible on detail
//	asserted          no credential arrived. The name a sender chose renders
//
// WHY verified_unnamed IS NOT A DEGRADED verified_named. DisplayName is optional
// (§1.1) and signs as eight zero bytes when absent (§2.1), so "the issuer named
// no name" is a statement the issuer made, not a gap. Rendering the principal
// there and rendering the sender's handle in the carried state are two different
// answers to two different questions; collapsing them would put an unchecked
// string and an authority's identifier under the same appearance.
//
// WHAT THIS FUNCTION DOES NOT DO. It does not verify. It is handed a result and
// renders it, so that no surface can accidentally treat "arrived" as "checked" —
// the caller has to have obtained an IdentityResult from somewhere, and
// obtaining one takes an issuer key and an evaluation time that this package
// never holds and never reads.

// IdentityDisplayState is which of D-I's rows a rendered name is under. A
// consumer branches on this rather than on the presence of a credential: the
// two are not the same question, and treating them as one is the failure mode
// this type exists to make impossible to write.
type IdentityDisplayState string

const (
	// IdentityDisplayVerifiedNamed: a pinned issuer signed a display name.
	IdentityDisplayVerifiedNamed IdentityDisplayState = "verified_named"
	// IdentityDisplayVerifiedUnnamed: a pinned issuer signed the binding and
	// named no display name. The principal renders. A verified state.
	IdentityDisplayVerifiedUnnamed IdentityDisplayState = "verified_unnamed"
	// IdentityDisplayCarried: a credential accompanied the key and this surface
	// did not check it — because nothing was pinned, because the pinned issuer
	// did not sign it, because the window had closed, or because the bytes did
	// not parse. All four render the same way, and which one it was is in Reason.
	IdentityDisplayCarried IdentityDisplayState = "carried"
	// IdentityDisplayAsserted: no credential. The oldest state and still the
	// common one.
	IdentityDisplayAsserted IdentityDisplayState = "asserted"
)

// IdentityDisplayMark is the glyph for a state, unstyled. It is here rather than
// in a UI package because the browser client and the terminal client must draw
// the same one, and a vocabulary that lives in two places is a vocabulary that
// drifts.
//
// The glyphs are deliberately NOT checkmarks. A ✓ in this product means "this
// client checked something itself" — a fingerprint pin, a spoken SAS — and an
// issuer attestation is somebody else's statement. So it gets its own shape,
// and the shape is filled when it has been checked and hollow when it has not:
//
//	◆  verified against an issuer key the reader pinned
//	◇  a credential arrived; nobody checked it
//	   (nothing) no credential
func IdentityDisplayMark(s IdentityDisplayState) string {
	switch s {
	case IdentityDisplayVerifiedNamed, IdentityDisplayVerifiedUnnamed:
		return "◆"
	case IdentityDisplayCarried:
		return "◇"
	default:
		return ""
	}
}

// IdentityDisplay is one rendered attribution: the name to draw, the state that
// name is in, and the facts a detail surface can show beside it.
//
// Principal, DisplayName and Issuer are populated from the artifact whenever one
// was parsed, verified or not — a detail line that says "this key arrived with a
// credential naming rosa.alvarez@acme.example, issued by SHA256:…, unchecked
// here" is more useful than silence, and it is not a claim about Rosa. Reason
// and ReasonClass carry WHY nothing verified, and ClassOf's rendering rule
// applies to them: unconfigured and unanchored are facts about the reader, and
// a surface must not dress either as a finding about the subject.
type IdentityDisplay struct {
	State IdentityDisplayState
	// Name is what to draw where a person's name goes. Never empty when the
	// asserted name was not empty.
	Name string

	Principal   string // from the artifact, when one was parsed
	DisplayName string // from the artifact, when one was parsed; empty is a legal signed value
	Issuer      string // the issuer fingerprint the artifact names
	Roles       []string

	Reason      IdentityReason      // why nothing verified; empty when it did
	ReasonClass IdentityReasonClass // what kind of outcome Reason is
	Detail      string              // a human sentence for a detail line
}

// IdentityDisplayFor renders one attribution.
//
// asserted is the name the sender chose — the only name that has ever been on
// this wire before. subjectFpr is the fingerprint of the key being rendered, and
// it is what turns a signed statement into a statement about THIS participant.
// carried is the artifact that accompanied that key, or nil. res is the outcome
// of verifying the artifact, or nil when no verification was attempted, which is
// the state every live Netherchat surface is in.
//
// # WHY subjectFpr IS A PARAMETER AND NOT AN OPTION
//
// An attestation is not a secret (§2.3), so possession of one proves nothing:
// anyone who has seen Rosa's identity.json can attach it to their own key, and
// VerifyIdentity will happily confirm that Rosa's issuer signed a statement about
// Rosa. Only the caller knows whose key the statement arrived on. Making the
// fingerprint a positional argument means a caller cannot reach a verified row
// without having made that join — an empty subjectFpr is not "skip the check", it
// is "I did not make the join", and it produces the carried state with
// ReasonSubjectMismatch. The strongest state in this vocabulary must not be
// reachable by copying a public file.
func IdentityDisplayFor(asserted, subjectFpr string, carried *IdentityAttestation, res *IdentityResult) IdentityDisplay {
	out := IdentityDisplay{State: IdentityDisplayAsserted, Name: asserted}
	if carried == nil && res == nil {
		return out
	}
	if carried != nil {
		out.Principal, out.DisplayName, out.Issuer = carried.Principal, carried.DisplayName, carried.Issuer
		out.Roles = append([]string(nil), carried.Roles...)
	}
	out.State = IdentityDisplayCarried

	// The join, before anything else is considered. A statement about another key
	// is not a weaker statement about this one; it is not about this one at all.
	if carried != nil && (subjectFpr == "" || carried.Subject != subjectFpr) {
		out.Reason, out.ReasonClass = ReasonSubjectMismatch, ClassOf(ReasonSubjectMismatch)
		where := subjectFpr
		if where == "" {
			where = "(the caller named no key)"
		}
		out.Detail = fmt.Sprintf("this credential is about %s and arrived on %s", carried.Subject, where)
		return out
	}

	if res == nil {
		out.Detail = "a credential accompanied this key and nothing here checked it"
		return out
	}
	if res.Principal != "" {
		out.Principal = res.Principal
	}
	if res.Issuer != "" {
		out.Issuer = res.Issuer
	}
	if len(res.Roles) > 0 {
		out.Roles = append([]string(nil), res.Roles...)
	}
	if !res.Valid {
		out.Reason, out.ReasonClass, out.Detail = res.Reason, res.ReasonClass, res.Detail
		if out.Detail == "" {
			out.Detail = string(res.Reason)
		}
		return out
	}

	out.DisplayName = res.DisplayName
	if res.DisplayName != "" {
		out.State, out.Name = IdentityDisplayVerifiedNamed, res.DisplayName
		return out
	}
	// The third verified path. The issuer named no display name, so the
	// identifier it DID sign is the name — and it stays in the verified state,
	// because what is missing is a field the issuer chose to omit, not a check.
	out.State, out.Name = IdentityDisplayVerifiedUnnamed, res.Principal
	return out
}

// IdentityDisplayForBytes is IdentityDisplayFor for a surface holding the raw
// carrier bytes: it parses, and bytes that do not parse land in the carried
// state rather than the asserted one. Something arrived; a surface that showed
// the asserted state would be saying nothing did.
func IdentityDisplayForBytes(asserted, subjectFpr string, carried []byte, res *IdentityResult) IdentityDisplay {
	if len(carried) == 0 {
		return IdentityDisplayFor(asserted, subjectFpr, nil, res)
	}
	a, err := ParseIdentity(carried)
	if err != nil {
		return IdentityDisplay{
			State:       IdentityDisplayCarried,
			Name:        asserted,
			Reason:      ReasonMalformedArtifact,
			ReasonClass: ClassOf(ReasonMalformedArtifact),
			Detail:      fmt.Sprintf("this key arrived with %d byte(s) that are not an identity artifact", len(carried)),
		}
	}
	return IdentityDisplayFor(asserted, subjectFpr, a, res)
}
