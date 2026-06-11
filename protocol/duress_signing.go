package protocol

import "bytes"

// DuressBeaconSigningBytes returns the canonical bytes a duress beacon's signature
// covers (C2): the actor attesting "I entered a duress credential, and the
// configured safe response was taken." A duress beacon is an OUT-OF-BAND signal to
// a trusted monitor — it deliberately never rides the relay the coercer can see —
// so binding it to the actor's identity is what lets a monitor ATTRIBUTE it, not
// merely receive an anonymous ping that anyone could forge.
//
// The preimage is domain-separated and length-prefixed like every other Netherchat
// signature, so a duress-beacon signature can never be confused with a
// message/record/seal/action signature, nor replayed: the nonce makes each beacon
// unique and issued_at bounds its freshness.
//
// Layout (duress-beacon v1):
//
//	field("netherchat/duress-beacon/v1")
//	  || field(actor_fpr) || field(mode) || field(context)
//	  || field(issued_at) || field(nonce)
//
// where field(b) = uint64-big-endian(len(b)) || b. `context` is an OPTIONAL,
// non-sensitive free label (e.g. a site or room name) and MUST NOT carry secrets:
// it crosses the boundary as metadata, like every other inbound/outbound field.
func DuressBeaconSigningBytes(actorFpr, mode, context, issuedAt, nonce string) []byte {
	var buf bytes.Buffer
	writeField(&buf, []byte("netherchat/duress-beacon/v1")) // domain-separation tag
	writeField(&buf, []byte(actorFpr))
	writeField(&buf, []byte(mode))
	writeField(&buf, []byte(context))
	writeField(&buf, []byte(issuedAt))
	writeField(&buf, []byte(nonce))
	return buf.Bytes()
}
