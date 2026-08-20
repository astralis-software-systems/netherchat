package protocol

import (
	"bytes"
	"encoding/binary"
)

// IdentitySigningBytes returns the canonical, unambiguous byte sequence an
// identity attestation's issuer signature covers (identity/v2): an authority
// stating "this key fingerprint belongs to this principal, who is known by this
// name, in these roles, between these times." As with every other layout in this
// package, the bytes are fixed here so the issuer and every verifier — including
// an offline `netherchat verify` that was never in the room, and a reader opening
// a sealed record years later — derive them identically.
//
// Layout (identity v2):
//
//	field("netherchat/identity/v2")
//	  || field(serial) || field(subject)
//	  || field(principal) || field(displayName) || field(principalType)
//	  || nroles_be64 || { field(role[i]) } for each role, in the order the artifact lists them
//	  || field(issuedAt) || field(expiresAt)
//	  || field(algorithm) || field(issuer)
//
// where field(b) = uint64-big-endian(len(b)) || b, and nroles_be64 is the role
// count as 8 bytes big-endian (NOT length-prefixed), exactly as the link count is
// in RecordSigningBytesV2. Every variable field is length-prefixed, so the
// encoding is injective; the count is signed too, so a role can be neither added
// nor dropped without breaking the signature.
//
// displayName is the name a directory would show for this principal, and it sits
// beside principal because that is what it is: the human-facing half of the same
// identifier. An issuer may leave it out. It does not thereby leave the
// signature — the field is written unconditionally, so the layout has a fixed
// shape and the NUMBER of fields never depends on the data. An absent display
// name and an empty one are ONE state, and it signs as field(""), eight zero
// bytes, exactly as field(nextUpdate) does for an omitted next_update in
// RevocationSigningBytes below. Making them one state is what keeps them from
// being confusable: there is a single encoding for "this issuer named no display
// name", so no artifact can be re-spelled into a different preimage.
//
// displayName is signed as the bytes the issuer wrote and is never trimmed,
// case-folded, or normalized here — the same rule roles follow, for the same
// reason. Normalizing would silently change what a signature means, and a
// consumer matching or displaying the value would be looking at something no
// authority ever signed.
//
// Role ORDER is signed and never normalized here. The constructor sorts once
// (attest.NewIdentityAttestation, as NewRoster sorts members); verification emits
// the roles in the order the parsed artifact lists them. A reordered artifact
// therefore fails the signature check rather than quietly verifying, which keeps
// "the bytes mean one thing" true.
//
// Timestamps are signed as the STRINGS the artifact carries, not as epoch
// integers, so the signature commits to exactly what the file says — the same
// choice SealSigningBytesV2 makes for signedAt.
//
// The version is not a field: it lives in the domain-separation tag, which is the
// convention every layout here follows, and a verifier rejects an unrecognized
// version before it ever builds a preimage. The tag reads v2 because this layout
// changed: v1 had no display name, so an artifact signed under it derives
// different bytes here and its signature will not verify. That is a breaking
// change, and the tag moving is how a v1 artifact is told apart from a forged v2
// one — the verifier stops at the version and says so, instead of reaching a
// signature check it was always going to fail.
//
// The layout binds no room and no record. An identity binding is the same
// statement in every room, so scoping it to one would mean re-issuing per room;
// the anti-replay property lives in the subject binding instead. An attestation
// is portable by design: anyone may carry a copy anywhere, and it grants nothing,
// because only the holder of the subject key can act as the subject.
//
// The algorithm is inside the preimage so that a later multi-algorithm verifier
// cannot be steered onto a different verification path by relabelling the file,
// and the issuer is inside it so an attestation cannot be re-attributed to
// another authority while keeping a signature that still verifies.
func IdentitySigningBytes(serial, subject, principal, displayName, principalType string, roles []string,
	issuedAt, expiresAt, algorithm, issuer string) []byte {
	var buf bytes.Buffer
	writeField(&buf, []byte("netherchat/identity/v2")) // domain-separation tag
	writeField(&buf, []byte(serial))
	writeField(&buf, []byte(subject))
	writeField(&buf, []byte(principal))
	writeField(&buf, []byte(displayName))
	writeField(&buf, []byte(principalType))
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(roles)))
	buf.Write(n[:])
	for _, r := range roles {
		writeField(&buf, []byte(r))
	}
	writeField(&buf, []byte(issuedAt))
	writeField(&buf, []byte(expiresAt))
	writeField(&buf, []byte(algorithm))
	writeField(&buf, []byte(issuer))
	return buf.Bytes()
}

// RevocationSigningBytes returns the canonical bytes an issuer's signature over a
// revocation statement covers (identity-revocation/v1): an authority naming the
// serials it has withdrawn, as of a stated time.
//
// Layout (identity-revocation v1):
//
//	field("netherchat/identity-revocation/v1")
//	  || field(issuer) || field(statementID) || number_be64
//	  || field(issuedAt) || field(nextUpdate)
//	  || n_be64 || { field(serial[i]) || field(revokedAt[i]) || field(reason[i]) } for each entry, in listed order
//
// where field(b) = uint64-big-endian(len(b)) || b and the *_be64 values are 8
// bytes big-endian (NOT length-prefixed). serials, revokedAt and reasons are
// parallel slices of equal length, one element per revoked entry, in the order
// the statement lists them.
//
// The list is inline and length-prefixed rather than hashed into a digest first.
// The receipt layout hashes a core struct's JSON, which works but makes
// encoding/json part of the canonical form; the roster layout hashes a sorted
// join, which is not injective for values that may contain the separator. Inline
// fields avoid both, and Ed25519 hashes internally anyway, so the cost is the
// same.
func RevocationSigningBytes(issuer, statementID string, number uint64, issuedAt, nextUpdate string,
	serials, revokedAt, reasons []string) []byte {
	var buf bytes.Buffer
	writeField(&buf, []byte("netherchat/identity-revocation/v1")) // domain-separation tag
	writeField(&buf, []byte(issuer))
	writeField(&buf, []byte(statementID))
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], number)
	buf.Write(n[:])
	writeField(&buf, []byte(issuedAt))
	writeField(&buf, []byte(nextUpdate))
	binary.BigEndian.PutUint64(n[:], uint64(len(serials)))
	buf.Write(n[:])
	for i := range serials {
		writeField(&buf, []byte(serials[i]))
		writeField(&buf, []byte(revokedAt[i]))
		writeField(&buf, []byte(reasons[i]))
	}
	return buf.Bytes()
}
