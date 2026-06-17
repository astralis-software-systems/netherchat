package protocol

import (
	"bytes"
	"encoding/binary"
)

// RecordSigningBytes returns the canonical, unambiguous byte sequence that a
// sealed-record entry's signature (RecordEntry.Sig, §1.4) covers. As with
// SigningBytes, the layout is fixed here in the protocol package so the signer
// and every verifier — including an offline `netherchat verify` that was never in
// the room — derive identical bytes. A cross-implementation test pins the bytes.
//
// Layout (record v1):
//
//	field("netherchat/record/v1")
//	  || seq_be64 || ts_be64
//	  || field(authorID) || field(kind) || field(actionee) || field(body)
//	  || prevHash[32]
//
// where field(b) = uint64-big-endian(len(b)) || b, seq_be64/ts_be64 are 8 bytes
// big-endian (ts as a two's-complement int64; NOT length-prefixed), and prevHash
// is the raw 32 bytes of the previous entry's hash (fixed size, NOT
// length-prefixed). Every variable-length field is length-prefixed so the
// encoding is injective. Binding prevHash into the signed bytes is what makes the
// chain tamper-evident: an entry's signature commits to its position.
//
// authorID is the SSH fingerprint of the signer's identity key (the human-
// recognizable, pinnable identifier); the verifier additionally checks that the
// public key it verifies against hashes to this fingerprint, binding the two.
func RecordSigningBytes(seq uint64, ts int64, authorID, kind, actionee, body string, prevHash []byte) []byte {
	var buf bytes.Buffer
	writeField(&buf, []byte("netherchat/record/v1")) // domain-separation tag
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], seq)
	buf.Write(n[:])
	binary.BigEndian.PutUint64(n[:], uint64(ts))
	buf.Write(n[:])
	writeField(&buf, []byte(authorID))
	writeField(&buf, []byte(kind))
	writeField(&buf, []byte(actionee)) // empty string for non-action entries
	writeField(&buf, []byte(body))
	buf.Write(prevHash) // raw 32 bytes, fixed size
	return buf.Bytes()
}

// RecordSigningBytesV2 returns the canonical bytes covered by an EXTENDED record
// entry's signature: one that carries a typed schema tag (a consumer-defined
// record type beyond decision/action/note/artifact) and/or cross-record
// traceability links. It is a strict superset of the v1 layout under a distinct
// domain tag, so a v1 and a v2 entry can never collide, and an entry's chosen
// layout is a pure function of its content (an entry with none of the v2 fields
// uses RecordSigningBytes, byte-for-byte as before — old records keep verifying).
//
// The library attaches NO meaning to the schema tag/version or the link
// hashes/relations: they are opaque, signed strings. Domain semantics are
// supplied by the consuming application.
//
// Layout (record v2):
//
//	field("netherchat/record/v2")
//	  || seq_be64 || ts_be64
//	  || field(authorID) || field(kind) || field(actionee) || field(body)
//	  || field(schema) || field(schemaVer)
//	  || nlinks_be64 || { field(linkHash[i]) || field(linkRel[i]) } for each link
//	  || prevHash[32]
//
// where field(b) = uint64-big-endian(len(b)) || b, the *_be64 values are 8 bytes
// big-endian (ts as a two's-complement int64; NOT length-prefixed), and prevHash
// is the raw 32 bytes (fixed size). linkHashes and linkRels are parallel slices
// of equal length (one entry per link, in order); the count is signed too, so a
// link can be neither added nor dropped without breaking the signature.
func RecordSigningBytesV2(seq uint64, ts int64, authorID, kind, actionee, body, schema, schemaVer string, linkHashes, linkRels []string, prevHash []byte) []byte {
	var buf bytes.Buffer
	writeField(&buf, []byte("netherchat/record/v2")) // domain-separation tag
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], seq)
	buf.Write(n[:])
	binary.BigEndian.PutUint64(n[:], uint64(ts))
	buf.Write(n[:])
	writeField(&buf, []byte(authorID))
	writeField(&buf, []byte(kind))
	writeField(&buf, []byte(actionee))
	writeField(&buf, []byte(body))
	writeField(&buf, []byte(schema))
	writeField(&buf, []byte(schemaVer))
	binary.BigEndian.PutUint64(n[:], uint64(len(linkHashes)))
	buf.Write(n[:])
	for i := range linkHashes {
		writeField(&buf, []byte(linkHashes[i]))
		writeField(&buf, []byte(linkRels[i]))
	}
	buf.Write(prevHash) // raw 32 bytes, fixed size
	return buf.Bytes()
}

// SealSigningBytes returns the canonical bytes a seal signature covers (§1.4): a
// participant attesting "I co-sign this record head, in this room." The bare head
// hash is NOT signed directly — the preimage is domain-separated and room-bound
// so a seal signature can never be confused with a message/record signature, nor
// replayed to attest the same chain in a different room.
//
// Layout (seal v1):
//
//	field("netherchat/seal/v1") || field(room) || headHash[32]
func SealSigningBytes(room string, headHash []byte) []byte {
	var buf bytes.Buffer
	writeField(&buf, []byte("netherchat/seal/v1"))
	writeField(&buf, []byte(room))
	buf.Write(headHash) // raw 32 bytes, fixed size
	return buf.Bytes()
}

// SealSigningBytesV2 returns the canonical bytes covered by a seal co-signature
// that carries a declared electronic-signature MEANING: why the participant
// signed (meaning, e.g. "approved"), their printed name, and the UTC time they
// signed. All three are bound into the preimage, so none can be altered without
// invalidating the signature — the meaning is a signed fact, not editable
// metadata. It is domain-separated from v1 so a meaning-bearing co-signature is
// never confused with a bare one.
//
// The library ships authored/reviewed/approved/rejected as default meanings but
// treats meaning as an opaque, extensible string; a consumer may declare others.
//
// Layout (seal v2):
//
//	field("netherchat/seal/v2") || field(room)
//	  || field(meaning) || field(signerName) || field(signedAt) || headHash[32]
func SealSigningBytesV2(room, meaning, signerName, signedAt string, headHash []byte) []byte {
	var buf bytes.Buffer
	writeField(&buf, []byte("netherchat/seal/v2"))
	writeField(&buf, []byte(room))
	writeField(&buf, []byte(meaning))
	writeField(&buf, []byte(signerName))
	writeField(&buf, []byte(signedAt))
	buf.Write(headHash) // raw 32 bytes, fixed size
	return buf.Bytes()
}
