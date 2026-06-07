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
