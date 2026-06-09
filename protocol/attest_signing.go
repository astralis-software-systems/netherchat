package protocol

import (
	"bytes"
	"encoding/binary"
)

// RosterSigningBytes returns the canonical bytes a roster co-signature covers
// (§1.4): a member attesting "this is the set of identities that hold the keys
// for this room at this epoch." The bare set_hash is NOT signed directly — the
// preimage is domain-separated and bound to room + epoch so a roster signature
// can never be confused with a message/seal/record signature, nor replayed to
// attest the same membership set in a different room or epoch.
//
// Layout (roster v1):
//
//	field("netherchat/roster/v1") || field(room) || epoch_be64 || setHash[32]
//
// where field(b) = uint64-big-endian(len(b)) || b, epoch_be64 is 8 bytes
// big-endian (NOT length-prefixed), and setHash is the raw 32 bytes of the
// SHA-256 over the sorted member fingerprints (fixed size, NOT length-prefixed).
func RosterSigningBytes(room string, epoch uint64, setHash []byte) []byte {
	var buf bytes.Buffer
	writeField(&buf, []byte("netherchat/roster/v1")) // domain-separation tag
	writeField(&buf, []byte(room))
	var e [8]byte
	binary.BigEndian.PutUint64(e[:], epoch)
	buf.Write(e[:])
	buf.Write(setHash) // raw 32 bytes, fixed size
	return buf.Bytes()
}

// ScuttleReceiptSigningBytes returns the canonical bytes a scuttle-receipt
// co-signature covers (§1.5): a member attesting "this room's keys were
// destroyed, per this receipt." The receipt hash already commits to the room,
// epoch range, reason, timestamp, and member set (it is the SHA-256 of the
// canonical receipt), so the preimage only needs the domain-separation tag to
// keep a receipt signature distinct from every other signature kind.
//
// Layout (receipt v1):
//
//	field("netherchat/receipt/v1") || receiptHash[32]
func ScuttleReceiptSigningBytes(receiptHash []byte) []byte {
	var buf bytes.Buffer
	writeField(&buf, []byte("netherchat/receipt/v1")) // domain-separation tag
	buf.Write(receiptHash)                            // raw 32 bytes, fixed size
	return buf.Bytes()
}
