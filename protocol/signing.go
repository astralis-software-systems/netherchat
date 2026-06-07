package protocol

import (
	"bytes"
	"encoding/binary"
)

// SigningBytes returns the canonical, unambiguous byte sequence that a
// Message.Sig covers. Both the signer (sender) and every verifier must derive
// the exact same bytes, so the layout is fixed here in the protocol package
// rather than in the crypto package. The TypeScript client mirrors this exactly
// (web/src/crypto/signing.ts); a cross-implementation test pins the bytes.
//
// Layout (protocol v3):
//
//	field("netherchat/msg/v1") || field(room_id) || field(from_id)
//	  || epoch_be64 || field(nonce) || field(ciphertext)
//
// where field(b) = uint64-big-endian(len(b)) || b, and epoch_be64 is the epoch
// as 8 bytes big-endian (NOT length-prefixed). Each field is length-prefixed so
// the encoding is injective. Binding room_id, from_id and epoch means a captured
// ciphertext cannot be replayed under a different room, sender, or epoch.
func SigningBytes(roomID, fromID string, epoch uint64, nonce, ciphertext []byte) []byte {
	var buf bytes.Buffer
	writeField(&buf, []byte("netherchat/msg/v1")) // domain-separation tag
	writeField(&buf, []byte(roomID))
	writeField(&buf, []byte(fromID))
	var e [8]byte
	binary.BigEndian.PutUint64(e[:], epoch)
	buf.Write(e[:])
	writeField(&buf, nonce)
	writeField(&buf, ciphertext)
	return buf.Bytes()
}

func writeField(buf *bytes.Buffer, b []byte) {
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(len(b)))
	buf.Write(l[:])
	buf.Write(b)
}
