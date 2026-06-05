package protocol

import (
	"bytes"
	"encoding/binary"
)

// SigningBytes returns the canonical, unambiguous byte sequence that a
// Message.Signature covers. Both the signer (sender) and every verifier must
// derive the exact same bytes, so the layout is fixed here in the protocol
// package rather than in the crypto package.
//
// Each field is length-prefixed (8-byte big-endian length, then bytes) so that
// no concatenation of one field can be mistaken for another — i.e. the encoding
// is injective. The signature binds the sender ID and epoch in addition to the
// ciphertext, so a captured ciphertext cannot be replayed under a different
// sender identity or epoch.
func SigningBytes(fromID string, epoch uint64, nonce, ciphertext []byte) []byte {
	var buf bytes.Buffer
	writeField(&buf, []byte("netherchat/msg/v1")) // domain-separation tag
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
