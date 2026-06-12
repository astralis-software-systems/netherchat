package protocol

import (
	"bytes"
	"encoding/binary"
)

// AlertSigningBytes returns the canonical bytes an inbound alert's signature
// covers (NC-1): the metadata an authenticated source attests it is sending. It is
// the preimage for the per-source HMAC-SHA256 — a source registered with an
// hmac_secret sets the alert's `signature` field to hex(HMAC-SHA256(secret,
// AlertSigningBytes(...))), and the relay recomputes and constant-time-compares it.
//
// Binding every metadata field into the preimage makes the signature tamper-
// evident: a captured alert cannot have its severity, kind, summary, or reference
// altered in transit without invalidating the HMAC. The domain-separation tag
// keeps it distinct from every other Netherchat signature, and every variable
// field is length-prefixed so the encoding is injective (a source cannot smuggle
// one field's bytes into another).
//
// Layout (alert v1):
//
//	field("netherchat/alert/v1")
//	  || field(source) || field(severity) || field(kind)
//	  || field(summary) || field(ref) || ts_be64
//
// where field(b) = uint64-big-endian(len(b)) || b, and ts_be64 is the unix-second
// timestamp as 8 bytes big-endian (two's-complement int64; NOT length-prefixed).
// This carries metadata only — never raw regulated content (the boundary law).
func AlertSigningBytes(source, severity, kind, summary, ref string, ts int64) []byte {
	var buf bytes.Buffer
	writeField(&buf, []byte("netherchat/alert/v1")) // domain-separation tag
	writeField(&buf, []byte(source))
	writeField(&buf, []byte(severity))
	writeField(&buf, []byte(kind))
	writeField(&buf, []byte(summary))
	writeField(&buf, []byte(ref))
	var t [8]byte
	binary.BigEndian.PutUint64(t[:], uint64(ts))
	buf.Write(t[:])
	return buf.Bytes()
}
