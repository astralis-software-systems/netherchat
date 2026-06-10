package protocol

import "bytes"

// DirectAuthBytes is the canonical message each side of a direct (Sneakernet,
// §1.1) connection signs to prove control of its Ed25519 identity key and bind the
// authentication to this specific session. Like SigningBytes it lives here, in the
// crypto-free protocol package, so the signer and the verifier derive identical
// bytes.
//
// The handshake is symmetric: each side signs DirectAuthBytes of its OWN public
// key and nonce against the PEER's public key and nonce, i.e.
//
//	sign( DirectAuthBytes(myPub, myNonce, peerPub, peerNonce) )
//
// and verifies the peer's signature against
//
//	DirectAuthBytes(peerPub, peerNonce, myPub, myNonce)
//
// Binding BOTH public keys defeats a key-substitution man-in-the-middle (a relay
// process splicing two connections cannot re-sign for a key it does not hold), and
// binding BOTH fresh nonces defeats replay of a captured handshake.
//
// Layout: field("netherchat/direct/v1") || field(signerPub) || field(signerNonce)
//
//	|| field(peerPub) || field(peerNonce)
//
// where field(b) = uint64-big-endian(len(b)) || b (the same injective framing as
// SigningBytes).
func DirectAuthBytes(signerPub, signerNonce, peerPub, peerNonce []byte) []byte {
	var buf bytes.Buffer
	writeField(&buf, []byte("netherchat/direct/v1")) // domain-separation tag
	writeField(&buf, signerPub)
	writeField(&buf, signerNonce)
	writeField(&buf, peerPub)
	writeField(&buf, peerNonce)
	return buf.Bytes()
}
