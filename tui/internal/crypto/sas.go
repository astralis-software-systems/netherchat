package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
)

// Short Authentication String (SAS) — out-of-band verification (§1.2).
//
// After key exchange, two members each hold the shared room key and both parties'
// public keys. SASWords derives a 5-word string from a CANONICAL transcript of
// that material. Both members compute the identical words iff there is no MITM:
// if a malicious relay substituted either party's identity or key-agreement key,
// the transcripts differ and the words will not match. The words are read to each
// other over a trusted side channel (a phone bridge, in person) to confirm the
// channel is clean.
//
// Transcript (length-prefixed, so the encoding is injective; the two members are
// ordered canonically by their Ed25519 key so both sides build the same bytes):
//
//	field("netherchat-sas-transcript-v1")
//	  || field(lo.sign) || field(lo.kx) || field(hi.sign) || field(hi.kx)
//	  || field(roomKey)
//
// where (lo, hi) are the two members ordered by ascending Ed25519 public key.
//
// Derivation: SAS = HKDF-SHA256(SHA-256(transcript), info="netherchat-sas-v1",
// 10 bytes). The 10 bytes are folded to 5 (b[i] ^ b[i+5]) and each maps to a PGP
// word — even positions from the two-syllable list, odd from the three-syllable
// list (see pgpwords.go).
const sasInfo = "netherchat-sas-v1"

// SASWords returns the 5-word short authentication string for the pairwise
// session between the local member (selfSign/selfKX) and a peer (peerSign/peerKX)
// who share roomKey.
func SASWords(selfSign ed25519.PublicKey, selfKX [32]byte, peerSign ed25519.PublicKey, peerKX [32]byte, roomKey [32]byte) []string {
	loSign, loKX, hiSign, hiKX := selfSign, selfKX, peerSign, peerKX
	if bytes.Compare(peerSign, selfSign) < 0 {
		loSign, loKX, hiSign, hiKX = peerSign, peerKX, selfSign, selfKX
	}

	var t bytes.Buffer
	sasField(&t, []byte("netherchat-sas-transcript-v1"))
	sasField(&t, loSign)
	sasField(&t, loKX[:])
	sasField(&t, hiSign)
	sasField(&t, hiKX[:])
	sasField(&t, roomKey[:])

	th := sha256.Sum256(t.Bytes())

	r := hkdf.New(sha256.New, th[:], nil, []byte(sasInfo))
	var raw [10]byte
	_, _ = io.ReadFull(r, raw[:])

	// Fold 10 bytes into 5 so the full derived SAS is committed in the words.
	words := make([]string, 5)
	for i := 0; i < 5; i++ {
		b := raw[i] ^ raw[i+5]
		if i%2 == 0 {
			words[i] = strings.ToLower(pgpEven[b])
		} else {
			words[i] = strings.ToLower(pgpOdd[b])
		}
	}
	return words
}

func sasField(buf *bytes.Buffer, b []byte) {
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(len(b)))
	buf.Write(l[:])
	buf.Write(b)
}
