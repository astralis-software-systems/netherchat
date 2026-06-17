package record

import (
	"crypto/ed25519"

	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// Fingerprint returns the SSH-style "SHA256:…" fingerprint of an Ed25519
// identity public key — the same human-recognizable, pinnable identifier used as
// an Entry.AuthorID and as the key of a SealedRecord's Signatures / SignerKeys
// maps.
//
// It is a thin, deliberate re-export of Netherchat's internal fingerprint helper
// so that an EXTERNAL program building a record with this library can compute the
// AuthorID and signer-map keys exactly the way Verify expects, without reaching
// into tui/internal/crypto — which Go's internal/ rule keeps unimportable from
// outside the tui/ tree, and which the blind relay must never link. The crypto
// implementation stays internal; this exposes only the one pure, public-key-only
// helper external consumers need.
func Fingerprint(pub ed25519.PublicKey) string {
	return crypto.Fingerprint(pub)
}
