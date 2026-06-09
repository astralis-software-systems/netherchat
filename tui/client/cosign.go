package client

import "time"

// cosignRound collects Ed25519 co-signatures over a fixed preimage from the
// present members of a room, so a single member's attestation can become a
// multi-party one. It finishes early when everyone present has signed, or when a
// timeout elapses. It generalizes the seal handshake (§1.4) for the roster
// attestation (§1.4) and the scuttle receipt (§1.5): the Client holds one round
// per feature plus the metadata needed to assemble that artifact at finalize
// time. All access is under Client.mu.
type cosignRound struct {
	preimage []byte            // the exact bytes every signer signs
	sigs     map[string][]byte // fpr -> raw Ed25519 signature
	keys     map[string][]byte // fpr -> raw Ed25519 public key
	timer    *time.Timer       // collection-window timer
}

// newCosignRound seeds a round with the initiator's own (already-computed)
// signature and public key.
func newCosignRound(preimage []byte, selfFpr string, selfSig, selfKey []byte) *cosignRound {
	return &cosignRound{
		preimage: preimage,
		sigs:     map[string][]byte{selfFpr: append([]byte(nil), selfSig...)},
		keys:     map[string][]byte{selfFpr: append([]byte(nil), selfKey...)},
	}
}

// add records an already-verified co-signature (the caller verifies the sig
// against preimage before calling).
func (r *cosignRound) add(fpr string, key, sig []byte) {
	r.sigs[fpr] = append([]byte(nil), sig...)
	r.keys[fpr] = append([]byte(nil), key...)
}

// count is the number of distinct signers collected so far.
func (r *cosignRound) count() int { return len(r.sigs) }

// stop halts the collection timer if it is running.
func (r *cosignRound) stop() {
	if r.timer != nil {
		r.timer.Stop()
		r.timer = nil
	}
}
