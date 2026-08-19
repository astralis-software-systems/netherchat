package client

import (
	"errors"

	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/record"
)

// AttestIdentity places an identity attestation into the room's record chain as
// a typed entry, signs it, broadcasts it, and echoes it locally — the same path
// /decide takes, with a typed entry instead of a text one.
//
// This is the PRODUCER half of the record carrier, and until it existed no
// Netherchat code appended a typed entry at all: the format was exercised only
// by a downstream consumer, which is a poor way to learn that a format is wrong.
//
// WHAT IT DOES NOT DO, and this is the design and not an omission:
//
//   - It does not verify the attestation. Verification takes an issuer key and an
//     evaluation time, both of which belong to whoever READS the record; a carrier
//     that refused to carry an attestation because the carrier had pinned no issuer
//     would make the evidence a function of the producer's configuration. The
//     caller parses the artifact — which is a structural check, not a verdict — and
//     this appends it.
//   - It does not decide who may carry whose attestation. Anyone may: the subject
//     themselves, an approver attaching their own credential to a decision they
//     made, an administrator batching credentials in. Placing a stranger's
//     attestation into your record proves only that you placed it there, because
//     the binding's trust comes entirely from an issuer signature checked against
//     a key the reader pinned.
//
// TIMING. The entry has to be in the chain before /seal, because the amend path
// admits a co-signature over an unchanged head and nothing else. Attesting after
// a seal does not amend that record; it starts a new one.
func (c *Client) AttestIdentity(att *attest.IdentityAttestation) error {
	if att == nil {
		return errors.New("no attestation to record")
	}
	spec, err := record.IdentityEntrySpec(att)
	if err != nil {
		return err
	}
	return c.appendSpec(spec)
}
