package client

import (
	"errors"
	"fmt"

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

// UseIdentity provisions this client with the operator's OWN identity
// attestation, so an approval this client sends can carry the credential the
// approver acts under. It is called once, before Connect; carrying none is the
// unchanged path and the free tier.
//
// WHAT IT CHECKS, AND WHAT IT DELIBERATELY DOES NOT.
//
// It checks one thing: that the attestation's subject is this client's own
// identity fingerprint. That is not a verdict about the credential — it is the
// question "is this statement about the key I am about to sign with", and it is
// answerable with no issuer key and no clock. An attestation about someone else
// would travel beside a signature it says nothing about, which is worse than
// carrying nothing.
//
// It does NOT verify the attestation, for the reason AttestIdentity gives above:
// verification takes an issuer key and an evaluation time that belong to whoever
// reads the record, and a producer that refused to carry a credential because
// the PRODUCER had pinned no issuer would make the evidence a function of the
// producer's configuration. Netherchat holds no trust anchors, so there is no
// key here to check a signature against and there must not be one. The reader
// checks the signature, against a key this process never sees.
//
// The roles it names become the vocabulary ApproveArtifact selects from. They
// are read from the artifact and never edited: a role is matched byte-for-byte
// downstream and is inside the issuer's signature.
func (c *Client) UseIdentity(att *attest.IdentityAttestation) error {
	if att == nil {
		return errors.New("no attestation to use")
	}
	self := c.id.Fingerprint()
	if att.Subject != self {
		return fmt.Errorf("that attestation is about subject %s; this client's identity is %s", att.Subject, self)
	}
	b, err := att.Marshal()
	if err != nil {
		return fmt.Errorf("marshal attestation: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.selfCredential = b
	c.selfCredentialRoles = append([]string(nil), att.Roles...)
	return nil
}

// IdentityRoles returns the roles the carried attestation names, or nil when
// this client carries none. It is what a command surface offers an operator to
// choose from: a selection from a signed set, never a free-text field.
func (c *Client) IdentityRoles() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.selfCredentialRoles...)
}
