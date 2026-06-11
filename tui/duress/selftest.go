package duress

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// SelfTest exercises the entire duress path end-to-end with throwaway secrets and
// an ephemeral identity, returning an error if any invariant fails. It proves, with
// zero operator input and no persistence, that:
//
//   - the duress credential yields the Duress disposition (the safe response fires);
//   - the real credential yields Normal;
//   - an unrelated credential is Rejected;
//   - the emitted beacon verifies offline and a tampered beacon does not.
//
// It is what `netherchat duress selftest` runs, and a confidence check an operator
// can run any time. It opens no network connections and writes nothing to disk.
func SelfTest(mode Mode) error {
	if err := mode.Valid(); err != nil {
		return err
	}

	real := mustRandom(16)
	duress := mustRandom(16)
	for bytes.Equal(real, duress) { // astronomically unlikely; loop is just correctness
		duress = mustRandom(16)
	}
	other := mustRandom(16)

	// Arm zeroes its inputs, so hand it copies and keep the originals for attempts.
	g, err := Arm(clone(real), clone(duress), mode)
	if err != nil {
		return fmt.Errorf("selftest: arm: %w", err)
	}

	if d := g.Evaluate(clone(duress)); d != Duress {
		return fmt.Errorf("selftest: duress credential classified as %s, want duress", d)
	}
	if d := g.Evaluate(clone(real)); d != Normal {
		return fmt.Errorf("selftest: real credential classified as %s, want normal", d)
	}
	if d := g.Evaluate(clone(other)); d != Reject {
		return fmt.Errorf("selftest: unrelated credential classified as %s, want reject", d)
	}

	id, err := crypto.GenerateIdentity()
	if err != nil {
		return fmt.Errorf("selftest: generate identity: %w", err)
	}
	b, err := SignBeacon(id, mode, "selftest")
	if err != nil {
		return fmt.Errorf("selftest: sign beacon: %w", err)
	}
	if err := b.Verify(); err != nil {
		return fmt.Errorf("selftest: fresh beacon failed to verify: %w", err)
	}
	tampered := *b
	tampered.Sig = clone(b.Sig)
	tampered.Sig[0] ^= 0xff
	if err := tampered.Verify(); err == nil {
		return errors.New("selftest: tampered beacon verified — signature check is not effective")
	}
	return nil
}

func mustRandom(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("duress: system CSPRNG failed: " + err.Error())
	}
	return b
}

func clone(b []byte) []byte { return append([]byte(nil), b...) }
