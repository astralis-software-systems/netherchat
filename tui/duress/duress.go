// Package duress implements Netherchat's coercion-resistant safe response (C2).
//
// The threat it addresses is physical or legal coercion: an adversary who can
// compel an operator to unlock or open a war room. The defense is a SECOND, duress
// credential that looks and feels exactly like the real one but quietly triggers a
// predefined safe response instead of normal access — without signaling to the
// coercer that anything unusual happened.
//
// Two safe responses are supported (see Mode):
//
//   - silent_scuttle — destroy local sensitive state (the integration ratchets the
//     room key forward and closes the room, exactly as a normal /scuttle would) and
//     emit a signed, out-of-band duress Beacon, while the UI behaves as if a normal
//     unlock failed or succeeded benignly.
//   - decoy_view — present a benign, pre-staged decoy in place of the real state;
//     the real material stays sealed and hidden.
//
// Design constraints, all enforced here:
//
//   - The passphrase is NEVER stored — not on disk, not even as a commitment. Arm
//     derives an argon2id token from the passphrase and a random in-memory salt,
//     then ZEROES the passphrase bytes; only the derived tokens live on, in process
//     memory, for the lifetime of the Guard. Persisting a commitment would itself be
//     a tell: an adversary inspecting the disk would learn that duress mode exists.
//     "In memory only" is the coercion-resistance property, not an implementation
//     shortcut. (See docs/duress.md.)
//   - Comparison is constant-time, and BOTH the real and duress tokens are always
//     compared, so neither the match result nor which credential matched leaks via
//     timing.
//   - The duress Beacon is signed with the actor's own Ed25519 identity key and is
//     offline-verifiable, so a monitor can attribute it rather than merely receive
//     an anonymous, forgeable ping. It travels out-of-band — never across the relay
//     the coercer can observe.
//   - No telemetry. This package opens no network connections of its own; emitting a
//     Beacon produces bytes for the caller to deliver over a channel of its choosing.
//
// It lives under tui/ so it may use the client crypto package; the blind relay
// neither links nor knows about any of this.
package duress

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// Mode is the safe response a duress credential triggers.
type Mode string

const (
	// ModeSilentScuttle destroys local sensitive state and emits a duress beacon,
	// while appearing benign to the coercer.
	ModeSilentScuttle Mode = "silent_scuttle"
	// ModeDecoyView presents a benign decoy; the real state stays sealed and hidden.
	ModeDecoyView Mode = "decoy_view"
)

// Valid reports whether m is a known mode.
func (m Mode) Valid() error {
	switch m {
	case ModeSilentScuttle, ModeDecoyView:
		return nil
	default:
		return fmt.Errorf("duress: unknown mode %q (want %q or %q)", m, ModeSilentScuttle, ModeDecoyView)
	}
}

// Disposition is the outcome of evaluating an entered credential.
type Disposition int

const (
	// Reject: the entered credential matched neither the real nor the duress token.
	Reject Disposition = iota
	// Normal: the entered credential matched the real token — proceed normally.
	Normal
	// Duress: the entered credential matched the duress token — take the safe response.
	Duress
)

// String renders the disposition as a lowercase word for CLI/logging use.
func (d Disposition) String() string {
	switch d {
	case Normal:
		return "normal"
	case Duress:
		return "duress"
	default:
		return "reject"
	}
}

// argon2id parameters. Tuned for an interactive unlock: ~32 MiB and a single pass
// is enough to make offline guessing of the (never-persisted) tokens expensive,
// while staying fast enough for a person typing a passphrase and for tests.
const (
	argonTime    = 1
	argonMemory  = 32 * 1024 // KiB => 32 MiB
	argonThreads = 2
	tokenLen     = 32
	saltLen      = 16
)

// Guard holds the derived tokens for one armed session. It NEVER holds the
// passphrases themselves. The zero value is not usable; build one with Arm.
type Guard struct {
	salt        []byte
	realToken   []byte
	duressToken []byte
	mode        Mode
}

// Arm derives the in-memory tokens for a real and a duress credential and returns
// a Guard. It ZEROES both input slices before returning, so the caller's
// passphrase bytes do not linger. The credentials must be non-empty and must
// differ.
//
// Callers should pass freshly-read []byte (e.g. from a prompt) rather than string
// literals, precisely so this zeroing is meaningful — a Go string cannot be wiped.
func Arm(real, duress []byte, mode Mode) (*Guard, error) {
	defer zero(real)
	defer zero(duress)

	if err := mode.Valid(); err != nil {
		return nil, err
	}
	if len(real) == 0 || len(duress) == 0 {
		return nil, errors.New("duress: both the real and duress credentials must be non-empty")
	}
	if subtle.ConstantTimeCompare(real, duress) == 1 {
		return nil, errors.New("duress: the duress credential must differ from the real one")
	}

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("duress: generate salt: %w", err)
	}
	return &Guard{
		salt:        salt,
		realToken:   deriveToken(real, salt),
		duressToken: deriveToken(duress, salt),
		mode:        mode,
	}, nil
}

// Mode returns the safe response this guard triggers on a duress match.
func (g *Guard) Mode() Mode { return g.mode }

// Evaluate classifies an entered credential. It derives a token from the input and
// the session salt, compares it (constant-time) against BOTH stored tokens, and
// returns the disposition. The input slice and the derived token are zeroed before
// returning. Both comparisons always run, so neither timing nor the result reveals
// which credential — if any — was a hit.
func (g *Guard) Evaluate(entered []byte) Disposition {
	defer zero(entered)
	tok := deriveToken(entered, g.salt)
	defer zero(tok)

	isDuress := subtle.ConstantTimeCompare(tok, g.duressToken) == 1
	isReal := subtle.ConstantTimeCompare(tok, g.realToken) == 1
	switch {
	case isDuress:
		return Duress
	case isReal:
		return Normal
	default:
		return Reject
	}
}

// deriveToken is the one-way KDF turning a credential into a comparison token.
func deriveToken(pass, salt []byte) []byte {
	return argon2.IDKey(pass, salt, argonTime, argonMemory, argonThreads, tokenLen)
}

// zero overwrites b in place. It is the best-effort wipe behind the
// "passphrase never stored" guarantee for the bytes this package controls.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
