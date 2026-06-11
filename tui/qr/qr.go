// Package qr renders data as a terminal QR code, sized to the available width with
// a graceful fall back to plain text (§2.4): a one-time invite link, a beacon URL,
// or a Sneakernet offer blob a peer can scan in person instead of reading base64
// aloud.
//
// It reuses the project's existing mdp/qrterminal dependency (already used for the
// /invite QR) rather than adding a second QR library — a focused tool beats a
// bloated one (CLAUDE.md #10). qrterminal's half-block output packs two QR rows
// per terminal line, so a code fits in roughly (modules+quiet-zone) columns.
package qr

import (
	"bytes"
	"os"
	"strings"

	"github.com/mdp/qrterminal/v3"
	"golang.org/x/term"
)

// Render encodes data as a half-block QR code for the terminal. maxWidth (<=0 means
// unlimited) is the column budget: when the code would be wider, or it rendered
// nothing, ok is false and the caller shows the data as text instead. This is the
// width-aware fallback §2.4 requires.
func Render(data string, maxWidth int) (string, bool) {
	if data == "" {
		return "", false
	}
	var buf bytes.Buffer
	qrterminal.GenerateHalfBlock(data, qrterminal.L, &buf)
	out := strings.TrimRight(buf.String(), "\n")
	if out == "" {
		return "", false
	}
	if maxWidth > 0 && MaxLineWidth(out) > maxWidth {
		return "", false
	}
	return out, true
}

// MaxLineWidth returns the width, in runes, of the widest line in s.
func MaxLineWidth(s string) int {
	max := 0
	for _, ln := range strings.Split(s, "\n") {
		if w := len([]rune(ln)); w > max {
			max = w
		}
	}
	return max
}

// TerminalWidth reports the width of the controlling terminal (stdout), or 80 when
// it cannot be determined (e.g. output is piped). Used by the non-TUI commands
// (beacon-link, pair) to decide whether a QR fits.
func TerminalWidth() int {
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 {
		return w
	}
	return 80
}
