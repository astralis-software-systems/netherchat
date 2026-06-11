package qr

import (
	"strings"
	"testing"
)

// blockChars are the half-block glyphs qrterminal renders QR modules with.
const blockChars = "█▀▄"

func TestRenderProducesQRBlocks(t *testing.T) {
	out, ok := Render("https://chat.example.com/join?room=ops&token=abc123", 200)
	if !ok {
		t.Fatal("expected a QR for a short URL at a generous width")
	}
	if !strings.ContainsAny(out, blockChars) {
		t.Fatalf("QR output contains no block characters:\n%s", out)
	}
}

func TestRenderFallsBackWhenTooNarrow(t *testing.T) {
	// A QR is always wider than a handful of columns, so it must decline to render.
	if _, ok := Render("https://chat.example.com/join?room=ops&token=abc123", 5); ok {
		t.Fatal("expected the width fallback to decline a QR that does not fit")
	}
}

func TestRenderEmptyIsFalse(t *testing.T) {
	if _, ok := Render("", 200); ok {
		t.Fatal("rendering empty data should report ok=false")
	}
}

func TestRenderBeaconURL(t *testing.T) {
	// A representative beacon-link URL (longer, with a base64 key) still renders at a
	// generous width — proving beacon-link --qr works.
	url := "https://chat.example.com/beacon?room=ops&key=" + strings.Repeat("A", 44) + "&ttl=7200"
	if _, ok := Render(url, 400); !ok {
		t.Fatal("expected a QR for a beacon URL at a wide terminal")
	}
}

func TestMaxLineWidth(t *testing.T) {
	if w := MaxLineWidth("ab\nabcd\nabc"); w != 4 {
		t.Fatalf("MaxLineWidth = %d, want 4", w)
	}
}
