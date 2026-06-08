package render

import (
	"fmt"
	"strconv"

	"github.com/charmbracelet/lipgloss"
	"github.com/salehkreiner/netherchat/tui/ui/theme"
)

// chromaStyleFor maps a Netherchat theme to a bundled chroma syntax style whose
// palette complements it. The mapping is deliberately *not* identity for every
// theme: nether/abyss/ghost/ember/sprinkles borrow a chroma style that matches
// their mood, while dracula/gruvbox/solarized use chroma's namesake style so
// code colors line up exactly with the rest of the UI.
//
// Two distinct Netherchat themes must never map to the same chroma style if we
// want a visible difference on /theme — in particular nether (monokai) and
// dracula (dracula) differ, which the theme-switch test pins.
func chromaStyleFor(themeName string) string {
	switch themeName {
	case "nether":
		return "monokai" // vivid on deep violet
	case "abyss":
		return "nord" // cold blue, matches the cyan-on-black mood
	case "ember":
		return "fruity" // warm oranges/reds
	case "ghost":
		return "bw" // monochrome, true to the grayscale theme
	case "sprinkles":
		return "colorful" // maximally colorful for the rainbow easter egg
	case "dracula":
		return "dracula"
	case "gruvbox":
		return "gruvbox"
	case "solarized":
		return "solarized-dark"
	default:
		return "monokai"
	}
}

// surfaceColor derives a code-block background from the theme background: a
// subtle "surface" that sits a little above (dark themes) or below (light
// themes) the message background, so a code block reads as a distinct panel
// without clashing with any theme. Terminals own the real background, but
// painting the panel cells gives the intended raised-surface look where the
// emulator honors it.
func surfaceColor(th theme.Theme) lipgloss.Color {
	rgb, ok := parseHexColor(string(th.Bg))
	if !ok {
		// No usable background hex; fall back to the muted color so the panel is
		// at least visually distinct from the surrounding text.
		return th.Muted
	}
	// Rec. 601 luma — good enough to decide lighten vs. darken.
	luma := 0.299*float64(rgb[0]) + 0.587*float64(rgb[1]) + 0.114*float64(rgb[2])
	const delta = 18
	step := delta
	if luma >= 128 {
		step = -delta
	}
	for i := range rgb {
		rgb[i] = clamp8(int(rgb[i]) + step)
	}
	return lipgloss.Color(fmt.Sprintf("#%02x%02x%02x", rgb[0], rgb[1], rgb[2]))
}

// parseHexColor parses "#rrggbb" (or "rrggbb") into RGB. It does not handle the
// "#rgb" short form — every Netherchat theme background is full 6-digit hex.
func parseHexColor(s string) ([3]uint8, bool) {
	if len(s) == 7 && s[0] == '#' {
		s = s[1:]
	}
	if len(s) != 6 {
		return [3]uint8{}, false
	}
	var out [3]uint8
	for i := 0; i < 3; i++ {
		v, err := strconv.ParseUint(s[i*2:i*2+2], 16, 8)
		if err != nil {
			return [3]uint8{}, false
		}
		out[i] = uint8(v)
	}
	return out, true
}

func clamp8(v int) uint8 {
	if v < 0 {
		return 0
	}
	if v > 255 {
		return 255
	}
	return uint8(v)
}
