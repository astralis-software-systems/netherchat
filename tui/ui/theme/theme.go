// Package theme defines Netherchat's named TUI color themes and the registry
// used to switch between them instantly at runtime (R2). A Theme is a palette;
// the app builds Lip Gloss styles from it, so swapping the active Theme and
// re-rendering is all it takes to change the look — no restart.
package theme

import (
	"hash/fnv"

	"github.com/charmbracelet/lipgloss"
)

// Theme is a named color palette plus an advisory font (terminals own the font;
// see ARCHITECTURE_DECISION.md §8.1).
type Theme struct {
	Name string
	Font string // advisory: the font this theme is designed for

	Bg      lipgloss.Color // informational; the terminal owns the real background
	Text    lipgloss.Color
	Muted   lipgloss.Color
	Accent  lipgloss.Color // primary accent: active room, titles
	Accent2 lipgloss.Color // secondary accent
	Success lipgloss.Color
	Warn    lipgloss.Color
	Error   lipgloss.Color

	// Rainbow is true for themes that color each user distinctly (sprinkles).
	Rainbow bool
	// Users is the palette usernames are colored from.
	Users []lipgloss.Color
}

// UserColor returns a stable color for a username (same name -> same color).
func (t Theme) UserColor(name string) lipgloss.Color {
	if len(t.Users) == 0 {
		return t.Accent2
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	return t.Users[int(h.Sum32())%len(t.Users)]
}

func c(hex string) lipgloss.Color { return lipgloss.Color(hex) }

// themes is the registry, in display order. nether is the default (brand).
var themes = []Theme{
	{
		Name: "nether", Font: "JetBrains Mono",
		Bg: c("#0a0a12"), Text: c("#e2e0f0"), Muted: c("#7c6fa0"),
		Accent: c("#7c3aed"), Accent2: c("#a78bfa"),
		Success: c("#8be9a8"), Warn: c("#f0c674"), Error: c("#ff6b6b"),
		Users: []lipgloss.Color{c("#a78bfa"), c("#7c3aed"), c("#c4b5fd"), c("#8b5cf6"), c("#d8b4fe"), c("#9d7cff")},
	},
	{
		Name: "abyss", Font: "JetBrains Mono",
		Bg: c("#04080a"), Text: c("#d0f0f5"), Muted: c("#4a6b78"),
		Accent: c("#22d3ee"), Accent2: c("#67e8f9"),
		Success: c("#5eead4"), Warn: c("#fcd34d"), Error: c("#fb7185"),
		Users: []lipgloss.Color{c("#22d3ee"), c("#67e8f9"), c("#7dd3fc"), c("#38bdf8"), c("#5eead4"), c("#a5f3fc")},
	},
	{
		Name: "ember", Font: "JetBrains Mono",
		Bg: c("#0f0a06"), Text: c("#f5e6d8"), Muted: c("#9a6b4a"),
		Accent: c("#fb923c"), Accent2: c("#fdba74"),
		Success: c("#bef264"), Warn: c("#fcd34d"), Error: c("#f87171"),
		Users: []lipgloss.Color{c("#fb923c"), c("#fdba74"), c("#f59e0b"), c("#fbbf24"), c("#fca5a5"), c("#fed7aa")},
	},
	{
		Name: "ghost", Font: "IBM Plex Mono",
		Bg: c("#0a0a0a"), Text: c("#d0d0d0"), Muted: c("#707070"),
		Accent: c("#e8e8e8"), Accent2: c("#b0b0b0"),
		Success: c("#c0c0c0"), Warn: c("#a0a0a0"), Error: c("#f0f0f0"),
		Users: []lipgloss.Color{c("#d0d0d0"), c("#a8a8a8"), c("#bcbcbc"), c("#909090"), c("#e0e0e0"), c("#808080")},
	},
	{
		Name: "sprinkles", Font: "Fira Code", Rainbow: true,
		Bg: c("#0a0a12"), Text: c("#f5f5fa"), Muted: c("#8a8aa0"),
		Accent: c("#ff79c6"), Accent2: c("#8be9fd"),
		Success: c("#50fa7b"), Warn: c("#f1fa8c"), Error: c("#ff5555"),
		Users: []lipgloss.Color{
			c("#ff5555"), c("#ffb86c"), c("#f1fa8c"), c("#50fa7b"),
			c("#8be9fd"), c("#bd93f9"), c("#ff79c6"), c("#ff6e6e"),
			c("#69ff94"), c("#d6acff"),
		},
	},
	{
		Name: "dracula", Font: "JetBrains Mono",
		Bg: c("#282a36"), Text: c("#f8f8f2"), Muted: c("#6272a4"),
		Accent: c("#bd93f9"), Accent2: c("#ff79c6"),
		Success: c("#50fa7b"), Warn: c("#f1fa8c"), Error: c("#ff5555"),
		Users: []lipgloss.Color{c("#8be9fd"), c("#50fa7b"), c("#ffb86c"), c("#ff79c6"), c("#bd93f9"), c("#f1fa8c")},
	},
	{
		Name: "gruvbox", Font: "JetBrains Mono",
		Bg: c("#282828"), Text: c("#ebdbb2"), Muted: c("#928374"),
		Accent: c("#fabd2f"), Accent2: c("#fe8019"),
		Success: c("#b8bb26"), Warn: c("#fabd2f"), Error: c("#fb4934"),
		Users: []lipgloss.Color{c("#fabd2f"), c("#b8bb26"), c("#8ec07c"), c("#83a598"), c("#d3869b"), c("#fe8019")},
	},
	{
		Name: "solarized", Font: "JetBrains Mono",
		Bg: c("#002b36"), Text: c("#93a1a1"), Muted: c("#586e75"),
		Accent: c("#268bd2"), Accent2: c("#2aa198"),
		Success: c("#859900"), Warn: c("#b58900"), Error: c("#dc322f"),
		Users: []lipgloss.Color{c("#268bd2"), c("#2aa198"), c("#859900"), c("#b58900"), c("#d33682"), c("#6c71c4")},
	},
}

var byName = func() map[string]Theme {
	m := make(map[string]Theme, len(themes))
	for _, t := range themes {
		m[t.Name] = t
	}
	return m
}()

// Default is the brand theme.
func Default() Theme { return themes[0] }

// Get returns the named theme and whether it exists.
func Get(name string) (Theme, bool) {
	t, ok := byName[name]
	return t, ok
}

// Names returns the theme names in display order (for autocomplete and /help).
func Names() []string {
	out := make([]string, len(themes))
	for i, t := range themes {
		out[i] = t.Name
	}
	return out
}
