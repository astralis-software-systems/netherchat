package theme

import "testing"

func TestRegistryHasEightThemes(t *testing.T) {
	names := Names()
	if len(names) != 8 {
		t.Fatalf("expected 8 themes, got %d: %v", len(names), names)
	}
	for _, want := range []string{"nether", "abyss", "ember", "ghost", "sprinkles", "dracula", "gruvbox", "solarized"} {
		if _, ok := Get(want); !ok {
			t.Errorf("missing theme %q", want)
		}
	}
}

func TestDefaultIsNether(t *testing.T) {
	if Default().Name != "nether" {
		t.Errorf("default = %q, want nether", Default().Name)
	}
}

func TestGetUnknown(t *testing.T) {
	if _, ok := Get("nope"); ok {
		t.Error("Get(nope) should not exist")
	}
}

func TestUserColorIsStable(t *testing.T) {
	th := Default()
	a := th.UserColor("alice")
	b := th.UserColor("alice")
	if a != b {
		t.Error("UserColor not stable for the same name")
	}
	if th.UserColor("") == "" {
		t.Error("UserColor should fall back to a non-empty color")
	}
}
