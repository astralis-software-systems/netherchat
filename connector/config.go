package connector

import (
	"os"

	"github.com/pelletier/go-toml/v2"
)

// Config holds the settings every adapter shares; each adapter's TOML file
// (netherchat-findings.toml, netherchat-egress.toml, …) maps onto it (the SIEM
// adapter extends it with its own fields). Command-line flags override file
// values. Like the relay's own config, this never contains message content.
type Config struct {
	Server      string `toml:"server"`
	Source      string `toml:"source"`
	Token       string `toml:"token"`
	HMACSecret  string `toml:"hmac_secret"`
	MinSeverity string `toml:"min_severity"`
}

// LoadInto reads a TOML config file into v (a pointer to a config struct). It is
// generic so the SIEM adapter can load its extended config with the same helper.
// A missing file is reported as an error; callers decide whether running from
// flags alone is acceptable.
func LoadInto(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return toml.Unmarshal(b, v)
}

// FirstNonEmpty returns the first non-empty argument — the idiom adapters use to
// let a flag override a config-file value (flag first, then file, then "").
func FirstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
