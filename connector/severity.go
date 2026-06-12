package connector

import "strings"

// severityRank orders the canonical severities used across adapters. Higher is
// more severe. Adapters normalize their source's severity into one of these.
var severityRank = map[string]int{
	"info":     0,
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

// SeverityRank returns the ordering rank of a severity (info=0 … critical=4), or
// -1 if it is not one of the canonical values.
func SeverityRank(sev string) int {
	if r, ok := severityRank[strings.ToLower(strings.TrimSpace(sev))]; ok {
		return r
	}
	return -1
}

// MeetsMin reports whether sev is at least min. An empty min disables filtering.
// An UNRECOGNIZED severity passes (fail-open): a detection adapter must never
// silently swallow an alert because of an unexpected severity label — surfacing it
// is safer than dropping it.
func MeetsMin(sev, min string) bool {
	if strings.TrimSpace(min) == "" {
		return true
	}
	rs, rm := SeverityRank(sev), SeverityRank(min)
	if rs < 0 || rm < 0 {
		return true
	}
	return rs >= rm
}

// Truncate caps s at max runes, appending an ellipsis when it must cut, so the
// result is never longer than max (NC-2 keeps summaries to a one-line metadata
// notice). It is rune-aware so it never splits a multi-byte character.
func Truncate(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max <= 3 {
		return string(r[:max])
	}
	return string(r[:max-3]) + "..."
}
