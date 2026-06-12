package connector

import (
	"fmt"
	"io"
	"time"
)

// ParseRFC3339 returns the unix-second timestamp for an RFC3339 string, or 0 when
// the input is absent or unparseable (the relay treats ts as optional metadata).
func ParseRFC3339(s string) int64 {
	if s == "" {
		return 0
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.Unix()
	}
	return 0
}

// PrintResult writes a human-readable line about an accepted alert: the spawned
// war room and its invite links, or that no route matched.
func PrintResult(w io.Writer, ref string, res Result) {
	if !res.Spawned {
		fmt.Fprintf(w, "%s → accepted (no route matched; no room spawned)\n", ref)
		return
	}
	fmt.Fprintf(w, "%s → war room %s spawned", ref, res.Room)
	if len(res.Links) > 0 {
		fmt.Fprintf(w, " (%d invite link(s))", len(res.Links))
	}
	fmt.Fprintln(w)
	for name, link := range res.Links {
		fmt.Fprintf(w, "    %s: %s\n", name, link)
	}
}
