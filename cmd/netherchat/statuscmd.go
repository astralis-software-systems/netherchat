package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/salehkreiner/netherchat/tui/statusline"
)

// statusCmd implements `netherchat status` (§2.3): a compact, glanceable segment of
// the active war room for a tmux status line, a starship custom module, or a shell
// prompt. It reads ONLY the local state file the running TUI writes — it never
// connects to a server — so it returns instantly. With no client running (no state
// file) it prints nothing and exits 0, so a prompt shows nothing when there is no
// war room open.
func statusCmd(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	format := fs.String("format", "plain", "segment format: plain | tmux | starship")
	jsonMode := fs.Bool("json", false, "emit the full room state as JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netherchat status [--format plain|tmux|starship] [--json]")
		fmt.Fprintln(os.Stderr, "\nEmits a compact war-room segment from local client state (no network).")
		fmt.Fprintln(os.Stderr, "Empty output and exit 0 when no client is running. See docs/commands.md.")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	path, err := statusline.DefaultPath()
	if err != nil {
		return // no discoverable state path → silent, exit 0
	}
	st, exists, err := statusline.Read(path)
	if err != nil || !exists {
		return // no client running (or unreadable state) → empty output, exit 0
	}

	if *jsonMode {
		fmt.Println(statusline.JSON(st))
		return
	}
	if seg := statusline.Format(st, *format); seg != "" {
		fmt.Println(seg)
	}
}
