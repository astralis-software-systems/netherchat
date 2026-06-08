package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/salehkreiner/netherchat/tui/client"
)

// runSend implements /send <path> (§2.3): relay a local artifact to the room as a
// secure, end-to-end-encrypted, relay-blind transfer. SendFile validates and
// returns immediately; progress and the outcome arrive as events.
func (m *Model) runSend(r *room, arg string) {
	if !m.connected(r) {
		return
	}
	path := strings.TrimSpace(arg)
	if path == "" {
		m.addError("usage: /send <path>   (relay a file as a secure artifact transfer)")
		return
	}
	if err := r.client.SendFile(path); err != nil {
		m.addError("transfer failed: " + err.Error())
		return
	}
	m.addSystem("📎 sending " + filepath.Base(path) + " …")
}

// renderFileOffer / renderFileComplete build the receiver-side system lines.
func renderFileOffer(e client.EvFileOffer) string {
	return fmt.Sprintf("📎 %s is sending %s (%s)…", e.From, e.Filename, humanBytes(e.Size))
}

func renderFileComplete(e client.EvFileComplete) string {
	if e.OK {
		return fmt.Sprintf("✓ %s received from %s (%s)", e.Filename, e.From, humanBytes(e.Size))
	}
	return fmt.Sprintf("✗ transfer of %s failed: %s", e.Filename, e.Err)
}

// completeFilePath tab-completes a local path for /send: it lists entries in the
// directory implied by the prefix, marking directories with a trailing slash so
// completion can descend.
func completeFilePath(prefix string) []string {
	dir, base := filepath.Split(prefix)
	searchDir := dir
	if searchDir == "" {
		searchDir = "."
	}
	entries, err := os.ReadDir(searchDir)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, base) {
			continue
		}
		full := dir + name
		if e.IsDir() {
			full += "/"
		}
		out = append(out, full)
	}
	return out
}

// humanBytes renders a byte count like "4.2 MB" for the transfer system lines.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}
