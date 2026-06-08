// Package clip puts text on the system clipboard for the TUI's /copy command. It
// tries mechanisms in order so it works across platforms and degrades gracefully
// where no clipboard is reachable (e.g. headless Linux): a native pure-Go path on
// Windows, OS tools elsewhere, and stdout as a last resort.
package clip

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"

	"golang.design/x/clipboard"
)

// ErrUnavailable means no real clipboard mechanism succeeded.
var ErrUnavailable = errors.New("no clipboard mechanism available")

// writer is one clipboard mechanism; write returns nil on success.
type writer struct {
	name  string
	write func(text string) error
}

// Copy puts text on the system clipboard and returns the name of the mechanism
// that worked. The chain is: the native clipboard (golang.design/x/clipboard —
// pure Go on Windows; needs cgo on Linux/macOS, where it fails over), then OS
// tools (powershell Set-Clipboard / pbcopy / xclip / xsel). If every real
// clipboard is unavailable it prints text to stdout as a last resort — so it
// still lands in terminal scrollback — and returns "stdout".
func Copy(text string) string {
	if method, err := copyVia(text, platformWriters()); err == nil {
		return method
	}
	fmt.Fprintln(os.Stdout, text)
	return "stdout"
}

// copyVia runs writers in order and returns the name of the first that succeeds,
// or ErrUnavailable if all fail. It is the testable core of the fallback chain.
func copyVia(text string, ws []writer) (string, error) {
	for _, w := range ws {
		if w.write == nil {
			continue
		}
		if err := w.write(text); err == nil {
			return w.name, nil
		}
	}
	return "", ErrUnavailable
}

// platformWriters is the ordered clipboard chain for the current OS.
func platformWriters() []writer {
	ws := []writer{{name: "native", write: nativeWrite}}
	switch runtime.GOOS {
	case "windows":
		// ReadToEnd preserves the exact text (including newlines) for Set-Clipboard.
		ws = append(ws, writer{"powershell", pipeWriter("powershell",
			"-NoProfile", "-NonInteractive", "-Command", "[Console]::In.ReadToEnd() | Set-Clipboard")})
	case "darwin":
		ws = append(ws, writer{"pbcopy", pipeWriter("pbcopy")})
	default: // linux, *bsd
		ws = append(ws,
			writer{"xclip", pipeWriter("xclip", "-selection", "clipboard")},
			writer{"xsel", pipeWriter("xsel", "--clipboard", "--input")},
		)
	}
	return ws
}

// initOnce caches the one-time native-clipboard initialization. On a build or
// platform where it is unavailable (e.g. CGO_ENABLED=0 on Linux), initErr is set
// and the native writer always fails over to the OS tools.
var (
	initOnce sync.Once
	initErr  error
)

func nativeWrite(text string) error {
	initOnce.Do(func() { initErr = clipboard.Init() })
	if initErr != nil {
		return initErr
	}
	clipboard.Write(clipboard.FmtText, []byte(text))
	return nil
}

// pipeWriter returns a writer that pipes text to a command's stdin. It checks the
// command exists first, so a missing tool fails fast and the chain continues.
func pipeWriter(name string, args ...string) func(string) error {
	return func(text string) error {
		if _, err := exec.LookPath(name); err != nil {
			return err
		}
		cmd := exec.Command(name, args...)
		cmd.Stdin = strings.NewReader(text)
		return cmd.Run()
	}
}
