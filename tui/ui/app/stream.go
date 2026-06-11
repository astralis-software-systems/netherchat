package app

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
)

// streamSender is our OWN outbound /stream (a tailed file, §2.2). Stopping it
// cancels the tail goroutine and the client.Stream driver, which sends a StreamEnd.
type streamSender struct {
	source string
	cancel context.CancelFunc
}

// stopActiveStream stops the room's outbound /stream, if any, ending it with reason.
func (r *room) stopActiveStream(reason string) {
	if r.activeStream != nil {
		r.activeStream.cancel()
		r.activeStream = nil
	}
}

// renderStreamBlock renders a received stream as a collapsible, log-level-colored
// block (§2.2). The header names the source and the streamer; an ended stream
// becomes static with a "stream ended" header.
func (m *Model) renderStreamBlock(sv *streamView) string {
	who := sv.from
	if sv.self {
		who = "you"
	}
	label := "stream: " + sv.name + " (" + who + ")"
	if sv.ended {
		label = "stream ended: " + sv.name + " (" + who + ")"
	}
	expanded := m.streamExpanded[sv.id]
	return m.renderer.RenderStream(label, sv.lines, expanded, "stream-"+strconv.Itoa(sv.num))
}

// runStream implements the /stream slash command (§2.2):
//
//	/stream <path>   tail a local file into the room as a live block
//	/stream stop     stop the active stream for this room
func (m *Model) runStream(r *room, arg string) {
	arg = strings.TrimSpace(arg)
	if r == nil {
		return
	}
	switch {
	case arg == "":
		m.addError("usage: /stream <local-file-path>   |   /stream stop")
		return
	case strings.EqualFold(arg, "stop"):
		if r.activeStream == nil {
			m.addError("no active stream in this room")
			return
		}
		m.addSystem("stopping stream of " + r.activeStream.source)
		r.stopActiveStream(protocol.StreamEndManual)
		return
	}

	if !m.connected(r) {
		return
	}
	if !r.keyReady {
		m.addError("encryption not ready yet — try again in a moment")
		return
	}
	if r.activeStream != nil {
		m.addError("already streaming " + r.activeStream.source + " here — /stream stop first")
		return
	}
	path := arg
	f, err := os.Open(path)
	if err != nil {
		m.addError("cannot open " + path + ": " + err.Error())
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	r.activeStream = &streamSender{source: filepath.Base(path), cancel: cancel}
	st := r.client.NewStream(filepath.Base(path), m.streamLines)
	lines := make(chan string, 256)
	go tailFile(ctx, f, lines)                      // follow the file → lines
	go st.Run(ctx, lines, protocol.StreamEndManual) // lines → ring buffer → room
	m.addSystem("streaming " + path + " to #" + r.name + " — /stream stop to end")
}

// tailFile follows f like `tail -f`: it streams the lines already present, then
// polls for appended lines until ctx is cancelled. It closes lines on exit so the
// stream driver ends cleanly.
func tailFile(ctx context.Context, f *os.File, lines chan<- string) {
	defer close(lines)
	defer f.Close()

	reader := bufio.NewReader(f)
	var pending strings.Builder
	emit := func(s string) bool {
		select {
		case lines <- s:
			return true
		case <-ctx.Done():
			return false
		}
	}
	for {
		chunk, err := reader.ReadString('\n')
		if len(chunk) > 0 {
			pending.WriteString(chunk)
			if strings.HasSuffix(chunk, "\n") {
				if !emit(strings.TrimRight(pending.String(), "\r\n")) {
					return
				}
				pending.Reset()
			}
		}
		if err == io.EOF {
			select {
			case <-ctx.Done():
				return
			case <-time.After(250 * time.Millisecond): // wait for more to be appended
			}
			continue
		}
		if err != nil {
			return
		}
	}
}
