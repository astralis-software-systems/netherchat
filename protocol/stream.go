package protocol

// Live log streaming (§2.2). Both opcodes carry a Message envelope sealed under the
// room key, exactly like OpMessage/OpAck — the relay only ever sees ciphertext. A
// stream is a single live-updating block in everyone's TUI rather than a flood of
// messages: each StreamUpdate REPLACES the prior content for its stream_id (the
// payload carries the whole current ring buffer), so there is nothing to persist
// and nothing to back-fill. The relay routes these blind and NEVER writes them to
// the optional history store (only OpMessage is persisted) — streams are live-only.
const (
	OpStreamUpdate Op = "stream_update" // streamer -> room: the current ring buffer for a stream
	OpStreamEnd    Op = "stream_end"    // streamer -> room: the stream is over; the block goes static
)

// Stream-end reasons carried in StreamEndBody.Reason.
const (
	StreamEndDisconnected = "sender_disconnected" // the pipe closed / the sender left
	StreamEndManual       = "manual_stop"         // /stream stop
	StreamEndScuttle      = "scuttle"             // the room scuttled out from under the stream
)

// StreamUpdateBody is the decrypted payload of an OpStreamUpdate Message. Lines is
// the ENTIRE current ring buffer (capped client-side), not a delta — receivers
// replace the block content wholesale, which makes ordering trivial and back-fill
// unnecessary. Seq is monotonic so a late/duplicate update can be ignored.
type StreamUpdateBody struct {
	StreamID string   `json:"stream_id"` // 16 hex chars, unique per stream session
	Name     string   `json:"name"`      // source label for the block header (e.g. "app.log")
	Lines    []string `json:"lines"`     // the current ring-buffer contents
	Seq      uint64   `json:"seq"`       // monotonically increasing
	TS       int64    `json:"ts"`        // unix seconds
}

// StreamEndBody is the decrypted payload of an OpStreamEnd Message.
type StreamEndBody struct {
	StreamID string `json:"stream_id"`
	Reason   string `json:"reason"` // one of StreamEnd*
}
