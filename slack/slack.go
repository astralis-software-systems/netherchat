// Package slack renders Slack Block Kit messages for the Netherchat Slack connector
// (NC-5) and posts them to an incoming webhook. It is pure: stdlib only, no Slack
// SDK — a Block Kit message is plain JSON and delivery is a plain HTTPS POST. It is
// the Slack-native twin of the teams package; the role and the guardrail are
// identical.
//
// THE BOUNDARY LAW IS STRUCTURAL HERE. Each message builder takes a small metadata
// struct whose fields are exactly what may cross to Slack — a room name, severity,
// a source, an actor, a one-time join URL, a record/receipt hash, an elapsed time,
// a reason. There is no field for message content, decision text, or a transcript,
// so a message cannot carry any. Slack sees pointers and metadata; never content.
package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// --- message metadata (the complete set of values that may reach Slack) --------

// OpenMeta is the metadata for a "war room opened" message. JoinURL is a one-time
// pointer; nothing here is room content.
type OpenMeta struct {
	Room     string
	Severity string
	Source   string
	JoinURL  string
	Expires  string
}

// SealMeta is the metadata for an "incident sealed" message. RecordHash is the
// chain head hash; the decisions/transcript it attests are NEVER included.
type SealMeta struct {
	Room       string
	Signers    int
	RecordHash string
	Elapsed    string
}

// ScuttleMeta is the metadata for a "room scuttled" message.
type ScuttleMeta struct {
	Room        string
	Actor       string
	Reason      string
	ReceiptHash string
}

// --- message builders (webhook delivery) ---------------------------------------

// OpenMessage renders the "war room opened" Block Kit message with a one-time join
// link, for delivery to an incoming webhook.
func OpenMessage(m OpenMeta) []byte {
	return marshal(blockMessage{Text: openTitle(m.Room), Blocks: openBlocks(m)})
}

// SealMessage renders the "incident sealed" message. It carries the chain head hash
// for cross-checking a sealed record — never the decisions themselves.
func SealMessage(m SealMeta) []byte {
	return marshal(blockMessage{Text: sealTitle(m.Room), Blocks: sealBlocks(m)})
}

// ScuttleMessage renders the "room scuttled" message.
func ScuttleMessage(m ScuttleMeta) []byte {
	return marshal(blockMessage{Text: scuttleTitle(m.Room), Blocks: scuttleBlocks(m)})
}

// --- slash-command responses (ephemeral, for the bot) --------------------------

// OpenResponse renders the open message as an ephemeral slash-command response —
// visible only to the user who invoked the command, never posted to the channel.
func OpenResponse(m OpenMeta) []byte {
	return marshal(blockMessage{ResponseType: "ephemeral", Text: openTitle(m.Room), Blocks: openBlocks(m)})
}

// TextResponse renders a plain ephemeral slash-command reply (an error or usage
// hint). It carries only the given text — no blocks, no metadata beyond the text.
func TextResponse(text string) []byte {
	return marshal(blockMessage{ResponseType: "ephemeral", Text: text})
}

// --- delivery ------------------------------------------------------------------

// Post delivers a message to a Slack incoming webhook via a plain HTTPS POST. A nil
// client uses a 10s-timeout default.
func Post(ctx context.Context, hc *http.Client, webhookURL string, msg []byte) error {
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(msg))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("slack webhook returned %s", resp.Status)
	}
	return nil
}

// ShortHash returns the first n characters of h with an ellipsis, or h unchanged
// when it is already short. Used to show a record/receipt hash as a reference.
func ShortHash(h string, n int) string {
	if len(h) <= n {
		return h
	}
	return h[:n] + "..."
}

// --- block assembly ------------------------------------------------------------

func openTitle(room string) string    { return "⚡ War room opened: #" + room }
func sealTitle(room string) string    { return "🔒 Incident sealed: #" + room }
func scuttleTitle(room string) string { return "💨 Room scuttled: #" + room }

// openBlocks builds the three documented lines: title, "Severity · Source", and the
// one-time join line. Empty values are skipped.
func openBlocks(m OpenMeta) []block {
	lines := []string{joinKV("Severity", m.Severity, "Source", m.Source)}
	if join := joinLine(m.JoinURL, m.Expires); join != "" {
		lines = append(lines, join)
	}
	return blocksFor(openTitle(m.Room), lines)
}

func sealBlocks(m SealMeta) []block {
	first := fmt.Sprintf("Sealed by %d member(s)", m.Signers)
	if m.Elapsed != "" {
		first += " · Duration: " + m.Elapsed
	}
	lines := []string{
		first,
		"Verify: netherchat verify · Hash: " + ShortHash(m.RecordHash, 16),
	}
	return blocksFor(sealTitle(m.Room), lines)
}

func scuttleBlocks(m ScuttleMeta) []block {
	line := "By: " + dash(m.Actor)
	if m.Reason != "" {
		line += " · Reason: " + m.Reason
	}
	lines := []string{line}
	if m.ReceiptHash != "" {
		lines = append(lines, "Receipt: "+ShortHash(m.ReceiptHash, 16))
	}
	return blocksFor(scuttleTitle(m.Room), lines)
}

// joinLine renders "Join (one-time): <url> · Expires: <ttl>", skipping empties.
func joinLine(url, expires string) string {
	if url == "" {
		if expires == "" {
			return ""
		}
		return "Expires: " + expires
	}
	s := "Join (one-time): " + url
	if expires != "" {
		s += " · Expires: " + expires
	}
	return s
}

// --- internal Block Kit model --------------------------------------------------
//
// Built from typed structs and json.Marshal so every value is correctly escaped and
// the body can ONLY contain the header and section text blocks we assemble — there
// is no path to inject arbitrary fields, and there is no field for room content.

type blockMessage struct {
	ResponseType string  `json:"response_type,omitempty"`
	Text         string  `json:"text,omitempty"` // notification fallback / plain reply
	Blocks       []block `json:"blocks,omitempty"`
}

type block struct {
	Type string   `json:"type"`
	Text *textObj `json:"text,omitempty"`
}

type textObj struct {
	Type  string `json:"type"` // "plain_text" | "mrkdwn"
	Text  string `json:"text"`
	Emoji bool   `json:"emoji,omitempty"`
}

// blocksFor builds a header block for the title and one section block per line.
func blocksFor(title string, lines []string) []block {
	blocks := []block{{Type: "header", Text: &textObj{Type: "plain_text", Text: title, Emoji: true}}}
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		blocks = append(blocks, block{Type: "section", Text: &textObj{Type: "mrkdwn", Text: l}})
	}
	return blocks
}

func marshal(m blockMessage) []byte {
	b, _ := json.MarshalIndent(m, "", "  ")
	return b
}

// joinKV renders "k1: v1 · k2: v2", skipping empties.
func joinKV(k1, v1, k2, v2 string) string {
	s := ""
	if v1 != "" {
		s = k1 + ": " + v1
	}
	if v2 != "" {
		if s != "" {
			s += " · "
		}
		s += k2 + ": " + v2
	}
	return s
}

func dash(s string) string {
	if s == "" {
		return "(unknown)"
	}
	return s
}
