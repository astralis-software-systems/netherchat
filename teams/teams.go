// Package teams renders Microsoft Teams Adaptive Cards for the Netherchat Teams
// connector (NC-3) and posts them to an incoming webhook. It is pure: stdlib only,
// no Teams SDK — a card is plain JSON and delivery is a plain HTTPS POST.
//
// THE BOUNDARY LAW IS STRUCTURAL HERE. Each card builder takes a small metadata
// struct whose fields are exactly what may cross to Teams — a room name, severity,
// an actor, a one-time join URL, a record/receipt hash, an elapsed time, a reason.
// There is no field for message content, decision text, or a transcript, so a card
// cannot carry any. Teams sees pointers and metadata; never content.
package teams

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// --- card metadata (the complete set of values that may reach Teams) ----------

// OpenMeta is the metadata for a "war room opened" card. JoinURL is a one-time
// pointer; nothing here is room content.
type OpenMeta struct {
	Room     string
	Severity string
	Source   string
	Actor    string
	JoinURL  string
	Expires  string
}

// SealMeta is the metadata for an "incident sealed" card. RecordHash is the chain
// head hash; the decisions/transcript it attests are NEVER included.
type SealMeta struct {
	Room       string
	Signers    int
	RecordHash string
	Elapsed    string
}

// ScuttleMeta is the metadata for a "room scuttled" card.
type ScuttleMeta struct {
	Room        string
	Actor       string
	Reason      string
	ReceiptHash string
}

// --- card builders ------------------------------------------------------------

// OpenCard renders the "war room opened" card with a one-time Join button.
func OpenCard(m OpenMeta) []byte {
	var lines []string
	if sev := joinKV("Severity", m.Severity, "Source", m.Source); sev != "" {
		lines = append(lines, sev)
	}
	if m.Actor != "" {
		lines = append(lines, "Opened by: "+m.Actor)
	}
	if m.Expires != "" {
		lines = append(lines, "Expires: "+m.Expires)
	}
	var act *action
	if m.JoinURL != "" {
		act = &action{Type: "Action.OpenUrl", Title: "Join room", URL: m.JoinURL}
	}
	return buildCard("⚡ War room opened: #"+m.Room, lines, act)
}

// SealCard renders the "incident sealed" card. It carries the chain head hash for
// cross-checking a sealed record — never the decisions themselves.
func SealCard(m SealMeta) []byte {
	lines := []string{fmt.Sprintf("Sealed by: %d member(s)", m.Signers)}
	if m.Elapsed != "" {
		lines = append(lines, "Duration: "+m.Elapsed)
	}
	lines = append(lines,
		"Record hash: "+ShortHash(m.RecordHash, 16),
		"Verify the sealed record offline with: netherchat verify record.json",
	)
	return buildCard("🔒 Incident sealed: #"+m.Room, lines, nil)
}

// ScuttleCard renders the "room scuttled" card.
func ScuttleCard(m ScuttleMeta) []byte {
	line := "Scuttled by: " + dash(m.Actor)
	if m.Reason != "" {
		line += " · Reason: " + m.Reason
	}
	lines := []string{line}
	if m.ReceiptHash != "" {
		lines = append(lines, "Receipt: "+ShortHash(m.ReceiptHash, 16))
	}
	return buildCard("💨 Room scuttled: #"+m.Room, lines, nil)
}

// --- delivery -----------------------------------------------------------------

// Post delivers a card to a Teams incoming webhook via a plain HTTPS POST. A nil
// client uses a 10s-timeout default.
func Post(ctx context.Context, hc *http.Client, webhookURL string, card []byte) error {
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(card))
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
		return fmt.Errorf("teams webhook returned %s", resp.Status)
	}
	return nil
}

// TextCard renders a plain Teams message (not an Adaptive Card) carrying only the
// given text — used for simple bot replies such as an acknowledgement or a usage
// hint. It carries no card actions and no metadata beyond the text.
func TextCard(text string) []byte {
	b, _ := json.Marshal(struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}{Type: "message", Text: text})
	return b
}

// ShortHash returns the first n characters of h with an ellipsis, or h unchanged
// when it is already short. Used to show a record/receipt hash as a reference.
func ShortHash(h string, n int) string {
	if len(h) <= n {
		return h
	}
	return h[:n] + "..."
}

// --- internal Adaptive Card model (1.2) ---------------------------------------
//
// Built from typed structs and json.Marshal so every value is correctly escaped
// and the body can ONLY contain the text blocks and the single optional action we
// assemble — there is no path to inject arbitrary fields.

type message struct {
	Type        string       `json:"type"`
	Attachments []attachment `json:"attachments"`
}

type attachment struct {
	ContentType string  `json:"contentType"`
	Content     content `json:"content"`
}

type content struct {
	Schema  string `json:"$schema"`
	Type    string `json:"type"`
	Version string `json:"version"`
	Body    []any  `json:"body"`
}

type textBlock struct {
	Type   string `json:"type"`
	Text   string `json:"text"`
	Size   string `json:"size,omitempty"`
	Weight string `json:"weight,omitempty"`
	Wrap   bool   `json:"wrap,omitempty"`
}

type actionSet struct {
	Type    string   `json:"type"`
	Actions []action `json:"actions"`
}

type action struct {
	Type  string `json:"type"`
	Title string `json:"title"`
	URL   string `json:"url"`
}

func buildCard(title string, lines []string, act *action) []byte {
	body := []any{textBlock{Type: "TextBlock", Text: title, Size: "Large", Weight: "Bolder", Wrap: true}}
	for _, l := range lines {
		body = append(body, textBlock{Type: "TextBlock", Text: l, Wrap: true})
	}
	if act != nil {
		body = append(body, actionSet{Type: "ActionSet", Actions: []action{*act}})
	}
	msg := message{
		Type: "message",
		Attachments: []attachment{{
			ContentType: "application/vnd.microsoft.card.adaptive",
			Content: content{
				Schema:  "http://adaptivecards.io/schemas/adaptive-card.json",
				Type:    "AdaptiveCard",
				Version: "1.2",
				Body:    body,
			},
		}},
	}
	b, _ := json.MarshalIndent(msg, "", "  ")
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
