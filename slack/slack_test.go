package slack

import (
	"encoding/json"
	"strings"
	"testing"
)

// decode parses a Block Kit message back into a generic map so tests can assert on
// its structure (and prove only the expected keys exist).
func decode(t *testing.T, msg []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(msg, &m); err != nil {
		t.Fatalf("message is not valid JSON: %v\n%s", err, msg)
	}
	return m
}

// blockTexts returns every text string in the blocks array, for content assertions.
func blockTexts(t *testing.T, m map[string]any) []string {
	t.Helper()
	raw, ok := m["blocks"].([]any)
	if !ok {
		t.Fatalf("message has no blocks array: %v", m)
	}
	var out []string
	for _, b := range raw {
		bm, _ := b.(map[string]any)
		if to, ok := bm["text"].(map[string]any); ok {
			if s, ok := to["text"].(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func TestOpenMessage(t *testing.T) {
	msg := OpenMessage(OpenMeta{
		Room: "inc-1", Severity: "high", Source: "scanner",
		JoinURL: "https://relay/join?room=inc-1&token=tok123", Expires: "2h",
	})
	m := decode(t, msg)
	texts := strings.Join(blockTexts(t, m), "\n")
	for _, want := range []string{
		"⚡ War room opened: #inc-1",
		"Severity: high",
		"Source: scanner",
		"Join (one-time): https://relay/join?room=inc-1&token=tok123",
		"Expires: 2h",
	} {
		if !strings.Contains(texts, want) {
			t.Errorf("open message missing %q\n%s", want, texts)
		}
	}
	// The first block is a header carrying the title.
	first := m["blocks"].([]any)[0].(map[string]any)
	if first["type"] != "header" {
		t.Errorf("first block type = %v, want header", first["type"])
	}
}

func TestSealMessageNoContentLeak(t *testing.T) {
	const fullHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	msg := SealMessage(SealMeta{Room: "inc-1", Signers: 2, RecordHash: fullHash, Elapsed: "1m30s"})
	body := string(msg)
	for _, want := range []string{
		"🔒 Incident sealed: #inc-1",
		"Sealed by 2 member(s)",
		"Duration: 1m30s",
		"Verify: netherchat verify",
		"Hash: 0123456789abcdef...",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("seal message missing %q\n%s", want, body)
		}
	}
	// The full head hash must never appear — only the 16-char prefix.
	if strings.Contains(body, fullHash) {
		t.Fatalf("seal message leaked the full head hash\n%s", body)
	}
}

func TestScuttleMessage(t *testing.T) {
	msg := ScuttleMessage(ScuttleMeta{Room: "inc-1", Actor: "alice", Reason: "manual", ReceiptHash: "abcdef0123456789abcdef0123456789"})
	body := string(msg)
	for _, want := range []string{
		"💨 Room scuttled: #inc-1",
		"By: alice · Reason: manual",
		"Receipt: abcdef0123456789...",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scuttle message missing %q\n%s", want, body)
		}
	}
}

// TestNoContentFieldExists proves the boundary law is structural: there is no
// builder that accepts room content, so even a maliciously constructed call cannot
// place a transcript or decision text into a message. We assert the only top-level
// keys Slack receives are response_type, text (a title/fallback), and blocks.
func TestOnlyExpectedTopLevelKeys(t *testing.T) {
	for _, msg := range [][]byte{
		OpenMessage(OpenMeta{Room: "r", JoinURL: "u"}),
		SealMessage(SealMeta{Room: "r", Signers: 1, RecordHash: "h"}),
		ScuttleMessage(ScuttleMeta{Room: "r", Actor: "a"}),
		OpenResponse(OpenMeta{Room: "r", JoinURL: "u"}),
		TextResponse("hi"),
	} {
		m := decode(t, msg)
		for k := range m {
			switch k {
			case "response_type", "text", "blocks":
			default:
				t.Errorf("unexpected top-level key %q in %s", k, msg)
			}
		}
	}
}

func TestOpenResponseIsEphemeral(t *testing.T) {
	m := decode(t, OpenResponse(OpenMeta{Room: "inc-2", JoinURL: "https://x/join?token=Z", Expires: "1h"}))
	if m["response_type"] != "ephemeral" {
		t.Errorf("response_type = %v, want ephemeral", m["response_type"])
	}
	if !strings.Contains(string(OpenResponse(OpenMeta{Room: "inc-2", JoinURL: "https://x/join?token=Z"})), "token=Z") {
		t.Error("open response missing the join link")
	}
}

func TestShortHash(t *testing.T) {
	if got := ShortHash("0123456789abcdef0123", 16); got != "0123456789abcdef..." {
		t.Errorf("ShortHash = %q", got)
	}
	if got := ShortHash("short", 16); got != "short" {
		t.Errorf("ShortHash(short) = %q", got)
	}
}
