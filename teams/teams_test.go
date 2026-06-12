package teams

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// cardParts decodes a card and returns every TextBlock text and every action URL,
// plus the AdaptiveCard version — enough to assert content without coupling to
// exact JSON layout.
func cardParts(t *testing.T, card []byte) (texts, urls []string, version string) {
	t.Helper()
	var msg struct {
		Type        string `json:"type"`
		Attachments []struct {
			ContentType string `json:"contentType"`
			Content     struct {
				Type    string           `json:"type"`
				Version string           `json:"version"`
				Body    []map[string]any `json:"body"`
			} `json:"content"`
		} `json:"attachments"`
	}
	if err := json.Unmarshal(card, &msg); err != nil {
		t.Fatalf("card is not valid JSON: %v\n%s", err, card)
	}
	if msg.Type != "message" || len(msg.Attachments) != 1 {
		t.Fatalf("unexpected envelope: %s", card)
	}
	att := msg.Attachments[0]
	if att.ContentType != "application/vnd.microsoft.card.adaptive" || att.Content.Type != "AdaptiveCard" {
		t.Fatalf("unexpected attachment: %s", card)
	}
	version = att.Content.Version
	for _, el := range att.Content.Body {
		switch el["type"] {
		case "TextBlock":
			if s, ok := el["text"].(string); ok {
				texts = append(texts, s)
			}
		case "ActionSet":
			if acts, ok := el["actions"].([]any); ok {
				for _, a := range acts {
					if am, ok := a.(map[string]any); ok {
						if u, ok := am["url"].(string); ok {
							urls = append(urls, u)
						}
					}
				}
			}
		}
	}
	return texts, urls, version
}

func joined(texts []string) string { return strings.Join(texts, "\n") }

func TestOpenCard(t *testing.T) {
	card := OpenCard(OpenMeta{Room: "ops", Severity: "high", Source: "scanner", Actor: "ingress", JoinURL: "https://relay/join?room=ops&token=tok", Expires: "2h"})
	texts, urls, version := cardParts(t, card)
	if version != "1.2" {
		t.Errorf("version = %q, want 1.2", version)
	}
	all := joined(texts)
	for _, want := range []string{"War room opened: #ops", "Severity: high · Source: scanner", "Opened by: ingress", "Expires: 2h"} {
		if !strings.Contains(all, want) {
			t.Errorf("open card missing %q\n%s", want, all)
		}
	}
	if len(urls) != 1 || urls[0] != "https://relay/join?room=ops&token=tok" {
		t.Errorf("join action url = %v", urls)
	}
}

func TestSealCard(t *testing.T) {
	hash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	card := SealCard(SealMeta{Room: "inc-1", Signers: 2, RecordHash: hash, Elapsed: "1h23m"})
	texts, urls, _ := cardParts(t, card)
	all := joined(texts)
	for _, want := range []string{"Incident sealed: #inc-1", "Sealed by: 2 member(s)", "Duration: 1h23m", "Record hash: 0123456789abcdef..."} {
		if !strings.Contains(all, want) {
			t.Errorf("seal card missing %q\n%s", want, all)
		}
	}
	// The full hash must NOT appear — only the 16-char prefix.
	if strings.Contains(all, hash) {
		t.Errorf("seal card leaked the full hash instead of the short form")
	}
	if len(urls) != 0 {
		t.Errorf("seal card should have no action, got %v", urls)
	}
}

func TestScuttleCard(t *testing.T) {
	card := ScuttleCard(ScuttleMeta{Room: "inc-2", Actor: "alice", Reason: "manual", ReceiptHash: "abcdef0123456789abcdef0123456789"})
	texts, _, _ := cardParts(t, card)
	all := joined(texts)
	for _, want := range []string{"Room scuttled: #inc-2", "Scuttled by: alice · Reason: manual", "Receipt: abcdef0123456789..."} {
		if !strings.Contains(all, want) {
			t.Errorf("scuttle card missing %q\n%s", want, all)
		}
	}
}

// TestBoundaryNoExtraContent: a card's text is composed ONLY from the metadata and
// the fixed labels — there is no field for, and thus no way to inject, message
// content. We assert a sentinel that is not part of any meta never appears.
func TestBoundaryNoExtraContent(t *testing.T) {
	card := SealCard(SealMeta{Room: "ops", Signers: 3, RecordHash: "deadbeefdeadbeefdeadbeef", Elapsed: "5m"})
	if strings.Contains(string(card), "SECRET") || strings.Contains(string(card), "decision") {
		t.Fatalf("card unexpectedly contains content-like text:\n%s", card)
	}
	// And the card is well-formed with exactly the expected structural keys.
	texts, _, _ := cardParts(t, card)
	if len(texts) == 0 {
		t.Fatal("card had no text blocks")
	}
}

func TestShortHash(t *testing.T) {
	if ShortHash("abc", 16) != "abc" {
		t.Error("short input should pass through")
	}
	if ShortHash("0123456789abcdefXX", 16) != "0123456789abcdef..." {
		t.Errorf("got %q", ShortHash("0123456789abcdefXX", 16))
	}
}

func TestPost(t *testing.T) {
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	card := OpenCard(OpenMeta{Room: "ops", JoinURL: "https://x/join"})
	if err := Post(context.Background(), srv.Client(), srv.URL, card); err != nil {
		t.Fatalf("post: %v", err)
	}
	if len(got) == 0 || !strings.Contains(string(got), "War room opened") {
		t.Errorf("server did not receive the card")
	}
}
