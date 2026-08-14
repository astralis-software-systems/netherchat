package app

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/crypto/ssh"
)

// TrustEntry mirrors a [[trust]] block from netherchat.toml. It is evaluated
// entirely client-side; the relay never sees it or participates in any trust
// decision.
type TrustEntry struct {
	Handle  string
	Fpr     string // optional pinned "SHA256:…" fingerprint
	KeysURL string // optional published-key source, e.g. https://github.com/<h>.keys
}

// runWhois implements /whois. With no argument it shows your own identity; with a
// @handle it shows that member's fingerprint and pin status, and (if a keys_url
// is configured) kicks off a CLIENT-SIDE fetch to check the published keys.
func (m *Model) runWhois(arg string) tea.Cmd {
	handle := strings.TrimPrefix(strings.TrimSpace(arg), "@")
	if handle == "" {
		m.addSystem(m.whoisSelfText())
		return nil
	}
	r := m.activeRoom()
	if !m.connected(r) {
		return nil
	}
	_, fpr, ok := r.client.LookupMember(handle)
	if !ok {
		m.addError("no member named @" + handle + " in this room")
		return nil
	}
	entry, has := m.trustFor(handle)

	var b strings.Builder
	b.WriteString("@" + handle + "\n")
	b.WriteString("  fingerprint: " + fpr + "\n")
	b.WriteString("  pin:         " + pinStatus(entry, has, fpr))
	m.addSystem(b.String())

	if has && entry.KeysURL != "" {
		m.addSystem("  fetching " + entry.KeysURL + " (client-side)…")
		return fetchKeys(handle, entry.KeysURL, fpr)
	}
	return nil
}

// whoisSelfText is the no-argument /whois: your own source, fingerprint, pin.
func (m *Model) whoisSelfText() string {
	var b strings.Builder
	b.WriteString("you (" + m.name + ")\n")
	b.WriteString("  fingerprint: " + m.fingerprint + "\n")
	b.WriteString("  identity:    " + m.sourceLabel() + "\n")
	entry, has := m.trustFor(m.name)
	b.WriteString("  pin:         " + pinStatus(entry, has, m.fingerprint))
	return b.String()
}

// trustFor returns the trust entry whose handle matches name (case-insensitive).
func (m *Model) trustFor(handle string) (TrustEntry, bool) {
	for _, t := range m.trust {
		if strings.EqualFold(t.Handle, handle) {
			return t, true
		}
	}
	return TrustEntry{}, false
}

// pinStatus evaluates a fingerprint against a trust entry's pinned fingerprint.
func pinStatus(entry TrustEntry, has bool, fpr string) string {
	if !has || entry.Fpr == "" {
		return "unpinned ✗"
	}
	if entry.Fpr == fpr {
		return "pinned ✓"
	}
	return "MISMATCH ✗  (pinned " + entry.Fpr + ")"
}

// whoisFetchMsg carries the result of a client-side published-key fetch.
type whoisFetchMsg struct {
	handle string
	url    string
	found  bool
	count  int
	err    error
}

// fetchKeys GETs an authorized_keys list (the github.com/<handle>.keys pattern)
// and reports whether target appears among the published key fingerprints. The
// fetch runs entirely in this client — the relay never participates.
func fetchKeys(handle, url, target string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return whoisFetchMsg{handle: handle, url: url, err: err}
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return whoisFetchMsg{handle: handle, url: url, err: err}
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return whoisFetchMsg{handle: handle, url: url, err: fmt.Errorf("HTTP %d", resp.StatusCode)}
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

		count, found := 0, false
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			pk, _, _, _, perr := ssh.ParseAuthorizedKey([]byte(line))
			if perr != nil {
				continue
			}
			count++
			if ssh.FingerprintSHA256(pk) == target {
				found = true
			}
		}
		return whoisFetchMsg{handle: handle, url: url, found: found, count: count}
	}
}

// shortFpr abbreviates an "SHA256:…" fingerprint for inline display.
func shortFpr(fpr string) string {
	const prefix = "SHA256:"
	if strings.HasPrefix(fpr, prefix) {
		body := fpr[len(prefix):]
		if len(body) > 10 {
			body = body[:10] + "…"
		}
		return prefix + body
	}
	if len(fpr) > 14 {
		return fpr[:14] + "…"
	}
	return fpr
}
