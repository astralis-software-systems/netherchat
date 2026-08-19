// Package attest holds Netherchat's portable, offline-verifiable attestation
// artifacts: the signed roster (§1.4) and the scuttle receipt (§1.5). Both are
// pure crypto over identity keys (Ed25519) and a deterministic hash, written so
// that `netherchat verify <file>.json` needs nothing but the file.
//
// It is presentation/verification logic only: it imports the protocol (for the
// canonical signing-byte layouts) and the client crypto package (for the SSH
// fingerprint), and nothing about the network, the server, or message transport.
// Like tui/record it lives under tui/ so it may link tui/internal/crypto.
package attest

import (
	"encoding/base64"
	"sort"
	"time"
)

// nowRFC3339 is the timestamp format shared by both artifacts (UTC, RFC 3339).
func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

// b64map base64-encodes the values of a fingerprint->bytes map, for the
// signatures{} and signer_keys{} JSON objects.
func b64map(m map[string][]byte) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = base64.StdEncoding.EncodeToString(v)
	}
	return out
}

// sortedKeys returns a map's fingerprint keys in sorted order, so a verifier
// that returns on the first failure names the SAME signature on every run. Go
// randomizes map iteration, and a verifier whose reported reason changes between
// runs on identical input gives an operator nothing to act on and a test nothing
// to assert.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
