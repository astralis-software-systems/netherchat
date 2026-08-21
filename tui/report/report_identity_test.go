package report

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
	"github.com/salehkreiner/netherchat/tui/record"
)

// AN EMBEDDED ATTESTATION RENDERED AS RAW JSON IN BOTH REPORTS (Phase 2 §F3).
//
// Both timelines fall through to printing e.Body for any kind they do not
// special-case, and an attestation's Body is the artifact's indented JSON. The
// full HTML timeline, the executive HTML timeline and the Markdown timeline all
// did it. That was filed as a CipherSigil-facing theory; Netherchat's own producer
// made it reachable here.
//
// The fix routes through record.IdentityDisplayForEntry, which is D-I's renderer
// with the record's own join in front of it — so a report and a room view and a
// participants panel cannot disagree about what a mark means.

// attestedRecord builds a record whose chain is [decision, identity], and returns
// the issuer key so a test can be the reader who pinned it.
func attestedRecord(t *testing.T) (*record.SealedRecord, ed25519.PublicKey, *attest.IdentityAttestation) {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	ipub, ipriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("issuer key: %v", err)
	}
	ifpr := crypto.Fingerprint(ipub)
	unsigned := attest.NewIdentityAttestation(attest.IdentitySpec{
		Serial:        "acme-0100",
		Subject:       id.Fingerprint(),
		Principal:     "rosa.alvarez@acme.example",
		DisplayName:   "Rosa Alvarez",
		PrincipalType: "person",
		Roles:         []string{"incident-commander"},
		ExpiresAt:     time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
		Algorithm:     attest.AlgorithmEd25519,
		Issuer:        ifpr,
	}, nil, nil)
	att := unsigned.WithSignatures(
		map[string][]byte{ifpr: ed25519.Sign(ipriv, attest.IdentitySigningBytes(unsigned))},
		map[string][]byte{ifpr: ipub},
	)

	author := record.Author{ID: id.Fingerprint(), Name: "alice", Key: id.SignPub, Sign: id.Sign}
	c := record.NewChain()
	if _, err := c.AppendNew(author, record.KindDecision, "", "rolled back to v2.3.1"); err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, err := c.AppendIdentity(author, att); err != nil {
		t.Fatalf("append identity: %v", err)
	}
	head := c.Head()
	sig, err := id.Sign(protocol.SealSigningBytes("ops", head))
	if err != nil {
		t.Fatalf("sign seal: %v", err)
	}
	return record.NewSealedRecord("ops", id.Fingerprint(), c.Entries(), head,
		map[string][]byte{id.Fingerprint(): sig}, map[string][]byte{id.Fingerprint(): id.SignPub}), ipub, att
}

// TestReportsDoNotPrintAnAttestationAsJSON covers all three timelines a reader can
// reach: the full HTML one, the executive HTML one, and Markdown.
func TestReportsDoNotPrintAnAttestationAsJSON(t *testing.T) {
	rec, _, att := attestedRecord(t)
	res, err := record.Verify(rec)
	if err != nil || !res.Valid {
		t.Fatalf("record should verify: err=%v reason=%q", err, res.Reason)
	}
	for _, tc := range []struct{ name, out string }{
		{"html", RenderHTML(rec, res, Options{})},
		{"html --executive", RenderHTML(rec, res, Options{Executive: true})},
		{"markdown", RenderMarkdown(rec, res, Options{})},
	} {
		for _, leak := range []string{"netherchat_identity", "signer_keys", `&#34;algorithm&#34;`, `"algorithm"`} {
			if strings.Contains(tc.out, leak) {
				t.Errorf("%s printed the artifact's raw JSON (%s)", tc.name, leak)
			}
		}
		if !strings.Contains(tc.out, "rosa.alvarez@acme.example") {
			t.Errorf("%s does not say what the credential claims", tc.name)
		}
		if !strings.Contains(tc.out, "◇") {
			t.Errorf("%s does not mark the credential as an unchecked claim", tc.name)
		}
		if strings.Contains(tc.out, "◆") {
			t.Errorf("%s marks a credential as checked; `netherchat report` pins no issuer key", tc.name)
		}
	}
	// The subject key is what the statement is ABOUT, and the full report must show
	// it: a name without the key it was bound to is a name attached to whoever the
	// reader assumes.
	if out := RenderMarkdown(rec, res, Options{}); !strings.Contains(out, att.Subject) {
		t.Errorf("the markdown report does not name the key the credential is about:\n%s", out)
	}
}

// TestAReportRendersAVerifiedBindingWhenTheCALLERSuppliedAKey.
//
// RenderHTML and RenderMarkdown take a *record.VerifyResult, and a caller that ran
// VerifyWithIdentity with a pinned issuer has one carrying bindings. `netherchat
// report` is not that caller and does not pin — but sealedrecord exports these
// renderers, and the Phase 4 consumer IS that caller. A renderer that showed ◇ for
// something its caller had verified would be lying by omission the day it is used,
// so the branch honours the result it is handed rather than assuming nobody
// checked anything.
func TestAReportRendersAVerifiedBindingWhenTheCallerSuppliedAKey(t *testing.T) {
	rec, ipub, _ := attestedRecord(t)
	res, err := record.VerifyWithIdentity(rec, attest.IdentityOptions{
		IssuerKeys: []ed25519.PublicKey{ipub},
		At:         time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("verify with identity: %v", err)
	}
	if len(res.IdentityBindings) == 0 {
		t.Fatal("the fixture produced no binding; this test would prove nothing")
	}
	for _, tc := range []struct{ name, out string }{
		{"html", RenderHTML(rec, res, Options{})},
		{"markdown", RenderMarkdown(rec, res, Options{})},
	} {
		if !strings.Contains(tc.out, "◆") {
			t.Errorf("%s does not mark a binding its caller verified:\n%s", tc.name, tc.out)
		}
		if !strings.Contains(tc.out, "Rosa Alvarez") {
			t.Errorf("%s does not render the name the issuer signed:\n%s", tc.name, tc.out)
		}
	}
}

// TestReportsAreInertForARecordWithoutAnAttestation. The identity branch is
// compiled into both renderers and reachable; a record that carries no credential
// must come out of them unchanged.
func TestReportsAreInertForARecordWithoutAnAttestation(t *testing.T) {
	rec := buildSealed(t)
	res, err := record.Verify(rec)
	if err != nil || !res.Valid {
		t.Fatalf("record should verify: err=%v", err)
	}
	for _, tc := range []struct{ name, out string }{
		{"html", RenderHTML(rec, res, Options{})},
		{"html --executive", RenderHTML(rec, res, Options{Executive: true})},
		{"markdown", RenderMarkdown(rec, res, Options{})},
	} {
		for _, forbidden := range []string{"◇", "◆", "credential", "issuer"} {
			if strings.Contains(strings.ToLower(tc.out), strings.ToLower(forbidden)) {
				t.Errorf("%s mentions %q for a record that carries no attestation", tc.name, forbidden)
			}
		}
	}
}
