package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/sealedrecord"
	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/output"
)

// These tests drive `netherchat verify` from ARGV — the whole command, not the
// library function underneath it. That is deliberate, and it is the point: the
// library's VerifyWithIdentity was correct and tested from the day it landed,
// and `verify record.json --issuer acme-ca.pub` still checked nothing, because
// the flags were parsed into a struct the record branch never read. A test that
// starts below the flag parse cannot see that; a test that starts at argv
// cannot miss it.

// testIssuer is a test authority: the private half signs attestations, the
// public half is what an operator writes into an --issuer file.
type testIssuer struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	fpr  string
}

func mkTestIssuer(t *testing.T) testIssuer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testIssuer{pub: pub, priv: priv, fpr: sealedrecord.Fingerprint(pub)}
}

// signedAttestation builds an attestation about subject, signed by is, whose
// window closes at expires.
func signedAttestation(t *testing.T, is testIssuer, subject, principal, serial string, expires time.Time) *attest.IdentityAttestation {
	t.Helper()
	unsigned := sealedrecord.NewIdentityAttestation(sealedrecord.IdentitySpec{
		Serial:        serial,
		Subject:       subject,
		Principal:     principal,
		PrincipalType: "person",
		Roles:         []string{"operations", "security"},
		ExpiresAt:     expires.UTC().Format(time.RFC3339),
		Algorithm:     sealedrecord.AlgorithmEd25519,
		Issuer:        is.fpr,
	}, nil, nil)
	sig := ed25519.Sign(is.priv, sealedrecord.IdentitySigningBytes(unsigned))
	return unsigned.WithSignatures(
		map[string][]byte{is.fpr: sig},
		map[string][]byte{is.fpr: is.pub},
	)
}

// writeIssuerFile writes public keys one base64 line each and returns the path —
// exactly what an operator hands to --issuer.
func writeIssuerFile(t *testing.T, keys ...ed25519.PublicKey) string {
	t.Helper()
	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(base64.StdEncoding.EncodeToString(k))
		sb.WriteString("\n")
	}
	p := filepath.Join(t.TempDir(), "issuers.pub")
	if err := os.WriteFile(p, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// testAuthor mints a fresh signing identity, the way a client holds one.
func testAuthor(t *testing.T) sealedrecord.Author {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return sealedrecord.Author{
		ID:   sealedrecord.Fingerprint(pub),
		Name: "alice",
		Key:  pub,
		Sign: func(b []byte) ([]byte, error) { return ed25519.Sign(priv, b), nil },
	}
}

// sealRecordFile writes a sealed record whose chain is one decision entry
// followed by the given attestations — the shape `netherchat attest` produces
// and the shape the manual walkthrough sealed.
func sealRecordFile(t *testing.T, author sealedrecord.Author, atts ...*attest.IdentityAttestation) string {
	t.Helper()
	chain := sealedrecord.NewChain()
	if _, err := chain.AppendNew(author, sealedrecord.KindDecision, "", "rolled back to v2.3.1"); err != nil {
		t.Fatal(err)
	}
	for _, a := range atts {
		if _, err := chain.AppendIdentity(author, a); err != nil {
			t.Fatal(err)
		}
	}
	sealer := sealedrecord.NewSealer("inc-3f9a2b71", author.ID, chain.Entries())
	if err := sealer.Sign(author); err != nil {
		t.Fatal(err)
	}
	rec, err := sealer.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	b, err := rec.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "record.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// attestedRecord is the demo's shape in one call: a record whose sealer carries
// their own credential, and the issuer file that anchors it.
func attestedRecord(t *testing.T, is testIssuer, expires time.Time) (path, subject, issuerFile string) {
	t.Helper()
	author := testAuthor(t)
	att := signedAttestation(t, is, author.ID, "alice.reyes@acme.example", "acme-0001", expires)
	return sealRecordFile(t, author, att), author.ID, writeIssuerFile(t, is.pub)
}

// verifyJSON runs the command and decodes its stdout, failing if the command did
// not emit exactly one JSON object.
func verifyJSON(t *testing.T, args ...string) (map[string]any, int) {
	t.Helper()
	var code int
	out := captureOut(t, func() { code = runVerify(args) })
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("verify %v: stdout is not one JSON object (%v): %s", args, err, out)
	}
	return m, code
}

// outcomesOf pulls the identity_outcomes array, requiring exactly n of them.
func outcomesOf(t *testing.T, m map[string]any, n int) []map[string]any {
	t.Helper()
	raw, _ := m["identity_outcomes"].([]any)
	if len(raw) != n {
		t.Fatalf("identity_outcomes has %d entries, want %d — a failed attestation must be VISIBLE, not absent: %v", len(raw), n, m)
	}
	out := make([]map[string]any, 0, n)
	for _, r := range raw {
		out = append(out, r.(map[string]any))
	}
	return out
}

// TestVerifyRecordWithIssuerSurfacesBindings is the reproduction, as a test. A
// record CARRIES a real attestation; the operator pins the issuer that signed
// it; the bindings must appear. It failed with identity_bindings absent, because
// the record branch called Verify and never VerifyWithIdentity — the flag was
// accepted and dropped, and an operator who pinned an issuer and saw VALID
// concluded the identity had been checked.
func TestVerifyRecordWithIssuerSurfacesBindings(t *testing.T) {
	is := mkTestIssuer(t)
	path, subject, issuerFile := attestedRecord(t, is, time.Now().Add(24*time.Hour))

	m, code := verifyJSON(t, path, "--issuer", issuerFile, "--json")
	if code != 0 {
		t.Fatalf("a sound record must still exit 0, got %d", code)
	}
	if m["valid"] != true {
		t.Fatalf("record must be VALID: %v", m)
	}
	bindings, ok := m["identity_bindings"].(map[string]any)
	if !ok {
		t.Fatalf("--issuer was pinned on a record carrying an attestation and identity_bindings is absent — the flag reached nothing: %v", m)
	}
	got, _ := bindings[subject].([]any)
	if len(got) != 1 {
		t.Fatalf("no binding keyed by the subject fingerprint %s: %v", subject, bindings)
	}
	b := got[0].(map[string]any)
	if b["principal"] != "alice.reyes@acme.example" {
		t.Errorf("principal = %v", b["principal"])
	}
	if vb, _ := b["verified_by"].([]any); len(vb) != 1 || vb[0] != is.fpr {
		t.Errorf("verified_by = %v, want the pinned issuer %s", b["verified_by"], is.fpr)
	}
	if o := outcomesOf(t, m, 1)[0]; o["valid"] != true { // one outcome per entry (§7.1)
		t.Errorf("outcome = %v, want valid", o)
	}

	// Human mode must name the principal and say which pinned key verified it.
	human := captureOut(t, func() { runVerify([]string{path, "--issuer", issuerFile}) })
	for _, want := range []string{"alice.reyes@acme.example", is.fpr, subject} {
		if !strings.Contains(human, want) {
			t.Errorf("human output does not carry %q:\n%s", want, human)
		}
	}
}

// TestVerifyRecordHonoursAt proves --at reaches the window check on a record.
// The walkthrough's second finding: --at 2027-06-01, well past the attestation's
// window, still printed VALID with nothing said about the credential.
func TestVerifyRecordHonoursAt(t *testing.T) {
	is := mkTestIssuer(t)
	path, subject, issuerFile := attestedRecord(t, is, time.Now().Add(time.Hour))
	late := time.Now().UTC().Add(10 * 365 * 24 * time.Hour).Format(time.RFC3339)

	m, code := verifyJSON(t, path, "--issuer", issuerFile, "--at", late, "--json")
	if code != 0 {
		t.Fatalf("an expired attestation must NOT change the record verdict, exit %d", code)
	}
	if m["valid"] != true {
		t.Fatal("an expired attestation must never make a sound record invalid (§7.2 step 5)")
	}
	if _, present := m["identity_bindings"]; present {
		t.Errorf("an expired credential must surface no binding: %v", m["identity_bindings"])
	}
	o := outcomesOf(t, m, 1)[0]
	if o["valid"] != false || o["reason"] != string(attest.ReasonExpired) {
		t.Errorf("outcome = %v, want valid=false reason=expired", o)
	}
	if o["reason_class"] != string(attest.ClassLifecycle) {
		t.Errorf("reason_class = %v, want %q", o["reason_class"], attest.ClassLifecycle)
	}
	if o["subject"] != subject {
		t.Errorf("outcome subject = %v, want %s", o["subject"], subject)
	}
	if ev, _ := m["identity_evaluation"].(map[string]any); ev["evaluated_at"] != late {
		t.Errorf("evaluated_at = %v, want the --at that was asked for (%s)", ev["evaluated_at"], late)
	}
}

// TestVerifyRecordUnanchoredIsNotACredentialFailure holds §5.2's normative
// rendering rule at the CLI. Pinning a DIFFERENT authority says nothing about
// the subject, and the output must not dress it as a finding about them.
func TestVerifyRecordUnanchoredIsNotACredentialFailure(t *testing.T) {
	acme, other := mkTestIssuer(t), mkTestIssuer(t)
	author := testAuthor(t)
	att := signedAttestation(t, acme, author.ID, "alice.reyes@acme.example", "acme-0001", time.Now().Add(24*time.Hour))
	path := sealRecordFile(t, author, att)
	issuerFile := writeIssuerFile(t, other.pub)

	m, code := verifyJSON(t, path, "--issuer", issuerFile, "--json")
	if code != 0 || m["valid"] != true {
		t.Fatalf("an unpinned authority must not change the record verdict: exit %d %v", code, m)
	}
	if c := outcomesOf(t, m, 1)[0]["reason_class"]; c != string(attest.ClassUnanchored) {
		t.Fatalf("reason_class = %v, want %q", c, attest.ClassUnanchored)
	}

	var code2 int
	human := captureOut(t, func() { code2 = runVerify([]string{path, "--issuer", issuerFile}) })
	if code2 != 0 {
		t.Errorf("human mode exit %d, want 0", code2)
	}
	for _, forbidden := range []string{"INVALID", "TAMPERED", "FAILED"} {
		if strings.Contains(human, forbidden) {
			t.Errorf("unanchored rendered as a credential failure (%q present):\n%s", forbidden, human)
		}
	}
	if !strings.Contains(human, "asserted") {
		t.Errorf("unanchored must render as asserted-not-verified:\n%s", human)
	}
}

// TestVerifyRecordForgedAttestationIsLoud is the other end of the class rule: a
// PINNED issuer's signature that does not verify is the one outcome that means
// stop, and it must not read like a broken file.
func TestVerifyRecordForgedAttestationIsLoud(t *testing.T) {
	is := mkTestIssuer(t)
	author := testAuthor(t)
	good := signedAttestation(t, is, author.ID, "alice.reyes@acme.example", "acme-0001", time.Now().Add(24*time.Hour))
	forged := good.WithSignatures(
		map[string][]byte{is.fpr: make([]byte, ed25519.SignatureSize)},
		map[string][]byte{is.fpr: is.pub},
	)
	path := sealRecordFile(t, author, forged)
	issuerFile := writeIssuerFile(t, is.pub)

	m, code := verifyJSON(t, path, "--issuer", issuerFile, "--json")
	if code != 0 || m["valid"] != true {
		t.Fatalf("a forged attestation must not flip the RECORD verdict (§7.2 step 5): exit %d %v", code, m)
	}
	if c := outcomesOf(t, m, 1)[0]["reason_class"]; c != string(attest.ClassForged) {
		t.Fatalf("reason_class = %v, want %q", c, attest.ClassForged)
	}
	human := captureOut(t, func() { runVerify([]string{path, "--issuer", issuerFile}) })
	if !strings.Contains(human, "SECURITY") {
		t.Errorf("a forged credential must not read like a broken file:\n%s", human)
	}
}

// TestVerifyRecordWithNoIssuerIsByteIdentical is the standalone-inert guarantee
// at the command. On a record that DOES carry attestations, plain verify must
// produce exactly what it produced before this change — the same property
// tui/record asserts of the library, asserted here of the surface an operator
// actually runs.
func TestVerifyRecordWithNoIssuerIsByteIdentical(t *testing.T) {
	is := mkTestIssuer(t)
	path, _, _ := attestedRecord(t, is, time.Now().Add(24*time.Hour))

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	res, err := sealedrecord.VerifyBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	want := captureOut(t, func() { _ = output.WriteJSON(res) })

	got := captureOut(t, func() { runVerify([]string{path, "--json"}) })
	if got != want {
		t.Errorf("unpinned verify is no longer byte-identical to plain VerifyBytes:\n got: %s\nwant: %s", got, want)
	}
	if strings.Contains(got, "identity_") {
		t.Errorf("no pin, no identity surface: %s", got)
	}
	if human := captureOut(t, func() { runVerify([]string{path}) }); strings.Contains(human, "identity") {
		t.Errorf("no pin, no identity surface in human mode:\n%s", human)
	}
}

// TestVerifyRecordWithIssuerAndNoAttestationsSaysSo is decision (a). A pinned
// issuer that finds nothing must produce a sentence, not an absence: silence is
// what let a dropped flag hide for a day, and "checked, found none" must never
// look like "never checked".
func TestVerifyRecordWithIssuerAndNoAttestationsSaysSo(t *testing.T) {
	is := mkTestIssuer(t)
	path := sealRecordFile(t, testAuthor(t)) // a record with no identity entry at all
	issuerFile := writeIssuerFile(t, is.pub)

	m, code := verifyJSON(t, path, "--issuer", issuerFile, "--json")
	if code != 0 || m["valid"] != true {
		t.Fatalf("exit %d %v", code, m)
	}
	ev, ok := m["identity_evaluation"].(map[string]any)
	if !ok {
		t.Fatalf("a pinned issuer that found nothing said nothing: %v", m)
	}
	if ev["evaluated"] != true {
		t.Errorf("evaluated = %v, want true", ev["evaluated"])
	}
	if ev["attestation_entries"] != float64(0) {
		t.Errorf("attestation_entries = %v, want 0", ev["attestation_entries"])
	}
	if ev["issuer_keys"] != float64(1) {
		t.Errorf("issuer_keys = %v, want 1", ev["issuer_keys"])
	}
	if s, _ := ev["evaluated_at"].(string); s == "" {
		t.Error("evaluated_at must be echoed, so the result is self-describing")
	}
	human := captureOut(t, func() { runVerify([]string{path, "--issuer", issuerFile}) })
	if !strings.Contains(human, "no identity attestations") {
		t.Errorf("human mode must say the pin found nothing:\n%s", human)
	}
}

// TestVerifyRecordNotSoundDoesNotClaimAnEvaluation is §7.2 step 1 at the
// command: bindings are not surfaced for a record that is not cryptographically
// sound, so the identity block must say the walk did not happen rather than
// report zero attestations found.
func TestVerifyRecordNotSoundDoesNotClaimAnEvaluation(t *testing.T) {
	is := mkTestIssuer(t)
	path, _, issuerFile := attestedRecord(t, is, time.Now().Add(24*time.Hour))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := sealedrecord.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	rec.Entries[0].Body = "do not ship"
	tb, err := rec.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	tampered := filepath.Join(t.TempDir(), "tampered.json")
	if err := os.WriteFile(tampered, tb, 0o644); err != nil {
		t.Fatal(err)
	}

	m, code := verifyJSON(t, tampered, "--issuer", issuerFile, "--json")
	if code != 1 || m["valid"] != false {
		t.Fatalf("a tampered record must still be TAMPERED, exit 1: exit %d %v", code, m)
	}
	ev, ok := m["identity_evaluation"].(map[string]any)
	if !ok {
		t.Fatalf("the pin must still be accounted for: %v", m)
	}
	if ev["evaluated"] != false {
		t.Errorf("evaluated = %v, want false — the identity walk does not run on an unsound record", ev["evaluated"])
	}
}

// TestVerifyAtWithoutIssuerIsAnError is decision (b): an evaluation time with
// nothing to evaluate is unusable input, not a silently ignored parameter. The
// spec already treats a zero At on the pinned path as an error rather than a
// Reason; this is the mirror of that rule at the command, and it holds for every
// artifact family because --at is one flag.
func TestVerifyAtWithoutIssuerIsAnError(t *testing.T) {
	is := mkTestIssuer(t)
	recPath, _, _ := attestedRecord(t, is, time.Now().Add(24*time.Hour))
	att := signedAttestation(t, is, is.fpr, "alice.reyes@acme.example", "acme-0002", time.Now().Add(24*time.Hour))
	ab, err := att.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	idPath := filepath.Join(t.TempDir(), "identity.json")
	if err := os.WriteFile(idPath, ab, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{recPath, idPath} {
		if code := runVerify([]string{p, "--at", "2027-06-01T00:00:00Z"}); code != 2 {
			t.Errorf("%s: --at without --issuer exited %d, want 2 — an evaluation time with nothing to evaluate is a broken invocation", p, code)
		}
	}
}

// TestVerifyRecordIssuerErrorsAreNotVerdicts proves the two ways an --issuer
// invocation can be unusable are reported as such. Before the fix both printed
// VALID and exited 0, because neither value was ever read on this path.
func TestVerifyRecordIssuerErrorsAreNotVerdicts(t *testing.T) {
	is := mkTestIssuer(t)
	path, _, issuerFile := attestedRecord(t, is, time.Now().Add(24*time.Hour))

	if code := runVerify([]string{path, "--issuer", filepath.Join(t.TempDir(), "nope.pub")}); code != 1 {
		t.Errorf("an unreadable issuer file exited %d, want 1", code)
	}
	if code := runVerify([]string{path, "--issuer", issuerFile, "--at", "yesterday"}); code != 1 {
		t.Errorf("an unparseable --at exited %d, want 1", code)
	}
}

// TestVerifyIssuerOnAnArtifactThatCannotUseItIsAnError closes the same shape one
// artifact family over: a roster carries no identity content, so accepting
// --issuer there and doing nothing with it is this session's defect in miniature.
func TestVerifyIssuerOnAnArtifactThatCannotUseItIsAnError(t *testing.T) {
	is := mkTestIssuer(t)
	issuerFile := writeIssuerFile(t, is.pub)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fpr := sealedrecord.Fingerprint(pub)
	unsigned := sealedrecord.NewRoster("ops", 1, fpr, []sealedrecord.RosterMember{{Fpr: fpr, Name: "alice"}}, nil, nil)
	setHash, err := hex.DecodeString(unsigned.SetHash)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, protocol.RosterSigningBytes(unsigned.Room, unsigned.Epoch, setHash))
	signed := sealedrecord.NewRoster("ops", 1, fpr, unsigned.Members,
		map[string][]byte{fpr: sig}, map[string][]byte{fpr: pub})
	rb, err := signed.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "roster.json")
	if err := os.WriteFile(p, rb, 0o644); err != nil {
		t.Fatal(err)
	}
	if code := runVerify([]string{p}); code != 0 {
		t.Fatalf("the roster fixture must verify on its own, exit %d", code)
	}
	if code := runVerify([]string{p, "--issuer", issuerFile}); code != 2 {
		t.Errorf("--issuer on a roster exited %d, want 2 — a flag this artifact cannot consume must not be swallowed", code)
	}
}
