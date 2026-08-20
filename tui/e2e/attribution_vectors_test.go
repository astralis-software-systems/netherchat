// Cross-language vectors for the D-I rendering decision.
//
// The decision has two implementations — tui/attest/identity_display.go and
// web/src/identity/attribution.ts — and this repository has already paid twice
// for a rule that lived in two languages and was checked by reading: the
// `members: null` Welcome the TypeScript type forbade anyone from writing down,
// and the v1/v2 approval preimage. So the rule ships as data.
//
// TestGenAttributionVectors writes web/src/net/testdata/attribution.json from
// the Go implementation. It is gated, like the wire-frame and crypto generators
// beside it, and the artifact is committed:
//
//	GEN_INTEROP=1 go test ./tui/e2e -run TestGenAttributionVectors -v
//
// TestAttributionVectorsMatchThisBuild is NOT gated. It replays the committed
// file through the Go implementation and fails if they have parted, so the
// vectors cannot go stale between regenerations — the same relationship
// TestWelcomeMembersIsNeverNull has to the wire frames.
//
// # WHY EACH CASE CARRIES TWO OUTCOMES
//
// Every case states what the input renders as WITH the issuer key pinned and
// WITHOUT it, because those are two different readers and both exist. The Go
// side can reach both. The browser can only ever reach the second — it holds no
// issuer key and no clock it would be entitled to use — and so can a live
// Netherchat room, for the same reason. Recording both in one file is what makes
// that asymmetry a fact in the repository rather than a paragraph in a document.
package e2e

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// attributionVectorPath is where the file lives, relative to this package.
var attributionVectorPath = filepath.Join("..", "..", "web", "src", "net", "testdata", "attribution.json")

// attributionOutcome is one rendering, as both languages must produce it.
type attributionOutcome struct {
	State string `json:"state"`
	Name  string `json:"name"`
	Mark  string `json:"mark"`
}

// attributionCase is one input and its two outcomes.
type attributionCase struct {
	Name         string             `json:"name"`
	Why          string             `json:"why"`
	AssertedName string             `json:"assertedName"`
	Subject      string             `json:"subjectFingerprint"` // the key the credential arrived ON
	Attestation  string             `json:"attestationB64"`     // "" means none was carried
	Pinned       attributionOutcome `json:"withIssuerPinned"`
	Unpinned     attributionOutcome `json:"withNoIssuerPinned"`
}

// fingerprintVector pins the subject-fingerprint derivation across the two
// implementations. The browser has to compute a key's SSH SHA-256 fingerprint to
// make the same join the Go side makes, and a subtly wrong derivation would
// silently turn every credential into a mismatch — a failure that looks like
// caution and is actually a broken check.
type fingerprintVector struct {
	PublicKey   string `json:"publicKeyB64"` // raw 32-byte Ed25519 public key
	Fingerprint string `json:"fingerprint"`  // crypto.Fingerprint == ssh.FingerprintSHA256
}

type attributionVectors struct {
	Comment      string              `json:"_comment"`
	Generator    string              `json:"_generator"`
	Source       string              `json:"_source"`
	IssuerKey    string              `json:"issuerKeyB64"`
	EvaluatedAt  string              `json:"evaluatedAt"`
	Fingerprints []fingerprintVector `json:"fingerprintVectors"`
	Cases        []attributionCase   `json:"cases"`
}

// fixedIssuer returns a deterministic issuer key pair, so regenerating the
// vectors is a small diff rather than two fresh base64 blobs.
func fixedIssuer() (ed25519.PublicKey, ed25519.PrivateKey, string) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(0x40 + i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv, crypto.Fingerprint(pub)
}

// fixedAttestation builds a signed artifact with no clock in it: issued_at is
// overwritten before the preimage is derived, so the bytes are the same on every
// run and the committed vectors do not churn.
func fixedAttestation(t *testing.T, subject, principal, displayName string, roles []string, signIt bool) []byte {
	t.Helper()
	pub, priv, fpr := fixedIssuer()
	a := attest.NewIdentityAttestation(attest.IdentitySpec{
		Serial:        "acme-vector-" + subject[7:11],
		Subject:       subject,
		Principal:     principal,
		DisplayName:   displayName,
		PrincipalType: "person",
		Roles:         roles,
		ExpiresAt:     "2036-01-01T00:00:00Z",
		Algorithm:     attest.AlgorithmEd25519,
		Issuer:        fpr,
	}, nil, nil)
	a.IssuedAt = "2026-01-01T00:00:00Z"

	sig := ed25519.Sign(priv, attest.IdentitySigningBytes(a))
	if !signIt {
		// A credential nobody's pinned key signed. Flip one byte of the signature
		// rather than omitting it: an artifact with no signature at all fails a
		// different check, and the row this stands for is "signed by an authority
		// this reader has not pinned".
		sig[0] ^= 0xff
	}
	signed := a.WithSignatures(
		map[string][]byte{fpr: sig},
		map[string][]byte{fpr: pub},
	)
	b, err := signed.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// buildAttributionVectors is the single source both the generator and the
// conformance test use, so they cannot describe different case sets.
func buildAttributionVectors(t *testing.T) attributionVectors {
	t.Helper()
	pub, _, _ := fixedIssuer()
	const evaluatedAt = "2030-06-01T12:00:00Z"
	at, err := time.Parse(time.RFC3339, evaluatedAt)
	if err != nil {
		t.Fatal(err)
	}

	const (
		keyA = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		keyB = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
		keyC = "SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
		keyD = "SHA256:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
		keyM = "SHA256:MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM"
	)
	type input struct {
		name, why, asserted, subject string
		artifact                     []byte
	}
	inputs := []input{
		{
			name: "attested_with_display_name", asserted: "rosa", subject: keyA,
			why:      "D-I row 1: a pinned issuer signed a display name, so the display name is the name.",
			artifact: fixedAttestation(t, keyA, "rosa.alvarez@acme.example", "Rosa Alvarez", []string{"incident-commander"}, true),
		},
		{
			name: "attested_no_display_name", asserted: "deploybot", subject: keyB,
			why:      "D-I row 2, the third VERIFIED path: the credential verified and the issuer named no name, so the principal is the name. Not a fallback and not the asserted state.",
			artifact: fixedAttestation(t, keyB, "svc-deploybot@acme.example", "", []string{"deployer"}, true),
		},
		{
			name: "carried_signed_by_an_unpinned_authority", asserted: "mallory", subject: keyC,
			why:      "A well-formed credential whose signature the pinned key did not make. Unanchored: a statement about the trust relationship, never about the subject.",
			artifact: fixedAttestation(t, keyC, "ceo@acme.example", "Chief Executive", []string{"approver"}, false),
		},
		{
			name: "credential_about_another_key", asserted: "mallory", subject: keyM,
			why:      "Rosa's real, valid, issuer-signed credential, replayed onto Mallory's key. An attestation is not a secret (§2.3), so anyone who has seen one can attach it; the verifier answers 'did the issuer sign this statement about subject X' and only the caller knows whether X is the key in front of it. Carried, never verified, in BOTH readers.",
			artifact: fixedAttestation(t, keyA, "rosa.alvarez@acme.example", "Rosa Alvarez", []string{"incident-commander"}, true),
		},
		{
			name: "carrier_is_not_an_artifact", asserted: "dave", subject: keyD,
			why:      "Bytes that do not parse. Carried, not asserted: something arrived, and saying otherwise hides it.",
			artifact: []byte("{not an identity artifact"),
		},
		{
			name: "nothing_carried", asserted: "alice", subject: keyA,
			why:      "The oldest state and still the common one.",
			artifact: nil,
		},
	}

	out := attributionVectors{
		Comment: "D-I rendering vectors. Each case is one input and the two outcomes it has: what a " +
			"reader WITH the issuer key pinned renders, and what a reader WITHOUT one renders. A " +
			"browser client and a live Netherchat room can only ever be the second reader.",
		Generator:   "GEN_INTEROP=1 go test ./tui/e2e -run TestGenAttributionVectors -v",
		Source:      "tui/e2e/attribution_vectors_test.go, via tui/attest.IdentityDisplayForBytes",
		IssuerKey:   base64.StdEncoding.EncodeToString(pub),
		EvaluatedAt: evaluatedAt,
	}

	// Deterministic keys, including the all-zero one, so a derivation that happens
	// to work on random input has somewhere to go wrong.
	for tag := 0; tag < 4; tag++ {
		raw := make([]byte, ed25519.PublicKeySize)
		for i := range raw {
			raw[i] = byte(tag * i)
		}
		out.Fingerprints = append(out.Fingerprints, fingerprintVector{
			PublicKey:   base64.StdEncoding.EncodeToString(raw),
			Fingerprint: crypto.Fingerprint(ed25519.PublicKey(raw)),
		})
	}

	for _, in := range inputs {
		var pinned, unpinned attest.IdentityDisplay
		if len(in.artifact) == 0 {
			pinned = attest.IdentityDisplayForBytes(in.asserted, in.subject, nil, nil)
			unpinned = pinned
		} else {
			unpinned = attest.IdentityDisplayForBytes(in.asserted, in.subject, in.artifact, nil)
			pinned = attest.IdentityDisplayForBytes(in.asserted, in.subject, in.artifact,
				verifyForVector(t, in.artifact, pub, at))
		}
		enc := ""
		if len(in.artifact) > 0 {
			enc = base64.StdEncoding.EncodeToString(in.artifact)
		}
		out.Cases = append(out.Cases, attributionCase{
			Name: in.name, Why: in.why, AssertedName: in.asserted, Subject: in.subject, Attestation: enc,
			Pinned:   attributionOutcome{string(pinned.State), pinned.Name, attest.IdentityDisplayMark(pinned.State)},
			Unpinned: attributionOutcome{string(unpinned.State), unpinned.Name, attest.IdentityDisplayMark(unpinned.State)},
		})
	}
	return out
}

// verifyForVector verifies an artifact against the pinned key, or returns nil
// when the bytes are not an artifact at all — which is the reader's state too:
// there is nothing to have a verdict about.
func verifyForVector(t *testing.T, artifact []byte, pub ed25519.PublicKey, at time.Time) *attest.IdentityResult {
	t.Helper()
	a, err := attest.ParseIdentity(artifact)
	if err != nil {
		return nil
	}
	res, err := attest.VerifyIdentity(a, attest.IdentityOptions{IssuerKeys: []ed25519.PublicKey{pub}, At: at})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return res
}

func TestGenAttributionVectors(t *testing.T) {
	if os.Getenv("GEN_INTEROP") == "" {
		t.Skip("set GEN_INTEROP=1 to regenerate web/src/net/testdata/attribution.json")
	}
	blob, err := json.MarshalIndent(buildAttributionVectors(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	blob = append(blob, '\n')
	if err := os.MkdirAll(filepath.Dir(attributionVectorPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(attributionVectorPath, blob, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s (%d bytes)\n%s", attributionVectorPath, len(blob), blob)
}

// TestAttributionVectorsMatchThisBuild is the ungated half. A gated generator
// alone would let the committed file drift from the code the day someone changes
// the decision and does not regenerate.
func TestAttributionVectorsMatchThisBuild(t *testing.T) {
	raw, err := os.ReadFile(attributionVectorPath)
	if err != nil {
		t.Fatalf("the committed vectors are missing: %v\nRegenerate: GEN_INTEROP=1 go test ./tui/e2e -run TestGenAttributionVectors -v", err)
	}
	var committed attributionVectors
	if err := json.Unmarshal(raw, &committed); err != nil {
		t.Fatalf("committed vectors: %v", err)
	}
	fresh := buildAttributionVectors(t)

	if len(committed.Cases) == 0 {
		t.Fatal("the committed vectors hold no cases; the TypeScript half is checking nothing")
	}
	if len(committed.Fingerprints) == 0 {
		t.Fatal("the committed vectors hold no fingerprint vectors; the browser's subject join is unchecked")
	}
	for i, want := range fresh.Fingerprints {
		if committed.Fingerprints[i] != want {
			t.Errorf("fingerprint vector %d: committed %+v, this build %+v", i, committed.Fingerprints[i], want)
		}
	}
	if len(committed.Cases) != len(fresh.Cases) {
		t.Fatalf("the committed vectors hold %d case(s) and this build produces %d; regenerate",
			len(committed.Cases), len(fresh.Cases))
	}
	for i, want := range fresh.Cases {
		got := committed.Cases[i]
		if got.Name != want.Name || got.AssertedName != want.AssertedName ||
			got.Subject != want.Subject || got.Attestation != want.Attestation {
			t.Errorf("case %d: the committed INPUT differs from this build's\n committed: %+v\n     build: %+v", i, got, want)
			continue
		}
		if got.Pinned != want.Pinned {
			t.Errorf("case %q with the issuer pinned: committed %+v, this build %+v", got.Name, got.Pinned, want.Pinned)
		}
		if got.Unpinned != want.Unpinned {
			t.Errorf("case %q with no issuer pinned: committed %+v, this build %+v", got.Name, got.Unpinned, want.Unpinned)
		}
	}

	// The asymmetry, asserted rather than described: exactly the rows that verify
	// under a pinned key must NOT verify without one, and nothing carried may
	// render an issuer's name in either reader's absence of a check.
	verifiedUnderPin := 0
	for _, c := range committed.Cases {
		if c.Pinned.Mark == "◆" {
			verifiedUnderPin++
			if c.Unpinned.Mark == "◆" {
				t.Errorf("case %q renders as verified with no issuer pinned", c.Name)
			}
			if c.Unpinned.Name != c.AssertedName {
				t.Errorf("case %q renders %q with no issuer pinned, want the asserted name %q",
					c.Name, c.Unpinned.Name, c.AssertedName)
			}
		}
	}
	if verifiedUnderPin < 2 {
		t.Fatalf("only %d case(s) verify under a pinned issuer; D-I has THREE verified rendering "+
			"paths and at least the two name-shaped ones have to be in the vectors", verifiedUnderPin)
	}
}
