package sealedrecord_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/salehkreiner/netherchat/sealedrecord"
)

// Example demonstrates the entire offline lifecycle — create, seal, verify,
// render — that an external program performs using ONLY this package and the
// standard library: no relay, no network, and no internal package.
func Example() {
	// An identity is just an Ed25519 keypair; its AuthorID is the key fingerprint.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	author := sealedrecord.Author{
		ID:   sealedrecord.Fingerprint(pub),
		Name: "alice",
		Key:  pub,
		Sign: func(b []byte) ([]byte, error) { return ed25519.Sign(priv, b), nil },
	}

	// Build an append-only chain of signed entries.
	chain := sealedrecord.NewChain()
	if _, err := chain.AppendNew(author, sealedrecord.KindDecision, "", "rolled back to v2.3.1"); err != nil {
		panic(err)
	}

	// Seal it by collecting co-signatures over the chain head (here just alice).
	sealer := sealedrecord.NewSealer("ops", author.ID, chain.Entries())
	if err := sealer.Sign(author); err != nil {
		panic(err)
	}
	rec, err := sealer.Finalize()
	if err != nil {
		panic(err)
	}

	// Marshal, then verify the bytes from scratch and render an HTML report.
	b, err := rec.Marshal()
	if err != nil {
		panic(err)
	}
	res, err := sealedrecord.VerifyBytes(b)
	if err != nil {
		panic(err)
	}
	_ = sealedrecord.RenderHTML(rec, res, sealedrecord.Options{})

	fmt.Printf("valid=%v entries=%d signers=%d\n", res.Valid, res.Entries, len(res.Signers))
	// Output: valid=true entries=1 signers=1
}

// TestExternalConsumerCreateVerify proves an external consumer can create AND
// verify a record using only the public façade, and that tampering with a signed
// field is detected as TAMPERED.
func TestExternalConsumerCreateVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	author := sealedrecord.Author{
		ID:   sealedrecord.Fingerprint(pub),
		Name: "alice",
		Key:  pub,
		Sign: func(b []byte) ([]byte, error) { return ed25519.Sign(priv, b), nil },
	}

	chain := sealedrecord.NewChain()
	if _, err := chain.AppendNew(author, sealedrecord.KindDecision, "", "ship it"); err != nil {
		t.Fatalf("append: %v", err)
	}
	sealer := sealedrecord.NewSealer("ops", author.ID, chain.Entries())
	if err := sealer.Sign(author); err != nil {
		t.Fatalf("sign seal: %v", err)
	}
	rec, err := sealer.Finalize()
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}

	// A valid record verifies VALID.
	b, err := rec.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	res, err := sealedrecord.VerifyBytes(b)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.Valid {
		t.Fatalf("expected VALID, got reason: %s", res.Reason)
	}

	// Tampering with a signed field flips the verdict to TAMPERED.
	rec.Entries[0].Body = "do not ship"
	bad, err := rec.Marshal()
	if err != nil {
		t.Fatalf("marshal tampered: %v", err)
	}
	res2, err := sealedrecord.VerifyBytes(bad)
	if err != nil {
		t.Fatalf("verify tampered: %v", err)
	}
	if res2.Valid {
		t.Fatal("tampered record verified as VALID through the public façade")
	}
}
