package client

import (
	"encoding/hex"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
	"github.com/salehkreiner/netherchat/tui/record"
)

// These white-box tests pin the HYBRID seal-amendment fix (§1.4): a verified
// co-signature is NEVER lost, even when it arrives after the record was already
// finalized and written. They reproduce BOTH races the fix closes — the
// immediate-finalize race (the sealer's membership view is 1 at seal time) and the
// post-timeout late-ack race — deterministically, by driving the sealer's own
// onSealAck (the exact path a decrypted SEAL_ACK frame reaches) with a second
// identity's real co-signature. They live in the client package because they poke
// the unexported seal machinery (onSealAck, sealTimeout, c.order) that the black-box
// e2e suite cannot reach; TestSealRoundTrip in tui/e2e remains the happy-path
// acceptance test and is unchanged.

// decodeHead returns the raw 32-byte chain head a record was sealed over, from its
// hex head_hash — the value a co-signer signs via protocol.SealSigningBytes.
func decodeHead(t *testing.T, rec *record.SealedRecord) []byte {
	t.Helper()
	h, err := hex.DecodeString(rec.HeadHash)
	if err != nil {
		t.Fatalf("decode head_hash: %v", err)
	}
	return h
}

// expectNoAmend fails if an amended EvSealComplete arrives within d (used to prove a
// duplicate or forged co-signature does not rewrite the record).
func expectNoAmend(t *testing.T, c *Client, d time.Duration) {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case ev := <-c.Events():
			if e, ok := ev.(EvSealComplete); ok && e.Amended {
				t.Fatalf("record was unexpectedly amended to %d signature(s)", e.Signers)
			}
		case <-deadline:
			return
		case <-c.Done():
			return
		}
	}
}

// soloSealed connects a lone client, records one decision, and seals it. Because the
// sealer is the only member (order == 1), maybeFinalize finalizes SYNCHRONOUSLY with
// a single signature — this is the immediate-finalize race, and also proves a
// genuinely solo sealer finalizes instantly and never hangs (INV-1). It returns the
// client and the finalized 1-signature record.
func soloSealed(t *testing.T, url string) (*Client, *record.SealedRecord) {
	t.Helper()
	alice := dialClient(t, url, "ops", "alice")
	waitFor[EvKeyReady](t, alice, 5*time.Second)
	if err := alice.Decide("rolled back to v2.3.1 at 03:47 UTC"); err != nil {
		t.Fatalf("decide: %v", err)
	}
	if err := alice.Seal(); err != nil {
		t.Fatalf("seal: %v", err)
	}
	done := waitFor[EvSealComplete](t, alice, 5*time.Second)
	if done.Amended {
		t.Fatal("the initial finalize must not be flagged as an amend")
	}
	if done.Signers != 1 {
		t.Fatalf("solo seal finalized with %d signatures, want 1", done.Signers)
	}
	return alice, done.Record
}

// TestSoloSealerFinalizesInstantly proves the settled constraint (INV-1): a genuinely
// solo sealer still finalizes instantly with one signature and the record verifies.
func TestSoloSealerFinalizesInstantly(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLog()))
	defer ts.Close()

	_, rec := soloSealed(t, ts.URL)
	res, err := record.Verify(rec)
	if err != nil || !res.Valid {
		t.Fatalf("solo-sealed record must verify: err=%v reason=%q", err, res.Reason)
	}
	if len(res.Signers) != 1 {
		t.Fatalf("verified %d signers, want 1", len(res.Signers))
	}
}

// TestSealImmediateFinalizeRaceAmends is the headline regression (race 1, INV-2): the
// record is written with only the sealer's signature (membership view == 1), then a
// co-signer acks the same head LATE. Pre-fix that ack was silently dropped and the
// second signature was lost forever; now it must amend the durable record to two.
func TestSealImmediateFinalizeRaceAmends(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLog()))
	defer ts.Close()

	alice, rec := soloSealed(t, ts.URL)
	if len(rec.Signatures) != 1 {
		t.Fatalf("immediate finalize wrote %d signatures, want 1", len(rec.Signatures))
	}
	head := decodeHead(t, rec)

	bob, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("bob identity: %v", err)
	}
	sig, err := bob.Sign(protocol.SealSigningBytes("ops", head))
	if err != nil {
		t.Fatalf("bob co-sign: %v", err)
	}
	// The exact path a decrypted SEAL_ACK takes on the sealer, arriving after finalize.
	alice.onSealAck(bob.Fingerprint(), "bob", bob.SignPub, head, sig, "", "", "")

	done := waitFor[EvSealComplete](t, alice, 5*time.Second)
	if !done.Amended {
		t.Fatal("a late co-signature must re-emit an amended EvSealComplete")
	}
	if done.Signers != 2 {
		t.Fatalf("amended record has %d signatures, want 2", done.Signers)
	}
	res, err := record.Verify(done.Record)
	if err != nil || !res.Valid {
		t.Fatalf("amended record must verify: err=%v reason=%q", err, res.Reason)
	}
	if len(res.Signers) != 2 {
		t.Fatalf("verified %d signers after amend, want 2 (no co-signature lost)", len(res.Signers))
	}
}

// TestSealPostTimeoutLateAckAmends reproduces race 2 (INV-2): with a synced denominator
// (order == 2) the seal does not finalize immediately, so the 30s collection window
// (shortened here) times out and finalizes with the sealer's signature alone; a
// co-signer that acks AFTER the timeout must still amend the record, not be dropped.
func TestSealPostTimeoutLateAckAmends(t *testing.T) {
	old := sealTimeout
	sealTimeout = 150 * time.Millisecond
	defer func() { sealTimeout = old }()

	ts := httptest.NewServer(server.Handler(config.Default(), quietLog()))
	defer ts.Close()

	alice := dialClient(t, ts.URL, "ops", "alice")
	waitFor[EvKeyReady](t, alice, 5*time.Second)
	if err := alice.Decide("failover completed at 04:10 UTC"); err != nil {
		t.Fatalf("decide: %v", err)
	}
	// Force the denominator above 1 so the seal waits for the window instead of
	// finalizing on the spot: the timer then finalizes with one signature (race 2).
	alice.mu.Lock()
	alice.order = append(alice.order, "phantom-member-that-never-acks")
	alice.mu.Unlock()

	if err := alice.Seal(); err != nil {
		t.Fatalf("seal: %v", err)
	}
	done := waitFor[EvSealComplete](t, alice, 5*time.Second)
	if done.Amended || done.Signers != 1 {
		t.Fatalf("post-timeout finalize = {amended:%v signers:%d}, want {false 1}", done.Amended, done.Signers)
	}
	head := decodeHead(t, done.Record)

	bob, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("bob identity: %v", err)
	}
	sig, err := bob.Sign(protocol.SealSigningBytes("ops", head))
	if err != nil {
		t.Fatalf("bob co-sign: %v", err)
	}
	alice.onSealAck(bob.Fingerprint(), "bob", bob.SignPub, head, sig, "", "", "")

	amended := waitFor[EvSealComplete](t, alice, 5*time.Second)
	if !amended.Amended || amended.Signers != 2 {
		t.Fatalf("amend after timeout = {amended:%v signers:%d}, want {true 2}", amended.Amended, amended.Signers)
	}
	if res, err := record.Verify(amended.Record); err != nil || !res.Valid || len(res.Signers) != 2 {
		t.Fatalf("amended record invalid after timeout race: err=%v valid=%v signers=%d", err, res.Valid, len(res.Signers))
	}
}

// TestLateCosignatureIsDurable proves monotonic domination (INV-2/INV-4): the earlier
// 1-signature record still verifies on its own after the amendment adds a second
// signature — amendment only ADDS. It also drives a meaning-bearing (v2) co-signature,
// exercising the endorsement amend path.
func TestLateCosignatureIsDurable(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLog()))
	defer ts.Close()

	alice, rec1 := soloSealed(t, ts.URL)
	rec1Bytes, err := rec1.Marshal()
	if err != nil {
		t.Fatalf("marshal rec1: %v", err)
	}
	head := decodeHead(t, rec1)

	carol, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("carol identity: %v", err)
	}
	signedAt := time.Now().UTC().Format(time.RFC3339)
	sig, err := carol.Sign(protocol.SealSigningBytesV2("ops", record.MeaningApproved, "carol", signedAt, head))
	if err != nil {
		t.Fatalf("carol co-sign: %v", err)
	}
	alice.onSealAck(carol.Fingerprint(), "carol", carol.SignPub, head, sig, record.MeaningApproved, "carol", signedAt)

	done := waitFor[EvSealComplete](t, alice, 5*time.Second)
	if !done.Amended || done.Signers != 2 {
		t.Fatalf("amend = {amended:%v signers:%d}, want {true 2}", done.Amended, done.Signers)
	}
	rec2 := done.Record
	if end, ok := rec2.Endorsements[carol.Fingerprint()]; !ok || end.Meaning != record.MeaningApproved {
		t.Fatalf("amended record missing carol's endorsement: %+v", rec2.Endorsements)
	}
	if res, err := record.Verify(rec2); err != nil || !res.Valid || len(res.Signers) != 2 {
		t.Fatalf("amended (v2) record invalid: err=%v valid=%v signers=%d", err, res.Valid, len(res.Signers))
	}

	// The pre-amendment bytes must still verify with exactly one signer.
	parsed, err := record.Parse(rec1Bytes)
	if err != nil {
		t.Fatalf("parse rec1: %v", err)
	}
	if res, err := record.Verify(parsed); err != nil || !res.Valid || len(res.Signers) != 1 {
		t.Fatalf("the pre-amendment record must still verify with 1 signer: err=%v valid=%v signers=%d", err, res.Valid, len(res.Signers))
	}
}

// TestAmendIsIdempotentOnDuplicateAck proves a re-delivered co-signature is a no-op
// (INV-6): the first delivery amends to two signatures; a second, identical delivery
// neither double-counts nor rewrites the record.
func TestAmendIsIdempotentOnDuplicateAck(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLog()))
	defer ts.Close()

	alice, rec := soloSealed(t, ts.URL)
	head := decodeHead(t, rec)

	bob, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("bob identity: %v", err)
	}
	sig, err := bob.Sign(protocol.SealSigningBytes("ops", head))
	if err != nil {
		t.Fatalf("bob co-sign: %v", err)
	}
	alice.onSealAck(bob.Fingerprint(), "bob", bob.SignPub, head, sig, "", "", "")
	first := waitFor[EvSealComplete](t, alice, 5*time.Second)
	if !first.Amended || first.Signers != 2 {
		t.Fatalf("first amend = {amended:%v signers:%d}, want {true 2}", first.Amended, first.Signers)
	}

	alice.onSealAck(bob.Fingerprint(), "bob", bob.SignPub, head, sig, "", "", "")
	expectNoAmend(t, alice, 400*time.Millisecond)
}

// TestAmendPreservesArtifactProofs proves artifact-approval proofs survive the
// re-assembly on amend (INV-7): a record whose entry chain includes an artifact entry
// with a retained approval proof keeps that proof after a late co-signature rewrites it.
func TestAmendPreservesArtifactProofs(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLog()))
	defer ts.Close()

	agent := dialClient(t, ts.URL, "ops", "agent")
	waitFor[EvKeyReady](t, agent, 5*time.Second)
	alice := dialClient(t, ts.URL, "ops", "alice")
	waitFor[EvKeyReady](t, alice, 5*time.Second)
	waitFor[EvMemberJoined](t, agent, 5*time.Second) // alice

	id, err := agent.Propose("planner-agent", "runbook", hashOf("the runbook"), "", 1)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	waitFor[EvArtifactProposed](t, alice, 5*time.Second)
	if err := alice.ApproveArtifact(id, ""); err != nil {
		t.Fatalf("approve: %v", err)
	}
	// The single approval reaches quorum: alice writes the artifact entry, and the
	// proposer captures alice's proof when it processes her approval (ordered before
	// the entry it now waits for), so agent holds both the entry and the proof.
	waitFor[EvRecordEntry](t, agent, 5*time.Second)

	// alice leaves so the proposer seals alone (order == 1, immediate finalize) while
	// still holding the retained approval proof.
	_ = alice.Close()
	waitFor[EvMemberLeft](t, agent, 5*time.Second)

	if err := agent.Seal(); err != nil {
		t.Fatalf("seal: %v", err)
	}
	done := waitFor[EvSealComplete](t, agent, 5*time.Second)
	if done.Amended {
		t.Fatal("the initial finalize must not be an amend")
	}
	if got := len(done.Record.ArtifactApprovals[id]); got != 1 {
		t.Fatalf("initial record has %d artifact proofs, want 1", got)
	}
	head := decodeHead(t, done.Record)

	carol, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("carol identity: %v", err)
	}
	sig, err := carol.Sign(protocol.SealSigningBytes("ops", head))
	if err != nil {
		t.Fatalf("carol co-sign: %v", err)
	}
	agent.onSealAck(carol.Fingerprint(), "carol", carol.SignPub, head, sig, "", "", "")

	amended := waitFor[EvSealComplete](t, agent, 5*time.Second)
	if !amended.Amended || amended.Signers != 2 {
		t.Fatalf("amend = {amended:%v signers:%d}, want {true 2}", amended.Amended, amended.Signers)
	}
	if got := len(amended.Record.ArtifactApprovals[id]); got != 1 {
		t.Fatalf("amended record lost artifact proofs: have %d, want 1 (INV-7)", got)
	}
	if res, err := record.Verify(amended.Record); err != nil || !res.Valid {
		t.Fatalf("amended record with artifact proofs must verify: err=%v reason=%q", err, res.Reason)
	}
}

// TestUnapplicableAckEmitsDiagnostic proves an ack that matches neither the active
// round nor the last finalized seal is surfaced, never dropped in silence (INV-10) —
// the silence is what hid the original loss.
func TestUnapplicableAckEmitsDiagnostic(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLog()))
	defer ts.Close()

	alice, _ := soloSealed(t, ts.URL)

	bob, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("bob identity: %v", err)
	}
	bogus := make([]byte, 32)
	for i := range bogus {
		bogus[i] = 0xAB
	}
	sig, err := bob.Sign(protocol.SealSigningBytes("ops", bogus))
	if err != nil {
		t.Fatalf("bob sign: %v", err)
	}
	alice.onSealAck(bob.Fingerprint(), "bob", bob.SignPub, bogus, sig, "", "", "")

	if got := waitFor[EvError](t, alice, 2*time.Second); got.Err == nil {
		t.Fatal("an unappliable co-signature must emit a diagnostic error")
	}
}

// TestAmendRejectsForgedCosignature proves a co-signature that does not verify never
// enters the record (INV-5): it is rejected with a diagnostic and does not amend.
func TestAmendRejectsForgedCosignature(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), quietLog()))
	defer ts.Close()

	alice, rec := soloSealed(t, ts.URL)
	head := decodeHead(t, rec)

	bob, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("bob identity: %v", err)
	}
	// A real signature, but over the wrong bytes: presented for the correct head, it
	// must fail verification in the amend path.
	forged, err := bob.Sign([]byte("not the seal preimage"))
	if err != nil {
		t.Fatalf("bob sign: %v", err)
	}
	alice.onSealAck(bob.Fingerprint(), "bob", bob.SignPub, head, forged, "", "", "")

	if got := waitFor[EvError](t, alice, 2*time.Second); got.Err == nil {
		t.Fatal("a forged co-signature must emit a diagnostic error")
	}
	expectNoAmend(t, alice, 400*time.Millisecond)
}
