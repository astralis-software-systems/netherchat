package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/salehkreiner/netherchat/itsm"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/record"
)

// TestAttachmentFor proves the seal→attachment mapping: the attachment is the
// record marshaled verbatim, provenance is the sealer's own head signature, and the
// work note is metadata-only (the boundary law for the human-facing summary).
func TestAttachmentFor(t *testing.T) {
	rec := &record.SealedRecord{
		Version:    "v1",
		Room:       "inc-9",
		SealedBy:   "SHA256:alice",
		SealedAt:   "2026-06-12T10:00:00Z",
		HeadHash:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Signatures: map[string]string{"SHA256:alice": "ALICESIG", "SHA256:bob": "BOBSIG"},
		Entries:    []record.Entry{{Kind: record.KindDecision, AuthorName: "alice", Body: "SECRET_DECISION_ROLLBACK"}},
	}
	want, err := rec.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	recordBytes, res, prov, ok := attachmentFor(client.EvSealComplete{Record: rec, Signers: 2}, "INC0010001", "12m")
	if !ok {
		t.Fatal("attachmentFor returned not-ok for a valid record")
	}
	if !bytes.Equal(recordBytes, want) {
		t.Fatal("attachment is not the record marshaled verbatim")
	}
	if res.TicketID != "INC0010001" || res.HeadHash != rec.HeadHash || res.Signers != 2 || res.Elapsed != "12m" {
		t.Fatalf("attach result wrong: %+v", res)
	}
	if !strings.Contains(res.Filename, "inc-9") || !strings.HasSuffix(res.Filename, ".json") {
		t.Errorf("filename = %q", res.Filename)
	}
	if res.VerifyCmd != "netherchat verify "+res.Filename {
		t.Errorf("verify cmd = %q", res.VerifyCmd)
	}
	// Provenance is the sealer's own seal signature over the head — checkable against
	// the record's signer keys.
	if prov.Room != "inc-9" || prov.Fpr != "SHA256:alice" || prov.Sig != "ALICESIG" || prov.Ts != "2026-06-12T10:00:00Z" {
		t.Fatalf("provenance wrong: %+v", prov)
	}

	// BOUNDARY: the sealed decision belongs in the verifiable attachment, never in
	// the human work note.
	summary := itsm.FormatSummary(res)
	if strings.Contains(summary, "SECRET_DECISION_ROLLBACK") {
		t.Fatal("boundary violated: the work note echoed decision text")
	}
	if !bytes.Contains(recordBytes, []byte("SECRET_DECISION_ROLLBACK")) {
		t.Fatal("the sealed decision should be in the attachment (it is the authoritative artifact)")
	}
}

func TestAttachmentForNoRecord(t *testing.T) {
	if _, _, _, ok := attachmentFor(client.EvSealComplete{Record: nil}, "INC1", ""); ok {
		t.Error("a seal with no record should not produce an attachment")
	}
}

func TestSafeName(t *testing.T) {
	if got := safeName("ops/../etc"); strings.ContainsAny(got, "/.") {
		t.Errorf("path characters not sanitized: %q", got)
	}
	if safeName("") != "incident" {
		t.Error("empty room should become incident")
	}
}
