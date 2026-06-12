package e2e

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/salehkreiner/netherchat/itsm"
	"github.com/salehkreiner/netherchat/tui/record"
)

// TestITSMAttachmentVerifiesOffline is the NC-4 acceptance gate (invariant 6): the
// artifact filed to an ITSM ticket must be the sealed record, byte-for-byte, and
// must still verify offline with `netherchat verify`. We push a REAL sealed record
// through each backend and re-verify the exact bytes the server received.
func TestITSMAttachmentVerifiesOffline(t *testing.T) {
	rec := sealedFixture(t, "inc-itsm")
	recordBytes, err := rec.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	for _, backend := range []string{"servicenow", "jira"} {
		t.Run(backend, func(t *testing.T) {
			var attachment []byte
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if ct := r.Header.Get("Content-Type"); strings.HasPrefix(ct, "multipart/") {
					_, params, _ := mime.ParseMediaType(ct)
					mr := multipart.NewReader(r.Body, params["boundary"])
					for {
						part, err := mr.NextPart()
						if err != nil {
							break
						}
						if part.FileName() != "" {
							attachment, _ = io.ReadAll(part)
						}
					}
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			cl, err := itsm.New(backend,
				itsm.Config{URL: srv.URL, User: "u", Token: "t", HTTPClient: srv.Client()},
				itsm.Provenance{Room: "inc-itsm", Fpr: rec.SealedBy, Sig: rec.Signatures[rec.SealedBy], Ts: rec.SealedAt},
			)
			if err != nil {
				t.Fatalf("new %s client: %v", backend, err)
			}
			res := itsm.AttachResult{TicketID: "T1", Filename: "rec.json", HeadHash: rec.HeadHash, Signers: len(rec.Signatures), VerifyCmd: "netherchat verify rec.json"}
			if err := itsm.Deliver(cl, res, recordBytes, io.Discard); err != nil {
				t.Fatalf("deliver: %v", err)
			}

			if !bytes.Equal(attachment, recordBytes) {
				t.Fatal("the attached bytes are not the sealed record verbatim")
			}
			parsed, err := record.Parse(attachment)
			if err != nil {
				t.Fatalf("attached record is not parseable: %v", err)
			}
			vr, err := record.Verify(parsed)
			if err != nil {
				t.Fatalf("verify error: %v", err)
			}
			if !vr.Valid {
				t.Fatalf("the attached record did NOT verify offline: %s", vr.Reason)
			}
			if len(vr.Signers) != 2 {
				t.Errorf("attached record verified %d signers, want 2", len(vr.Signers))
			}
		})
	}
}
