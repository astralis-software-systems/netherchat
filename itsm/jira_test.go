package itsm

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func TestJiraAttach(t *testing.T) {
	srv, reqs := captureServer(t, 200)
	c, _ := New("jira", testCfg(srv), testProv())
	if err := c.Attach("INC-1234", sampleRecord, "rec.json"); err != nil {
		t.Fatalf("attach: %v", err)
	}
	r := (*reqs)[0]
	if r.method != http.MethodPost || r.path != "/rest/api/3/issue/INC-1234/attachments" {
		t.Fatalf("wrong endpoint: %s %s", r.method, r.path)
	}
	if r.headers.Get("X-Atlassian-Token") != "no-check" {
		t.Error("missing X-Atlassian-Token: no-check")
	}
	assertProvenance(t, r)
	_, file, name := parseMultipart(t, r)
	if name != "rec.json" {
		t.Errorf("file name = %q", name)
	}
	if !bytes.Equal(file, sampleRecord) {
		t.Errorf("attached file is not the record verbatim:\n%s", file)
	}
}

func TestJiraComment(t *testing.T) {
	srv, reqs := captureServer(t, 200)
	c, _ := New("jira", testCfg(srv), testProv())
	if err := c.Comment("INC-1234", "the summary"); err != nil {
		t.Fatalf("comment: %v", err)
	}
	r := (*reqs)[0]
	if r.method != http.MethodPost || r.path != "/rest/api/3/issue/INC-1234/comment" {
		t.Fatalf("wrong endpoint: %s %s", r.method, r.path)
	}
	assertProvenance(t, r)
	var body struct {
		Body struct {
			Type    string `json:"type"`
			Version int    `json:"version"`
			Content []struct {
				Type    string `json:"type"`
				Content []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"content"`
			} `json:"content"`
		} `json:"body"`
	}
	if err := json.Unmarshal(r.body, &body); err != nil {
		t.Fatalf("decode ADF: %v", err)
	}
	if body.Body.Type != "doc" || body.Body.Version != 1 {
		t.Fatalf("bad ADF document: %+v", body.Body)
	}
	if len(body.Body.Content) == 0 || body.Body.Content[0].Type != "paragraph" ||
		len(body.Body.Content[0].Content) == 0 || body.Body.Content[0].Content[0].Text != "the summary" {
		t.Errorf("ADF comment text wrong: %+v", body.Body)
	}
}

// TestJiraBoundary is mandatory: attachment is the record verbatim, no transcript
// crosses, and the comment is metadata-only.
func TestJiraBoundary(t *testing.T) {
	srv, reqs := captureServer(t, 200, 200)
	c, _ := New("jira", testCfg(srv), testProv())
	res := AttachResult{TicketID: "INC-1234", Filename: "rec.json", HeadHash: "deadbeefdeadbeef", Signers: 2, VerifyCmd: "netherchat verify rec.json"}
	if err := Deliver(c, res, sampleRecord, io.Discard); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	_, file, _ := parseMultipart(t, (*reqs)[0])
	if !bytes.Equal(file, sampleRecord) {
		t.Fatal("attachment is not the record verbatim")
	}
	if bytes.Contains((*reqs)[0].body, []byte(transcriptSentinel)) {
		t.Fatal("boundary violated: unsealed transcript present in the attachment request")
	}
	if bytes.Contains((*reqs)[1].body, []byte("SEALED_DECISION_OK")) {
		t.Fatal("boundary violated: the comment echoed decision text (must be metadata only)")
	}
}
