package itsm

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
)

// jira files records to a Jira Cloud instance via the REST v3 API (plain REST, no
// SDK). Attachments require the X-Atlassian-Token: no-check header; comments use
// the Atlassian Document Format (ADF).
func init() {
	register("jira", func(cfg Config, prov Provenance) Client { return &jira{cfg: cfg, prov: prov} })
}

type jira struct {
	cfg  Config
	prov Provenance
}

// Attach uploads the record as an issue attachment (multipart/form-data, field
// "file"). The record bytes are sent verbatim.
func (j *jira) Attach(ticketID string, record []byte, filename string) error {
	return j.cfg.do(func() (*http.Request, error) {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		fw, err := mw.CreateFormFile("file", filename)
		if err != nil {
			return nil, err
		}
		if _, err := fw.Write(record); err != nil {
			return nil, err
		}
		if err := mw.Close(); err != nil {
			return nil, err
		}
		req, err := http.NewRequest(http.MethodPost, j.cfg.URL+"/rest/api/3/issue/"+ticketID+"/attachments", &buf)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("X-Atlassian-Token", "no-check")
		req.SetBasicAuth(j.cfg.User, j.cfg.Token)
		j.prov.apply(req)
		return req, nil
	})
}

// Comment adds an issue comment with an ADF body carrying the metadata summary.
func (j *jira) Comment(ticketID string, summary string) error {
	body, err := json.Marshal(newADFComment(summary))
	if err != nil {
		return err
	}
	return j.cfg.do(func() (*http.Request, error) {
		req, err := http.NewRequest(http.MethodPost, j.cfg.URL+"/rest/api/3/issue/"+ticketID+"/comment", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.SetBasicAuth(j.cfg.User, j.cfg.Token)
		j.prov.apply(req)
		return req, nil
	})
}

// adfComment is the Jira comment envelope; the body is an ADF document.
type adfComment struct {
	Body adfNode `json:"body"`
}

// adfNode is a node in an Atlassian Document Format tree.
type adfNode struct {
	Type    string    `json:"type"`
	Version int       `json:"version,omitempty"`
	Content []adfNode `json:"content,omitempty"`
	Text    string    `json:"text,omitempty"`
}

// newADFComment wraps plain text in the minimal ADF doc Jira's comment API expects.
func newADFComment(text string) adfComment {
	return adfComment{Body: adfNode{
		Type:    "doc",
		Version: 1,
		Content: []adfNode{{
			Type:    "paragraph",
			Content: []adfNode{{Type: "text", Text: text}},
		}},
	}}
}
