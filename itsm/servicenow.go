package itsm

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
)

// serviceNow files records to a ServiceNow instance via the Table API (plain REST,
// no SDK). Attachments go to sys_attachment; the work note is a PATCH to the
// incident record.
func init() {
	register("servicenow", func(cfg Config, prov Provenance) Client { return &serviceNow{cfg: cfg, prov: prov} })
}

type serviceNow struct {
	cfg  Config
	prov Provenance
}

// Attach uploads the record as a sys_attachment bound to the incident, as
// multipart/form-data. The record bytes are sent verbatim as the file part.
func (s *serviceNow) Attach(ticketID string, record []byte, filename string) error {
	return s.cfg.do(func() (*http.Request, error) {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		_ = mw.WriteField("table_name", "incident")
		_ = mw.WriteField("table_sys_id", ticketID)
		_ = mw.WriteField("file_name", filename)
		_ = mw.WriteField("content_type", "application/json")
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
		req, err := http.NewRequest(http.MethodPost, s.cfg.URL+"/api/now/table/sys_attachment", &buf)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.SetBasicAuth(s.cfg.User, s.cfg.Token)
		s.prov.apply(req)
		return req, nil
	})
}

// Comment sets the incident's work_notes via the Table API (PATCH). The summary is
// metadata only.
func (s *serviceNow) Comment(ticketID string, summary string) error {
	body, err := json.Marshal(map[string]string{"work_notes": summary})
	if err != nil {
		return err
	}
	return s.cfg.do(func() (*http.Request, error) {
		req, err := http.NewRequest(http.MethodPatch, s.cfg.URL+"/api/now/table/incident/"+ticketID, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.SetBasicAuth(s.cfg.User, s.cfg.Token)
		s.prov.apply(req)
		return req, nil
	})
}
