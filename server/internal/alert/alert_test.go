package alert

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/server/config"
)

func sign(secret string, a AlertV1) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(protocol.AlertSigningBytes(a.Source, a.Severity, a.Kind, a.Summary, a.Ref, a.TS))
	return hex.EncodeToString(mac.Sum(nil))
}

func TestParseStrict(t *testing.T) {
	good := `{"source":"scanner","severity":"high","kind":"finding","summary":"s3 public","ref":"CIS-1.20","ts":1700000000}`
	a, err := Parse([]byte(good))
	if err != nil {
		t.Fatalf("good alert rejected: %v", err)
	}
	if a.Source != "scanner" || a.Severity != "high" || a.Kind != "finding" {
		t.Fatalf("fields not parsed: %+v", a)
	}

	bad := map[string]string{
		"unknown field":  `{"source":"s","severity":"h","kind":"k","extra":"x"}`,
		"trailing data":  `{"source":"s","severity":"h","kind":"k"} junk`,
		"missing source": `{"severity":"h","kind":"k"}`,
		"missing kind":   `{"source":"s","severity":"h"}`,
		"not an object":  `["nope"]`,
	}
	for name, raw := range bad {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("%s: expected parse error", name)
		}
	}
}

func TestValidateBounds(t *testing.T) {
	big := make([]byte, MaxSummaryBytes+1)
	for i := range big {
		big[i] = 'x'
	}
	a := AlertV1{Source: "s", Severity: "h", Kind: "k", Summary: string(big)}
	if err := a.Validate(); err == nil {
		t.Error("oversized summary should be rejected")
	}
	long := make([]byte, MaxFieldBytes+1)
	for i := range long {
		long[i] = 'y'
	}
	a = AlertV1{Source: string(long), Severity: "h", Kind: "k"}
	if err := a.Validate(); err == nil {
		t.Error("oversized source should be rejected")
	}
}

func TestToMatchMap(t *testing.T) {
	a := AlertV1{Source: "scanner", Severity: "high", Kind: "finding", Summary: "x", Ref: "r"}
	m := a.ToMatchMap()
	if m["source"] != "scanner" || m["severity"] != "high" || m["kind"] != "finding" {
		t.Fatalf("match map mismatch: %+v", m)
	}
	if _, ok := m["signature"]; ok {
		t.Error("signature must never be a routable field")
	}
}

func TestAuthenticateToken(t *testing.T) {
	src := config.SourceConfig{Name: "s", Token: "sekret"}
	a := AlertV1{Source: "s", Severity: "h", Kind: "k"}
	if err := Authenticate(src, a, "sekret"); err != nil {
		t.Errorf("valid token rejected: %v", err)
	}
	if err := Authenticate(src, a, "wrong"); err == nil {
		t.Error("wrong token accepted")
	}
	if err := Authenticate(config.SourceConfig{Name: "s"}, a, ""); err == nil {
		t.Error("source with no credentials should be rejected")
	}
}

func TestAuthenticateHMAC(t *testing.T) {
	secret := "hmac-secret"
	src := config.SourceConfig{Name: "s", HMACSecret: secret}
	a := AlertV1{Source: "s", Severity: "high", Kind: "finding", Summary: "boom", Ref: "r1", TS: 123}
	a.Signature = sign(secret, a)
	if err := Authenticate(src, a, ""); err != nil {
		t.Fatalf("valid HMAC rejected: %v", err)
	}

	// Tampering any signed field must break the signature.
	tampered := a
	tampered.Severity = "low"
	if err := Authenticate(src, tampered, ""); err == nil {
		t.Error("tampered severity accepted under original signature")
	}

	bad := a
	bad.Signature = "not-hex"
	if err := Authenticate(src, bad, ""); err == nil {
		t.Error("non-hex signature accepted")
	}
	missing := a
	missing.Signature = ""
	if err := Authenticate(src, missing, ""); err == nil {
		t.Error("missing signature accepted for hmac source")
	}
}

// TestAuthenticateBothRequired: when a source declares both a token and an HMAC
// secret, both must pass (defense in depth).
func TestAuthenticateBothRequired(t *testing.T) {
	secret := "sec"
	src := config.SourceConfig{Name: "s", Token: "tok", HMACSecret: secret}
	a := AlertV1{Source: "s", Severity: "h", Kind: "k"}
	a.Signature = sign(secret, a)

	if err := Authenticate(src, a, "tok"); err != nil {
		t.Errorf("valid token+hmac rejected: %v", err)
	}
	if err := Authenticate(src, a, "wrong"); err == nil {
		t.Error("bad token accepted despite good hmac")
	}
	bad := a
	bad.Signature = sign("other", a)
	if err := Authenticate(src, bad, "tok"); err == nil {
		t.Error("bad hmac accepted despite good token")
	}
}

func TestGuardsRateAndSpawn(t *testing.T) {
	g := NewGuards()
	rated := config.SourceConfig{Name: "r", RatePerMinute: 1}
	if !g.AllowRequest(rated) {
		t.Fatal("first request should be allowed")
	}
	if g.AllowRequest(rated) {
		t.Error("second request within the same minute should be rate-limited (burst 1)")
	}

	spawner := config.SourceConfig{Name: "sp", SpawnPerHour: 1}
	if !g.AllowSpawn(spawner) {
		t.Fatal("first spawn should be allowed")
	}
	if g.AllowSpawn(spawner) {
		t.Error("second spawn within the hour should be capped (burst 1)")
	}
}

func TestNilGuardsAllow(t *testing.T) {
	var g *Guards
	if !g.AllowRequest(config.SourceConfig{Name: "x"}) || !g.AllowSpawn(config.SourceConfig{Name: "x"}) {
		t.Error("nil guards must allow everything")
	}
}
