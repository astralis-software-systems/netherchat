package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
)

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// msgFrame builds a raw relay frame: an OpMessage envelope carrying ciphertext,
// as the tap would capture it.
func msgFrame(t *testing.T, ciphertext []byte) []byte {
	t.Helper()
	env, err := protocol.Encode(protocol.OpMessage, protocol.Message{FromID: "x", Ciphertext: ciphertext})
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestDoctorBasic checks connectivity, version, and identity against a live relay.
func TestDoctorBasic(t *testing.T) {
	ts := httptest.NewServer(server.Handler(config.Default(), discardLogger()))
	defer ts.Close()

	rep, err := runBasic(ts.URL, "", 5*time.Second)
	if err != nil {
		t.Fatalf("runBasic: %v", err)
	}
	if !rep.Reachable {
		t.Fatal("relay should be reachable")
	}
	if rep.ProtocolVersion != protocol.Version {
		t.Errorf("protocol version = %d, want %d", rep.ProtocolVersion, protocol.Version)
	}
	if rep.Identity == "" || !strings.HasPrefix(rep.Identity, "SHA256:") {
		t.Errorf("identity = %q, want a SHA256: fingerprint", rep.Identity)
	}
	if !rep.ok(false) {
		t.Error("a reachable relay with a key should be healthy")
	}
}

// TestDoctorUnreachable proves a dead relay yields a non-healthy report (exit 1),
// not an error.
func TestDoctorUnreachable(t *testing.T) {
	rep, err := runBasic("ws://127.0.0.1:1", "", 2*time.Second)
	if err != nil {
		t.Fatalf("runBasic should report unreachable, not error: %v", err)
	}
	if rep.Reachable || rep.ok(false) {
		t.Errorf("port-1 relay should be unreachable+unhealthy, got %+v", rep)
	}
}

// TestDoctorParanoid is the §3.1 proof end to end: a canary round-trips through a
// real tapped relay and the relay-visible bytes are ciphertext only.
func TestDoctorParanoid(t *testing.T) {
	rep, err := runParanoid("", 20*time.Second)
	if err != nil {
		t.Fatalf("runParanoid: %v", err)
	}
	p := rep.Paranoid
	if p == nil {
		t.Fatal("no paranoid report")
	}
	if p.CanaryFound {
		t.Fatal("canary appeared in a relay frame — the relay is NOT blind")
	}
	if p.Entropy < entropyFloor {
		t.Errorf("frame entropy %.3f below floor %.1f", p.Entropy, entropyFloor)
	}
	if !p.RelayBlind || !rep.ok(true) {
		t.Errorf("relay should be proven blind: %+v", p)
	}
}

// TestAnalyzeFramesDetectsLeak is the tamper test: clean ciphertext reads as
// blind, but a frame that leaks the canary fails the verdict — proving the
// detection is real, not vacuous.
func TestAnalyzeFramesDetectsLeak(t *testing.T) {
	canary := "NETHERCHAT-CANARY-deadbeefcafef00d"
	clean := msgFrame(t, randomBytes(t, 4096))

	blind := analyzeFrames([][]byte{clean}, canary)
	if blind.CanaryFound {
		t.Error("clean ciphertext frames must not contain the canary")
	}
	if blind.Entropy < entropyFloor {
		t.Errorf("random ciphertext entropy %.3f below floor", blind.Entropy)
	}
	if !blind.RelayBlind {
		t.Error("clean frames should read as blind")
	}

	// A frame that leaks the canary in cleartext must be caught.
	leak := []byte(`{"type":"msg","data":{"from_id":"x","ciphertext":"` + canary + ` leaked here"}}`)
	bad := analyzeFrames([][]byte{clean, leak}, canary)
	if !bad.CanaryFound {
		t.Fatal("a frame containing the canary must be detected")
	}
	if bad.RelayBlind {
		t.Error("a leaked canary must fail the blindness verdict")
	}
}

// TestShannonEntropy pins the discriminator: random ≈ 8, constant = 0.
func TestShannonEntropy(t *testing.T) {
	if e := shannonEntropy(nil); e != 0 {
		t.Errorf("entropy(empty) = %v, want 0", e)
	}
	if e := shannonEntropy(bytes.Repeat([]byte{0x42}, 4096)); e != 0 {
		t.Errorf("entropy(constant) = %v, want 0", e)
	}
	if e := shannonEntropy(randomBytes(t, 16384)); e < 7.9 {
		t.Errorf("entropy(random) = %.3f, want ≥ 7.9", e)
	}
}

// TestDoctorReportJSON proves the --json shape round-trips with unknown-field
// rejection (Sprint 3 contract) and never leaks the unexported canary.
func TestDoctorReportJSON(t *testing.T) {
	rep := &doctorReport{
		Reachable: true, Server: "ws://x", ProtocolVersion: protocol.Version,
		Encryption: encryptionSuite, Identity: "SHA256:abc",
		Paranoid: &paranoidReport{FramesCaptured: 2, CanaryFound: false, Entropy: 7.96, RelayBlind: true, canary: "secret"},
	}
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "secret") {
		t.Errorf("the canary value must not be serialized: %s", b)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var got doctorReport
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("--json output has an unknown field: %v\n%s", err, b)
	}
	if !got.Paranoid.RelayBlind {
		t.Error("relay_blind lost in round-trip")
	}
}
