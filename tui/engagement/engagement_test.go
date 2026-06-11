package engagement

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
	"github.com/salehkreiner/netherchat/tui/record"
)

func TestInitGeneratesPackage(t *testing.T) {
	out := t.TempDir()
	m, err := Init(Options{
		Name:        "acme-q3",
		Client:      "Acme",
		Consultants: []string{"alice", "bob"},
		Rooms:       []string{"ops", "findings"},
		OutDir:      out,
		Quorum:      2,
	})
	if err != nil {
		t.Fatalf("init: %v", err)
	}

	dir := filepath.Join(out, "acme-q3")
	for _, f := range []string{
		"netherchat.toml", "docker-compose.yml", "README.md", "trust-pins.txt",
		"engagement.json",
		filepath.Join("identities", "identity-alice.json"),
		filepath.Join("identities", "identity-bob.json"),
		filepath.Join("records", "README.md"),
	} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("expected %s: %v", f, err)
		}
	}
	if len(m.Consultants) != 2 {
		t.Fatalf("consultants = %d, want 2", len(m.Consultants))
	}
	for _, c := range m.Consultants {
		if !strings.HasPrefix(c.Fingerprint, "SHA256:") {
			t.Errorf("consultant %s has odd fingerprint %q", c.Handle, c.Fingerprint)
		}
	}
}

// TestGeneratedTOMLLoadsAndMatches is the crux of C1: the generated netherchat.toml
// must parse under the REAL server config and carry the rooms, action quorums, and
// trust pins (matching the generated identities) we promised.
func TestGeneratedTOMLLoadsAndMatches(t *testing.T) {
	out := t.TempDir()
	m, err := Init(Options{
		Name:        "eng",
		Consultants: []string{"alice"},
		Rooms:       []string{"ops"},
		OutDir:      out,
		Quorum:      2,
	})
	if err != nil {
		t.Fatalf("init: %v", err)
	}

	b, err := os.ReadFile(filepath.Join(out, "eng", "netherchat.toml"))
	if err != nil {
		t.Fatalf("read toml: %v", err)
	}
	cfg, err := config.Parse(b)
	if err != nil {
		t.Fatalf("generated netherchat.toml does not parse: %v", err)
	}

	room, ok := cfg.Rooms["ops"]
	if !ok {
		t.Fatal("room ops missing from generated config")
	}
	if !room.InviteOnly || !room.Webhook || room.WebhookToken == "" {
		t.Errorf("room ops not provisioned as expected: %+v", room)
	}
	if q := cfg.ActionQuorum("scuttle"); q != 2 {
		t.Errorf("scuttle quorum = %d, want 2", q)
	}
	if q := cfg.ActionQuorum(protocol.ActionBreakGlass); q != 2 {
		t.Errorf("break-glass quorum = %d, want 2", q)
	}

	// The trust pin must match the generated consultant identity's fingerprint.
	if len(cfg.Trust) != 1 || cfg.Trust[0].Handle != "alice" {
		t.Fatalf("trust pins = %+v, want one for alice", cfg.Trust)
	}
	if cfg.Trust[0].Fpr != m.Consultants[0].Fingerprint {
		t.Errorf("trust pin fpr %q != manifest fingerprint %q", cfg.Trust[0].Fpr, m.Consultants[0].Fingerprint)
	}
}

func TestInitRefusesOverwrite(t *testing.T) {
	out := t.TempDir()
	opts := Options{Name: "dup", Consultants: []string{"alice"}, OutDir: out}
	if _, err := Init(opts); err != nil {
		t.Fatalf("first init: %v", err)
	}
	if _, err := Init(opts); err == nil {
		t.Error("second init into the same dir should refuse to overwrite")
	}
}

func TestInitValidation(t *testing.T) {
	out := t.TempDir()
	cases := []Options{
		{Name: "", Consultants: []string{"a"}, OutDir: out},          // empty name
		{Name: "x", Consultants: nil, OutDir: out},                   // no consultants
		{Name: "../escape", Consultants: []string{"a"}, OutDir: out}, // path traversal in name
		{Name: "ok", Consultants: []string{"a/b"}, OutDir: out},      // bad handle
		{Name: "ok2", Consultants: []string{"a", "a"}, OutDir: out},  // duplicate handle
	}
	for i, c := range cases {
		if _, err := Init(c); err == nil {
			t.Errorf("case %d (%+v) should have errored", i, c)
		}
	}
}

func TestClose(t *testing.T) {
	dir := t.TempDir()
	recDir := filepath.Join(dir, "records")
	if err := os.MkdirAll(recDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A valid sealed record, and a tampered one.
	writeFile(t, filepath.Join(recDir, "a-valid.json"), sealedRecord(t, "ops-room", false))
	writeFile(t, filepath.Join(recDir, "z-tampered.json"), sealedRecord(t, "ops-room", true))

	path, rep, err := Close(dir, "")
	if err != nil {
		t.Fatalf("close: %v", err)
	}
	if rep.Total != 2 || rep.Verified != 1 {
		t.Fatalf("verified %d/%d, want 1/2", rep.Verified, rep.Total)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	s := string(body)
	if !strings.Contains(s, "1 of 2 verified offline") {
		t.Errorf("report missing the verification summary:\n%s", s)
	}
	if !strings.Contains(s, "rotate the signing keys") {
		t.Errorf("report missing the sealed decision body:\n%s", s)
	}
	if !strings.Contains(s, "NOT VERIFIED") {
		t.Errorf("report should flag the tampered record:\n%s", s)
	}
}

// sealedRecord builds a one-decision sealed record. If tamper is set, the room is
// changed after sealing, so the seal signature (room-bound) no longer verifies.
func sealedRecord(t *testing.T, room string, tamper bool) []byte {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	author := record.Author{ID: id.Fingerprint(), Name: "alice", Key: id.SignPub, Sign: id.Sign}
	ch := record.NewChain()
	if _, err := ch.AppendNew(author, record.KindDecision, "", "rotate the signing keys"); err != nil {
		t.Fatal(err)
	}
	head := ch.Head()
	sig, err := id.Sign(protocol.SealSigningBytes(room, head))
	if err != nil {
		t.Fatal(err)
	}
	fpr := id.Fingerprint()
	rec := record.NewSealedRecord(room, fpr, ch.Entries(), head,
		map[string][]byte{fpr: sig}, map[string][]byte{fpr: id.SignPub})
	if tamper {
		rec.Room = "different-room" // seal sig was over `room`; this breaks verification
	}
	b, err := rec.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}
