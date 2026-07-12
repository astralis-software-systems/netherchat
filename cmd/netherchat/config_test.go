package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/server/config"
)

// These tests pin the fail-closed config loading (§1.5/D5) and loud provenance (D6):
// a broken config must be an error rather than a silent fall-back to single-actor
// defaults (which is how the two-person rule silently disabled itself), while genuine
// absence is legitimate and surfaced clearly.

func TestLoadClientConfigExplicitMissingIsFatal(t *testing.T) {
	_, _, err := loadClientConfig(filepath.Join(t.TempDir(), "does-not-exist.toml"))
	if err == nil {
		t.Fatal("an explicit --config that cannot be read must be an error (fail closed)")
	}
}

func TestLoadClientConfigExplicitUnparseableIsFatal(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "netherchat.toml")
	if err := os.WriteFile(bad, []byte("this is not = valid : toml ["), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadClientConfig(bad); err == nil {
		t.Fatal("an explicit but unparseable config must be an error (fail closed)")
	}
}

func TestLoadClientConfigCwdUnparseableIsFatal(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "netherchat.toml"), []byte("broken = ["), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir) // auto-discovery finds the present-but-broken config
	if _, _, err := loadClientConfig(""); err == nil {
		t.Fatal("a present-but-unparseable ./netherchat.toml must be an error (fail closed)")
	}
}

func TestLoadClientConfigAbsentIsSingleActorDefault(t *testing.T) {
	t.Chdir(t.TempDir()) // no netherchat.toml here
	cfg, source, err := loadClientConfig("")
	if err != nil {
		t.Fatalf("absent config must not error (legitimate single-actor): %v", err)
	}
	if source != "" {
		t.Fatalf("source = %q, want empty (built-in defaults)", source)
	}
	if q := cfg.ActionQuorum(protocol.ActionScuttleAction); q != 1 {
		t.Fatalf("default scuttle quorum = %d, want 1 (single-actor)", q)
	}
}

func TestConfigProvenanceLineIsLoudOnAbsence(t *testing.T) {
	line := configProvenanceLine(config.Default(), "")
	if !strings.Contains(line, "none found") || !strings.Contains(line, "OFF") {
		t.Fatalf("absent-config provenance must loudly state defaults are on: %q", line)
	}
}

func TestGovernanceSummaryReportsEngagedQuorum(t *testing.T) {
	cfg := config.Default()
	cfg.Actions = map[string]config.ActionPolicy{protocol.ActionScuttleAction: {Quorum: 2}}
	if s := governanceSummary(cfg); !strings.Contains(s, "scuttle quorum 2") {
		t.Fatalf("governance summary should report the engaged quorum: %q", s)
	}
	if s := governanceSummary(config.Default()); !strings.Contains(s, "single-actor") {
		t.Fatalf("default governance summary should say single-actor: %q", s)
	}
}
