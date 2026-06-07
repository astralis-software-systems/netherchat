package server

import (
	"os/exec"
	"testing"
)

// TestTorInstalledMatchesLookPath proves the PATH probe the --tor preflight relies
// on agrees with the actual lookup.
func TestTorInstalledMatchesLookPath(t *testing.T) {
	_, err := exec.LookPath("tor")
	if got, want := TorInstalled(), err == nil; got != want {
		t.Fatalf("TorInstalled() = %v, but exec.LookPath(tor) err == nil is %v", got, want)
	}
}

// TestTorOptionsDefaultDisabled proves the onion listener is opt-in: the zero
// value (and the default no-flag build) never tries to start tor.
func TestTorOptionsDefaultDisabled(t *testing.T) {
	var o TorOptions
	if o.Enabled {
		t.Fatal("zero-value TorOptions must be disabled (TCP-only)")
	}
}
