package clip

import (
	"errors"
	"reflect"
	"testing"
)

// recordingWriter returns a writer that records that it was tried and fails or
// succeeds as told.
func recordingWriter(name string, ok bool, log *[]string) writer {
	return writer{name, func(string) error {
		*log = append(*log, name)
		if ok {
			return nil
		}
		return errors.New(name + " failed")
	}}
}

// TestCopyViaFallbackChain proves the chain tries mechanisms in order and stops
// at the first success — later mechanisms are not tried.
func TestCopyViaFallbackChain(t *testing.T) {
	var tried []string
	ws := []writer{
		recordingWriter("a", false, &tried),
		recordingWriter("b", false, &tried),
		recordingWriter("c", true, &tried),
		recordingWriter("d", true, &tried),
	}
	method, err := copyVia("hello", ws)
	if err != nil {
		t.Fatalf("copyVia err = %v, want nil (c should have succeeded)", err)
	}
	if method != "c" {
		t.Fatalf("method = %q, want c", method)
	}
	if !reflect.DeepEqual(tried, []string{"a", "b", "c"}) {
		t.Fatalf("tried = %v, want [a b c] (d must not be tried after c succeeds)", tried)
	}
}

// TestCopyViaAllFail proves ErrUnavailable when every mechanism fails (the case
// that triggers the stdout last resort in Copy).
func TestCopyViaAllFail(t *testing.T) {
	var tried []string
	ws := []writer{
		recordingWriter("a", false, &tried),
		recordingWriter("b", false, &tried),
	}
	if _, err := copyVia("x", ws); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	if !reflect.DeepEqual(tried, []string{"a", "b"}) {
		t.Fatalf("tried = %v, want both attempted", tried)
	}
}

// TestCopyViaPassesText proves the exact text reaches the winning writer.
func TestCopyViaPassesText(t *testing.T) {
	var got string
	ws := []writer{{"sink", func(s string) error { got = s; return nil }}}
	if _, err := copyVia("the database is on fire", ws); err != nil {
		t.Fatal(err)
	}
	if got != "the database is on fire" {
		t.Fatalf("writer received %q", got)
	}
}
