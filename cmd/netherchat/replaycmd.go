package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/salehkreiner/netherchat/tui/output"
	"github.com/salehkreiner/netherchat/tui/record"
)

// replayCmd implements `netherchat replay <record.json> --into <room>` (§2.7): it
// streams a previously sealed record's entries into a room for a retrospective —
// the room walks the decisions that mattered, signatures intact, without anyone
// re-typing them. The record is fully verified BEFORE a single frame is sent
// (you must not stream tampered minutes), then each entry is broadcast as an
// end-to-end-encrypted record entry flagged "replayed", which receivers render
// dimmed and never re-seal.
//
// The replayed entries keep their original authors' Ed25519 signatures (the
// canonical signed bytes do not include the replayed flag or the room), so they
// verify in the retro room exactly as they did when first recorded. Replay into
// a fresh room; a room that already holds a record chain rejects the stream as a
// fork.
//
// --verify-only checks the record and exits without connecting or streaming (the
// same verdict and exit code as `netherchat verify`), so CI can gate a replay on
// a record that still verifies.
func replayCmd(args []string) {
	fs := flag.NewFlagSet("replay", flag.ExitOnError)
	into := fs.String("into", "", "room to replay the record into (required unless --verify-only)")
	url := fs.String("server", "ws://localhost:3000", "server URL")
	name := fs.String("name", defaultName(), "display name")
	identity := fs.String("identity", "", "identity file path")
	invite := fs.String("invite", "", "one-time invite token for an invite-only room")
	jsonMode := fs.Bool("json", false, "output the result as JSON")
	verifyOnly := fs.Bool("verify-only", false, "verify the record and exit without connecting or streaming")
	timeout := fs.Duration("timeout", 10*time.Second, "max time to wait for the room key")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netherchat replay <record.json> --into <room> [--server ws://...] [--json] [--verify-only]")
		fs.PrintDefaults()
	}
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fs.Usage()
		os.Exit(2)
	}
	path := args[0]
	_ = fs.Parse(args[1:])

	// --verify-only never touches the network: just run the shared verifier.
	if *verifyOnly {
		os.Exit(verifyFile(path, *jsonMode))
	}

	room := strings.TrimPrefix(strings.TrimSpace(*into), "#")
	if room == "" {
		output.Fatal(*jsonMode, errors.New("--into <room> is required (or pass --verify-only to just check the record)"))
	}

	// Load, parse, and verify before connecting: a record that does not verify is
	// never streamed into a room — you would be replaying tampered minutes.
	b, err := os.ReadFile(path)
	if err != nil {
		output.Fatal(*jsonMode, err)
	}
	rec, err := record.Parse(b)
	if err != nil {
		output.Fatal(*jsonMode, err)
	}
	res, err := record.Verify(rec)
	if err != nil {
		output.Fatal(*jsonMode, err)
	}
	if !res.Valid {
		output.Fatal(*jsonMode, fmt.Errorf("refusing to replay a record that does not verify: %s", res.Reason))
	}

	c, err := dialErr(*url, room, *name, *identity, *invite, *timeout)
	if err != nil {
		output.Fatal(*jsonMode, err)
	}
	defer c.Close()

	if err := waitForKey(c, *timeout); err != nil {
		output.Fatal(*jsonMode, err)
	}
	n, err := c.Replay(rec.Entries)
	if err != nil {
		output.Fatal(*jsonMode, err)
	}
	// The protocol has no delivery ack; give the frames a moment to flush to the
	// relay and out to present members before we disconnect (mirrors send).
	time.Sleep(400 * time.Millisecond)

	if *jsonMode {
		_ = output.WriteJSON(replayResult{
			Replayed:   n,
			Room:       room,
			SourceRoom: rec.Room,
			HeadHash:   res.HeadHash,
			Signers:    res.Signers,
		})
		return
	}
	output.WriteHuman("replayed %d entr%s from %s into #%s\n", n, plural(n, "y", "ies"), path, room)
	output.WriteHuman("  source sealed in #%s by %d signer(s); head %s\n", rec.Room, len(res.Signers), res.HeadHash)
}

// replayResult is the --json output of `netherchat replay`: how many entries were
// streamed and the provenance of the source record (its original room, head, and
// the signers whose seal verified before we agreed to replay it).
type replayResult struct {
	Replayed   int      `json:"replayed"`
	Room       string   `json:"room"`        // room we streamed the entries into
	SourceRoom string   `json:"source_room"` // room the record was originally sealed in
	HeadHash   string   `json:"head_hash"`
	Signers    []string `json:"signers"`
}
