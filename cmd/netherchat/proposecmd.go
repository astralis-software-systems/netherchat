package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/client"
)

// proposeCmd implements `netherchat propose` (NC-W1): a headless proposer that joins
// a room, broadcasts an artifact proposal (an agent-produced artifact awaiting human
// approval — by hash, never content), lingers briefly so the proposal fans out, then
// disconnects. The proposer can never approve its own proposal (the second law), so
// it does not stay to seal — a human approver writes the record entry.
func proposeCmd(args []string) {
	fs := flag.NewFlagSet("propose", flag.ExitOnError)
	url := fs.String("server", "ws://localhost:3000", "server URL")
	room := fs.String("room", "", "room to propose into (required)")
	source := fs.String("source", "", "agent/tool label, e.g. requirements-agent (required)")
	ref := fs.String("ref", "", "artifact title or reference id (required)")
	hash := fs.String("hash", "", "hex SHA-256 of the artifact CONTENT — never the content (required)")
	summary := fs.String("summary", "", "one-line human-readable description")
	name := fs.String("name", "", "display name in the room (default: the source label)")
	identity := fs.String("identity", "", "identity key file (default: BYO-key cascade)")
	invite := fs.String("invite", "", "one-time invite token, if the room is invite-only")
	quorum := fs.Int("quorum", 1, "human approvers required to seal (the proposer never counts)")
	linger := fs.Duration("linger", 1500*time.Millisecond, "how long to stay connected after proposing, so the proposal fans out")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netherchat propose --room <room> --source <agent> --ref <ref> --hash <sha256> [--summary <line>] [--server ws://...]")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	if *room == "" || *source == "" || *ref == "" || *hash == "" {
		fs.Usage()
		os.Exit(2)
	}
	dispName := *name
	if dispName == "" {
		dispName = *source
	}
	room0 := strings.TrimPrefix(*room, "#")
	c := dial(*url, room0, dispName, *identity, *invite, 15*time.Second)
	defer c.Close()

	if err := waitForKey(c, 10*time.Second); err != nil {
		fatal(err)
	}
	id, err := c.Propose(*source, *ref, *hash, *summary, *quorum)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("proposed artifact %q (id %s, source %s) — awaiting %d human approval(s)\n", *ref, id, *source, *quorum)
	// Linger so the relay fans the proposal out to present members before we leave.
	time.Sleep(*linger)
}

// approveArtifactCmd implements `netherchat approve-artifact` (NC-W1): a headless
// human approver that joins a room, waits for an artifact proposal, approves it (an
// agent can never self-approve), and — with --seal — seals the resulting record and
// writes it to --out. Used by scripts/demo-attest.sh to automate the loop.
func approveArtifactCmd(args []string) {
	fs := flag.NewFlagSet("approve-artifact", flag.ExitOnError)
	url := fs.String("server", "ws://localhost:3000", "server URL")
	room := fs.String("room", "", "room to watch for a proposal (required)")
	proposalID := fs.String("proposal", "", "proposal id to approve (default: the first one seen)")
	name := fs.String("name", "approver", "display name in the room")
	identity := fs.String("identity", "", "identity key file (default: BYO-key cascade)")
	invite := fs.String("invite", "", "one-time invite token, if the room is invite-only")
	seal := fs.Bool("seal", false, "after approval, seal the record and write it to --out")
	out := fs.String("out", "record.json", "where to write the sealed record (with --seal)")
	wait := fs.Duration("wait", 120*time.Second, "how long to wait for a proposal to arrive")
	// The credential this approver acts under, and which of its roles. --role is
	// only ever needed when the attestation names more than one; with one, it
	// resolves itself, and with no attestation there is no signed set to name.
	attestation := fs.String("attestation", "", "your identity attestation (identity.json), carried with the approval")
	role := fs.String("role", "", "which of the roles your attestation names to approve as (only needed when it names more than one)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netherchat approve-artifact --room <room> [--proposal <id>] [--attestation <identity.json> [--role <role>]] [--seal --out record.json] [--server ws://...]")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	if *room == "" {
		fs.Usage()
		os.Exit(2)
	}
	if *attestation == "" && *role != "" {
		fatal(fmt.Errorf("--role %q needs an --attestation: a role has to be one an issuer signed into your credential", *role))
	}
	// Read and parse BEFORE dialing, so a typo in a path does not join a room.
	var credential *attest.IdentityAttestation
	if *attestation != "" {
		a, err := readAttestation(*attestation)
		if err != nil {
			fatal(err)
		}
		credential = a
	}
	room0 := strings.TrimPrefix(*room, "#")
	c := dial(*url, room0, *name, *identity, *invite, 15*time.Second)
	defer c.Close()
	if credential != nil {
		if err := c.UseIdentity(credential); err != nil {
			fatal(err)
		}
	}

	// One unified event loop from connect (like `netherchat tail`): print readiness
	// when the key is established and capture the first matching proposal. A single
	// loop avoids any window where an event is consumed by one wait helper and not
	// seen by the next.
	prop := watchForProposal(c, *proposalID, room0, *wait)
	fmt.Printf("approving artifact %q (id %s, source %s, hash %s)\n", prop.ArtifactRef, prop.ProposalID, prop.Source, prop.ArtifactHash)
	if err := c.ApproveArtifact(prop.ProposalID, *role); err != nil {
		fatal(err)
	}
	// Wait until the artifact entry is written (we are the completing approver for
	// quorum 1; for higher quorums this fires when the last approver completes it).
	waitForSealed(c, *wait)
	fmt.Println("artifact approved and written into the record chain")

	if !*seal {
		return
	}
	// Give any other members (e.g. the transient proposer) a moment to leave so the
	// seal finalizes promptly, then seal and write the record.
	drainBriefly(c, 2*time.Second)
	if err := c.Seal(); err != nil {
		fatal(err)
	}
	rec := waitForSealComplete(c, 35*time.Second)
	b, err := rec.Record.Marshal()
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		fatal(err)
	}
	fmt.Printf("sealed record written to %s (%d entr%s, %d signer(s))\n", *out, rec.Entries, plural(rec.Entries, "y", "ies"), rec.Signers)
}

// --- small headless event helpers -------------------------------------------

// watchForProposal runs a single event loop from connect: it prints a readiness
// line once the room key is established (so an orchestrator knows we are a present
// member), then returns the first artifact proposal matching wantID (or any).
func watchForProposal(c *client.Client, wantID, room string, timeout time.Duration) client.EvArtifactProposed {
	deadline := time.After(timeout)
	announced := false
	for {
		select {
		case ev := <-c.Events():
			switch p := ev.(type) {
			case client.EvKeyReady:
				if !announced {
					announced = true
					// Readiness: a proposal sent before this would be lost (no replay),
					// so the demo waits for this line before proposing.
					fmt.Printf("approve-artifact ready: watching #%s for a proposal\n", room)
				}
			case client.EvArtifactProposed:
				if wantID == "" || strings.HasPrefix(p.ProposalID, wantID) {
					return p
				}
			}
		case <-c.Done():
			fatal(fmt.Errorf("disconnected before a proposal arrived"))
		case <-deadline:
			fatal(fmt.Errorf("timed out waiting for an artifact proposal"))
		}
	}
}

func waitForSealed(c *client.Client, timeout time.Duration) {
	deadline := time.After(timeout)
	for {
		select {
		case ev := <-c.Events():
			if _, ok := ev.(client.EvArtifactSealed); ok {
				return
			}
		case <-c.Done():
			fatal(fmt.Errorf("disconnected before the artifact was sealed"))
		case <-deadline:
			fatal(fmt.Errorf("timed out waiting for the artifact to be approved"))
		}
	}
}

func waitForSealComplete(c *client.Client, timeout time.Duration) client.EvSealComplete {
	deadline := time.After(timeout)
	for {
		select {
		case ev := <-c.Events():
			if s, ok := ev.(client.EvSealComplete); ok {
				return s
			}
		case <-c.Done():
			fatal(fmt.Errorf("disconnected before the seal completed"))
		case <-deadline:
			fatal(fmt.Errorf("timed out waiting for the seal to complete"))
		}
	}
}

// drainBriefly consumes events for d (letting transient members leave), so a
// subsequent seal sees a quiesced room and finalizes promptly.
func drainBriefly(c *client.Client, d time.Duration) {
	deadline := time.After(d)
	for {
		select {
		case <-c.Events():
		case <-c.Done():
			return
		case <-deadline:
			return
		}
	}
}
