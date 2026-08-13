package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/server"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/output"
)

// encryptionSuite is the v1 content-encryption stack (ARCHITECTURE_DECISION.md §3).
const encryptionSuite = "NaCl:X25519+XChaCha20-Poly1305"

// entropyFloor is the bits/byte below which relay-visible ciphertext would look
// suspiciously structured. Real XChaCha20-Poly1305 output sits ~7.9+; 7.5 leaves
// margin for the finite sample while still rejecting plaintext/base64 (≤6).
const entropyFloor = 7.5

// doctorReport is the result of `netherchat doctor`, and its --json shape (§3.1).
type doctorReport struct {
	Reachable       bool            `json:"reachable"`
	Server          string          `json:"server,omitempty"`
	ProtocolVersion int             `json:"protocol_version,omitempty"`
	Encryption      string          `json:"encryption,omitempty"`
	Identity        string          `json:"identity,omitempty"`
	Paranoid        *paranoidReport `json:"paranoid,omitempty"`
}

// paranoidReport is the relay-blindness proof.
type paranoidReport struct {
	FramesCaptured int     `json:"frames_captured"`
	CanaryFound    bool    `json:"canary_found"`
	Entropy        float64 `json:"entropy"`
	RelayBlind     bool    `json:"relay_blind"`

	canary string // for human output only; never serialized
}

// ok reports overall health, which drives the process exit code.
func (r *doctorReport) ok(paranoid bool) bool {
	if !r.Reachable {
		return false
	}
	if paranoid {
		return r.Paranoid != nil && r.Paranoid.RelayBlind
	}
	return true
}

// doctorCmd implements `netherchat doctor [--paranoid] [--server ws://...] [--json]`
// (§3.1). Without --paranoid it is a connectivity/version/identity check against
// --server. With --paranoid it stands up its own tapped relay and PROVES the
// relay cannot read message content — the demo that converts skeptics.
func doctorCmd(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	url := fs.String("server", "ws://localhost:3000", "relay to check (ignored with --paranoid, which runs its own tapped relay)")
	paranoid := fs.Bool("paranoid", false, "prove relay blindness: round-trip a canary through a tapped local relay and assert the bytes are ciphertext")
	jsonMode := fs.Bool("json", false, "emit the report as JSON")
	identity := fs.String("identity", "", "identity file path (default: ssh-agent → ~/.ssh/id_ed25519 → generated)")
	timeout := fs.Duration("timeout", 10*time.Second, "max time to wait for connect / key / canary")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netherchat doctor [--paranoid] [--server ws://...] [--json]")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	var (
		rep *doctorReport
		err error
	)
	if *paranoid {
		rep, err = runParanoid(*identity, *timeout)
	} else {
		rep, err = runBasic(*url, *identity, *timeout)
	}
	if err != nil {
		output.Fatal(*jsonMode, err)
	}

	if *jsonMode {
		_ = output.WriteJSON(rep)
	} else {
		printDoctorHuman(rep, *paranoid)
	}
	if !rep.ok(*paranoid) {
		os.Exit(1)
	}
}

// runBasic checks connectivity, version, encryption, and identity against a relay.
func runBasic(url, identityPath string, timeout time.Duration) (*doctorReport, error) {
	rep := &doctorReport{Server: url, Encryption: encryptionSuite}
	c, err := client.New(url, "doctor", defaultName(), identityPath)
	if err != nil {
		return nil, err // identity could not be loaded — a real error, not "unreachable"
	}
	rep.Identity = c.Fingerprint()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		return rep, nil // unreachable: report it (reachable=false) and exit non-zero
	}
	defer c.Close()
	rep.Reachable = true
	rep.ProtocolVersion = protocol.Version
	// Establishing the room key confirms the E2E handshake actually works, not just
	// that the socket opened. A failure here leaves Reachable=true but unhealthy.
	if err := waitForKey(c, timeout); err != nil {
		rep.Encryption = ""
	}
	return rep, nil
}

// runParanoid stands up a frame-tapped local relay, round-trips a canary between
// two real clients, and asserts the relay-visible bytes never contain the canary
// and are statistically indistinguishable from random (§3.1). The relay it tests
// is the SAME relay code that runs in production — the proof is of the
// implementation, which is the honest thing it can prove.
func runParanoid(identityPath string, timeout time.Duration) (*doctorReport, error) {
	tap := &frameTap{}
	ts := httptest.NewServer(server.HandlerWithTap(config.Default(), tap.add, discardLogger()))
	defer ts.Close()

	// Sender uses the operator's real identity (it is THEIR message proven
	// unreadable); the receiver is an ephemeral peer, present so the message is
	// actually broadcast and decrypts on the far side.
	sender, err := client.New(ts.URL, "doctor", "doctor-sender", identityPath)
	if err != nil {
		return nil, err
	}
	defer sender.Close()
	if err := connectAndKey(sender, timeout); err != nil {
		return nil, fmt.Errorf("paranoid: sender connect: %w", err)
	}
	receiver, err := client.NewEphemeral(ts.URL, "doctor", "doctor-receiver")
	if err != nil {
		return nil, err
	}
	defer receiver.Close()
	if err := connectAndKey(receiver, timeout); err != nil {
		return nil, fmt.Errorf("paranoid: receiver connect: %w", err)
	}
	if err := awaitMember(sender, "doctor-receiver", timeout); err != nil {
		return nil, fmt.Errorf("paranoid: %w", err)
	}

	// A unique canary, padded so its ciphertext is a large enough sample for a
	// meaningful entropy estimate (a few dozen bytes cannot reach ~8 bits/byte).
	canary := "NETHERCHAT-CANARY-" + randomHex(16)
	if err := sender.Send(canary + strings.Repeat(".", 4096)); err != nil {
		return nil, fmt.Errorf("paranoid: send canary: %w", err)
	}
	// Wait until the receiver decrypts it: proves the frame really traversed the
	// relay (so the tap holds it) AND that the legitimate peer CAN read what the
	// relay cannot.
	if err := awaitMessageContains(receiver, canary, timeout); err != nil {
		return nil, fmt.Errorf("paranoid: receiver never got the canary: %w", err)
	}

	pr := analyzeFrames(tap.snapshot(), canary)
	pr.canary = canary
	return &doctorReport{
		Reachable: true, Server: ts.URL, ProtocolVersion: protocol.Version,
		Encryption: encryptionSuite, Identity: sender.Fingerprint(), Paranoid: &pr,
	}, nil
}

// analyzeFrames is the blindness verdict over the captured relay frames. It is a
// pure function so the proof — and its failure mode — are unit-testable: the
// canary must appear in NONE of the raw frames, and the accumulated message
// ciphertext must look random.
func analyzeFrames(frames [][]byte, canary string) paranoidReport {
	canaryBytes := []byte(canary)
	found := false
	var cipher []byte
	for _, f := range frames {
		if bytes.Contains(f, canaryBytes) {
			found = true
		}
		var env protocol.Envelope
		if err := json.Unmarshal(f, &env); err != nil {
			continue
		}
		// Sealed payloads (chat + exec/ack/record/seal) all carry a Message; pull
		// the raw ciphertext out for the entropy estimate.
		if env.Type == protocol.OpMessage {
			var m protocol.Message
			if env.Decode(&m) == nil {
				cipher = append(cipher, m.Ciphertext...)
				if bytes.Contains(m.Ciphertext, canaryBytes) {
					found = true
				}
			}
		}
	}
	ent := shannonEntropy(cipher)
	return paranoidReport{
		FramesCaptured: len(frames),
		CanaryFound:    found,
		Entropy:        ent,
		RelayBlind:     !found && ent >= entropyFloor,
	}
}

// shannonEntropy returns the Shannon entropy of b in bits per byte (0 for empty).
// Random bytes approach 8; structured data (JSON, base64, plaintext) sits lower.
func shannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	n := float64(len(b))
	var h float64
	for _, cnt := range counts {
		if cnt == 0 {
			continue
		}
		p := float64(cnt) / n
		h -= p * math.Log2(p)
	}
	return h
}

// frameTap collects copies of raw relay-visible frames. Safe for the relay's
// per-connection goroutines to call concurrently.
type frameTap struct {
	mu     sync.Mutex
	frames [][]byte
}

func (t *frameTap) add(raw []byte) {
	cp := append([]byte(nil), raw...) // the websocket lib reuses its buffer; copy
	t.mu.Lock()
	t.frames = append(t.frames, cp)
	t.mu.Unlock()
}

func (t *frameTap) snapshot() [][]byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([][]byte, len(t.frames))
	copy(out, t.frames)
	return out
}

// connectAndKey connects c and waits for its room key to establish.
func connectAndKey(c *client.Client, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := c.Connect(ctx); err != nil {
		return err
	}
	return waitForKey(c, timeout)
}

// awaitMember waits until c observes a member with the given display name join.
func awaitMember(c *client.Client, name string, timeout time.Duration) error {
	deadline := time.After(timeout)
	for {
		select {
		case ev := <-c.Events():
			if e, ok := ev.(client.EvMemberJoined); ok && e.Name == name {
				return nil
			}
		case <-c.Done():
			return errors.New("disconnected while waiting for " + name)
		case <-deadline:
			return errors.New("timed out waiting for " + name + " to join")
		}
	}
}

// awaitMessageContains waits for a decrypted message containing want.
func awaitMessageContains(c *client.Client, want string, timeout time.Duration) error {
	deadline := time.After(timeout)
	for {
		select {
		case ev := <-c.Events():
			if e, ok := ev.(client.EvMessage); ok && !e.Self && strings.Contains(e.Text, want) {
				return nil
			}
		case <-c.Done():
			return errors.New("disconnected")
		case <-deadline:
			return errors.New("timed out")
		}
	}
}

// discardLogger silences the embedded paranoid relay (its logs are noise to the
// person reading a doctor report).
func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// randomHex returns 2n hex chars of cryptographic randomness.
func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// printDoctorHuman renders the report as a checklist.
func printDoctorHuman(r *doctorReport, paranoid bool) {
	mark := func(ok bool) string {
		if ok {
			return "✓"
		}
		return "✗"
	}
	if r.Reachable {
		output.WriteHuman("%s server reachable (%s)\n", mark(true), r.Server)
	} else {
		output.WriteHuman("%s server unreachable (%s)\n", mark(false), r.Server)
	}
	if r.ProtocolVersion > 0 {
		output.WriteHuman("%s protocol version: %d\n", mark(true), r.ProtocolVersion)
	}
	if r.Encryption != "" {
		output.WriteHuman("%s encryption: %s\n", mark(true), r.Encryption)
	}
	if r.Identity != "" {
		output.WriteHuman("%s identity: %s\n", mark(true), r.Identity)
	}

	if paranoid && r.Paranoid != nil {
		p := r.Paranoid
		output.WriteHuman("%s sent canary message: %s\n", mark(true), p.canary)
		output.WriteHuman("%s relay-visible frames: %d (message bodies sealed; routing fields plaintext)\n",
			mark(true), p.FramesCaptured)
		output.WriteHuman("%s canary %s in any relay frame  ← this is the proof\n",
			mark(!p.CanaryFound), foundWord(p.CanaryFound))
		output.WriteHuman("%s frame entropy: %.2f bits/byte (consistent with random ciphertext)\n",
			mark(p.Entropy >= entropyFloor), p.Entropy)
		if p.RelayBlind {
			output.WriteHuman("%s relay is blind — it cannot read your messages\n", mark(true))
		} else {
			output.WriteHuman("%s relay blindness NOT confirmed\n", mark(false))
		}
	}
}

func foundWord(found bool) string {
	if found {
		return "FOUND"
	}
	return "NOT found"
}
