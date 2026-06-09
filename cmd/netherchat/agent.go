package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/server/config"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/eventlog"
	"github.com/salehkreiner/netherchat/tui/output"
)

// agentCmd implements `netherchat agent --room <room> --allow runbook.toml`: it
// joins a room as an ordinary E2E member, watches for signed EXEC_REQUEST
// messages, matches each against its OWN local allowlist, runs the mapped command
// on THIS host, and posts a signed EXEC_RESULT back into the room. The relay only
// ever sees ciphertext and never runs anything (FEATURE_ROADMAP_FREE.md §0.1).
func agentCmd(args []string) {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	url := fs.String("server", "ws://localhost:3000", "server URL")
	room := fs.String("room", "", "room to watch (required)")
	allow := fs.String("allow", "", "path to the runbook allowlist TOML (required)")
	name := fs.String("name", agentName(), "display name")
	identity := fs.String("identity", "", "identity key (default: ssh-agent → ~/.ssh/id_ed25519 → generated)")
	maxOutput := fs.Int("max-output", 16<<10, "cap on bytes of command output posted back")
	jsonMode := fs.Bool("json", false, "emit an ndjson exec event stream to stdout (audit log stays on stderr)")
	configPath := fs.String("config", "", "netherchat.toml for [action.runbook] quorum (default: ./netherchat.toml if present)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netherchat agent --room <room> --allow runbook.toml [--config netherchat.toml] [--json] [--server ws://...] [--name <host>]")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	if *room == "" || *allow == "" {
		fs.Usage()
		os.Exit(2)
	}
	rb, err := loadRunbook(*allow)
	if err != nil {
		fatal(err)
	}
	// Two-Person Rule (§1.3): when [action.runbook] quorum > 1, the agent does not
	// run a requested action until quorum independent members co-sign — gating the
	// edge-exec runbook feature behind the cryptographic quorum.
	quorum := loadRunbookQuorum(*configPath)

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	room0 := strings.TrimPrefix(*room, "#")
	c := dial(*url, room0, *name, *identity, "", 15*time.Second)
	defer c.Close()

	log.Info("agent online",
		"room", room0, "identity", c.Fingerprint(), "source", c.Source(), "actions", len(rb), "runbook_quorum", quorum)
	fmt.Fprintf(os.Stderr, "netherchat agent watching #%s as %s — %d allowed action(s), runbook quorum %d\n",
		room0, c.Fingerprint(), len(rb), quorum)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	for {
		select {
		case ev := <-c.Events():
			switch e := ev.(type) {
			case client.EvKeyReady:
				log.Info("room key established; ready for exec requests", "epoch", e.Epoch)
			case client.EvExecRequest:
				if e.Self {
					continue // never act on our own echo
				}
				_, inRunbook := rb[e.Cmd]
				willRun := e.Signed && inRunbook && quorum >= 1
				if *jsonMode {
					_ = output.WriteJSON(eventlog.ExecRequest(room0, e.FromName, e.FromFingerprint, e.Cmd, eventlog.Bool(willRun)))
				}
				if !e.Signed {
					// Refuse to run an unsigned request: we must be able to
					// attribute every action to an identity key.
					log.Warn("exec IGNORED (unsigned request)", "cmd", e.Cmd, "by", e.FromName)
					continue
				}
				if inRunbook && quorum == 0 {
					log.Warn("exec DENIED (runbook disabled: [action.runbook] quorum = 0)", "cmd", e.Cmd, "by", e.FromName)
					_ = c.PostExecResult(e.ID, e.Cmd, false, 0, "runbook execution is disabled by policy (quorum = 0)")
					continue
				}
				if inRunbook && quorum > 1 {
					// Two-Person Rule (§1.3): open an ActionRequest and run the command
					// only once quorum independent members co-sign it. The agent is the
					// initiator (endorser #1) and never self-approves.
					req := e
					params := fmt.Sprintf("cmd=%s, requested_by=%s", e.Cmd, e.FromName)
					if _, err := c.RequestAction(protocol.ActionRunbook, params, quorum, func() {
						go runRunbookAction(c, rb, req, *maxOutput, log, room0, *name, *jsonMode)
					}); err != nil {
						log.Warn("could not open quorum request; not running un-gated", "err", err, "cmd", e.Cmd)
					} else {
						log.Info("exec AWAITING QUORUM", "cmd", e.Cmd, "quorum", quorum, "by", e.FromName)
					}
					continue
				}
				go runRunbookAction(c, rb, e, *maxOutput, log, room0, *name, *jsonMode)
			case client.EvError:
				log.Warn("client error", "err", e.Err)
			}
		case <-c.Done():
			fmt.Fprintln(os.Stderr, "netherchat agent: disconnected")
			return
		case <-ctx.Done():
			return
		}
	}
}

// allowEntry is one runbook action: a name the room uses (Cmd) mapped to a
// concrete command line run on this host, with a timeout.
type allowEntry struct {
	Cmd     string `toml:"cmd"`
	Command string `toml:"command"`
	Timeout string `toml:"timeout"`
}

type runbookFile struct {
	Allow []allowEntry `toml:"allow"`
}

// loadRunbookQuorum reads [action.runbook] quorum from netherchat.toml (§1.3),
// defaulting to ./netherchat.toml if present. A missing/unreadable file means the
// default single-actor behavior (quorum 1).
func loadRunbookQuorum(path string) int {
	if path == "" {
		if _, err := os.Stat("netherchat.toml"); err == nil {
			path = "netherchat.toml"
		}
	}
	if path == "" {
		return 1
	}
	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "netherchat agent: warning: could not read %s: %v\n", path, err)
		return 1
	}
	return cfg.ActionQuorum(protocol.ActionRunbook)
}

// loadRunbook parses runbook.toml into a name→action map.
func loadRunbook(path string) (map[string]allowEntry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read runbook %s: %w", path, err)
	}
	var rf runbookFile
	if err := toml.Unmarshal(b, &rf); err != nil {
		return nil, fmt.Errorf("parse runbook %s: %w", path, err)
	}
	out := make(map[string]allowEntry, len(rf.Allow))
	for _, a := range rf.Allow {
		if a.Cmd == "" || a.Command == "" {
			return nil, fmt.Errorf("runbook %s: every [[allow]] needs both cmd and command", path)
		}
		if _, dup := out[a.Cmd]; dup {
			return nil, fmt.Errorf("runbook %s: duplicate action %q", path, a.Cmd)
		}
		out[a.Cmd] = a
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("runbook %s has no [[allow]] actions", path)
	}
	return out, nil
}

// runRunbookAction is the security-critical core: it ONLY runs commands present
// in the local allowlist, mapped to a fixed command line (no shell, no
// caller-supplied arguments), and logs every attempt — allowed or denied —
// locally on this host. The requester is identified by their key fingerprint.
func runRunbookAction(c *client.Client, rb map[string]allowEntry, e client.EvExecRequest, maxOutput int, log *slog.Logger, room, selfName string, jsonMode bool) {
	emitResult := func(allowed bool, exit int) {
		if jsonMode {
			_ = output.WriteJSON(eventlog.ExecResult(room, selfName, c.Fingerprint(), e.Cmd, allowed, exit))
		}
	}
	entry, ok := rb[e.Cmd]
	if !ok {
		log.Warn("exec DENIED (not in runbook)", "cmd", e.Cmd, "by", e.FromFingerprint, "name", e.FromName)
		_ = c.PostExecResult(e.ID, e.Cmd, false, 0, "")
		emitResult(false, 0)
		return
	}

	timeout := 30 * time.Second
	if entry.Timeout != "" {
		if d, perr := time.ParseDuration(entry.Timeout); perr == nil && d > 0 {
			timeout = d
		}
	}

	log.Info("exec ALLOWED", "cmd", e.Cmd, "command", entry.Command, "by", e.FromFingerprint, "name", e.FromName, "timeout", timeout.String())

	exitCode, out := executeAllowed(entry, timeout, maxOutput)

	log.Info("exec result", "cmd", e.Cmd, "exit", exitCode, "by", e.FromFingerprint)
	if perr := c.PostExecResult(e.ID, e.Cmd, true, exitCode, out); perr != nil {
		log.Warn("failed to post exec result", "err", perr)
	}
	emitResult(true, exitCode)
}

// executeAllowed runs an allowlisted command line (no shell, no caller-supplied
// args) under a timeout and returns the exit code and captured output. It is the
// pure execution core, kept separate from the network/logging plumbing so it can
// be unit-tested.
func executeAllowed(entry allowEntry, timeout time.Duration, maxOutput int) (exitCode int, output string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	argv := strings.Fields(entry.Command)
	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()

	switch {
	case ctx.Err() == context.DeadlineExceeded:
		exitCode = -1
		out = append(out, []byte(fmt.Sprintf("\n[timed out after %s]", timeout))...)
	case err != nil:
		var ee *exec.ExitError
		if errorsAs(err, &ee) {
			exitCode = ee.ExitCode()
		} else {
			exitCode = -1
			out = append(out, []byte("\n["+err.Error()+"]")...)
		}
	}
	if len(out) > maxOutput {
		out = append(out[:maxOutput:maxOutput], []byte("\n…(truncated)")...)
	}
	return exitCode, string(out)
}

func errorsAs(err error, target **exec.ExitError) bool {
	if ee, ok := err.(*exec.ExitError); ok {
		*target = ee
		return true
	}
	return false
}

func agentName() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return "agent@" + h
	}
	return "agent"
}
