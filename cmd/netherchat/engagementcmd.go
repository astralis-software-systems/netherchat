package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/salehkreiner/netherchat/tui/engagement"
)

// stringList is a repeatable / comma-separated string flag (--consultant alice
// --consultant bob, or --consultant alice,bob).
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*s = append(*s, part)
		}
	}
	return nil
}

// engagementCmd implements `netherchat engagement <init|close>` (C1): generate a
// turnkey, self-contained deployment package per client, and roll the resulting
// sealed records into one consolidated close report. See docs/engagement.md.
func engagementCmd(args []string) {
	if len(args) == 0 {
		engagementUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "init":
		engagementInit(args[1:])
	case "close":
		engagementClose(args[1:])
	case "-h", "--help", "help":
		engagementUsage()
	default:
		fmt.Fprintf(os.Stderr, "netherchat engagement: unknown subcommand %q\n\n", args[0])
		engagementUsage()
		os.Exit(2)
	}
}

func engagementInit(args []string) {
	fs := flag.NewFlagSet("engagement init", flag.ExitOnError)
	name := fs.String("name", "", "engagement name; also the package directory [required]")
	client := fs.String("client", "", "optional client/organization label")
	var consultants stringList
	var rooms stringList
	fs.Var(&consultants, "consultant", "consultant handle; repeatable or comma-separated [at least one required]")
	fs.Var(&rooms, "room", "room to provision; repeatable or comma-separated (default: ops, findings)")
	out := fs.String("out", ".", "parent directory for the package")
	addr := fs.String("addr", ":3000", "relay listen address")
	image := fs.String("image", "salkreiner/netherchat:latest", "relay container image")
	quorum := fs.Int("quorum", 2, "Two-Person-Rule quorum for scuttle/break-glass")
	ttl := fs.String("ttl", "168h", "hard room lifetime")
	idle := fs.String("idle", "2h", "room scuttle idle_after")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netherchat engagement init --name <name> --consultant <handle> [--consultant <handle>...] [flags]")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	if *name == "" {
		fmt.Fprintln(os.Stderr, "netherchat engagement init: --name is required")
		fs.Usage()
		os.Exit(2)
	}

	m, err := engagement.Init(engagement.Options{
		Name:        *name,
		Client:      *client,
		Consultants: consultants,
		Rooms:       rooms,
		OutDir:      *out,
		Addr:        *addr,
		Image:       *image,
		Quorum:      *quorum,
		RoomTTL:     *ttl,
		IdleScuttle: *idle,
	})
	if err != nil {
		fatal(err)
	}

	fmt.Printf("engagement %q ready in %s\n", m.Name, m.Dir)
	fmt.Printf("  rooms:        %s\n", strings.Join(m.Rooms, ", "))
	fmt.Printf("  consultants:  %d (private identities in identities/)\n", len(m.Consultants))
	for _, c := range m.Consultants {
		fmt.Printf("    %-16s %s\n", c.Handle, c.Fingerprint)
	}
	fmt.Printf("\nnext: deliver each identities/identity-<handle>.json to its owner over a secure\n")
	fmt.Printf("channel (they hold private keys — no escrow, no recovery), then run the relay:\n")
	fmt.Printf("  cd %s && docker compose up -d\n", m.Dir)
	fmt.Printf("see %s%cREADME.md for the full checklist.\n", m.Dir, os.PathSeparator)
}

func engagementClose(args []string) {
	fs := flag.NewFlagSet("engagement close", flag.ExitOnError)
	out := fs.String("out", "", "output path (default: <dir>/close-report.md)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netherchat engagement close <engagement-dir> [--out file]")
		fs.PrintDefaults()
	}

	var dir string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		dir = args[0]
		_ = fs.Parse(args[1:])
	} else {
		_ = fs.Parse(args)
		dir = fs.Arg(0)
	}
	if dir == "" {
		fs.Usage()
		os.Exit(2)
	}

	path, rep, err := engagement.Close(dir, *out)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("wrote %s — %d of %d sealed record(s) verified offline\n", path, rep.Verified, rep.Total)
	if rep.Verified < rep.Total {
		fmt.Fprintf(os.Stderr, "warning: %d record(s) did NOT verify — see the report\n", rep.Total-rep.Verified)
	}
}

func engagementUsage() {
	fmt.Fprintln(os.Stderr, `usage: netherchat engagement <subcommand>

  init   --name <name> --consultant <handle> [flags]   generate a turnkey engagement package
  close  <engagement-dir> [--out file]                  consolidate sealed records into a close report

see docs/engagement.md.`)
}
