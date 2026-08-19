package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/salehkreiner/netherchat/tui/attest"
	"golang.org/x/crypto/ssh"

	"github.com/salehkreiner/netherchat/tui/output"
)

// attestCmd implements `netherchat attest`: a headless carrier that joins a
// room, places one or more identity attestations into the record chain as typed
// entries, lingers briefly so they fan out, and disconnects. It is the producer
// half of the record carrier — the counterpart of `netherchat propose`, and the
// reason the entry format is exercised by Netherchat itself rather than only by
// a downstream consumer.
//
// It PARSES each file and never verifies it, which is deliberate twice over.
// Verification takes an issuer key and an evaluation time that belong to
// whoever reads the record later, and this process has neither; and a carrier
// that refused to carry a credential because the CARRIER had pinned no issuer
// would make the evidence depend on the producer's configuration. Parsing is a
// structural check — is this an identity/v1 artifact at all — not a verdict, and
// the output says so in as many words.
//
// The entries have to be in the chain before /seal. A record is sealed over its
// head hash, and the amend path admits a co-signature over an unchanged head and
// nothing else, so there is no "attach the credentials afterwards".
func attestCmd(args []string) {
	fs := flag.NewFlagSet("attest", flag.ExitOnError)
	url := fs.String("server", "ws://localhost:3000", "server URL")
	room := fs.String("room", "", "room to place the attestation into (required)")
	name := fs.String("name", "attester", "display name in the room")
	identity := fs.String("identity", "", "identity key file (default: BYO-key cascade)")
	invite := fs.String("invite", "", "one-time invite token, if the room is invite-only")
	linger := fs.Duration("linger", 1500*time.Millisecond, "how long to stay connected afterwards, so the entries fan out")
	var files filePathList
	fs.Var(&files, "file", "an identity.json to place into the record (repeatable)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netherchat attest --room <room> --file <identity.json> [--file <another>] [--server ws://...]")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	if *room == "" || len(files) == 0 {
		fs.Usage()
		os.Exit(2)
	}

	// Read and parse everything BEFORE dialing, so a typo in a path does not join
	// a room and leave half an attestation set in someone's chain.
	atts := make([]*attest.IdentityAttestation, 0, len(files))
	for _, path := range files {
		b, err := os.ReadFile(path)
		if err != nil {
			fatal(err)
		}
		a, err := attest.ParseIdentity(b)
		if err != nil {
			fatal(fmt.Errorf("%s: %w", path, err))
		}
		atts = append(atts, a)
	}

	room0 := strings.TrimPrefix(*room, "#")
	c := dial(*url, room0, *name, *identity, *invite, 15*time.Second)
	defer c.Close()
	if err := waitForKey(c, 10*time.Second); err != nil {
		fatal(err)
	}

	for i, a := range atts {
		if err := c.AttestIdentity(a); err != nil {
			fatal(fmt.Errorf("%s: %w", files[i], err))
		}
		fmt.Printf("carried attestation %s for %s (subject %s) — NOT verified here; a reader supplies the issuer key\n",
			a.Serial, a.Principal, a.Subject)
	}
	fmt.Printf("%d attestation(s) placed in the record for #%s — seal the record to make them evidence\n", len(atts), room0)
	time.Sleep(*linger)
}

// filePathList collects a repeatable --file flag. Unlike stringList it does NOT
// split on commas: a comma is legal in a file path, and silently cutting one in
// half would turn a readable path into two unreadable ones.
type filePathList []string

func (s *filePathList) String() string     { return strings.Join(*s, ", ") }
func (s *filePathList) Set(v string) error { *s = append(*s, v); return nil }

// identityVerifyOpts carries what `netherchat verify` needs to evaluate an
// identity artifact. Both are operator-supplied, because this binary holds no
// trust anchor and this package is where a clock may legitimately be read — the
// no-clock rule is a constraint on the library, not on a command.
type identityVerifyOpts struct {
	issuerPath string // a file of issuer public keys, one per line
	at         string // RFC3339 evaluation time; empty means now
}

// pinned reports whether the operator supplied a trust anchor. Every identity
// path branches on this and nothing else: it is the standalone-inert switch.
func (o identityVerifyOpts) pinned() bool { return o.issuerPath != "" }

// resolve turns the operator's --issuer and --at into the options the identity
// verifier takes: the trust anchors, and the instant the validity windows are
// asked about.
//
// ONE function does this for every artifact family. The record carrier and the
// standalone artifact must not be able to answer "which keys, and as of when"
// differently — that they diverged at all is what let `verify record.json
// --issuer acme-ca.pub` verify nothing while `verify identity.json --issuer
// acme-ca.pub` verified correctly, for a day, in the same binary.
//
// A missing --at defaults to now, which is the CLI's job: VerifyIdentity rejects
// a zero At as an error, and a command is the right place to read a clock —
// the no-clock rule is a constraint on the library.
//
// It must not be called unless o.pinned(); an unpinned caller has to stay on the
// byte-identical path and never reach a key file or a clock.
func (o identityVerifyOpts) resolve() (attest.IdentityOptions, error) {
	keys, err := loadIssuerKeys(o.issuerPath)
	if err != nil {
		return attest.IdentityOptions{}, err
	}
	at := time.Now().UTC()
	if o.at != "" {
		parsed, perr := time.Parse(time.RFC3339, o.at)
		if perr != nil {
			return attest.IdentityOptions{}, fmt.Errorf("--at %q does not parse as RFC3339: %w", o.at, perr)
		}
		at = parsed
	}
	return attest.IdentityOptions{IssuerKeys: keys, At: at}, nil
}

// verifyIdentityBytes parses and reports on an identity attestation.
//
// With NO issuer key it prints the artifact's structural facts and exits
// non-zero, in wording that never says VALID: with no anchor there is no verdict
// to give, and printing one would be the inert-breaking accident this path
// exists to avoid. The exit code is 1 because "I could not check this" is not
// success, and a script must not read it as one.
//
// With an issuer key it prints VALID / INVALID and exits 0/1, and prints the
// evaluated time in the verdict line either way — a bare "VALID identity" claims
// something the tool cannot support, since validity is a property of the
// artifact, the issuer set, AND the time.
func verifyIdentityBytes(b []byte, jsonMode bool, opts identityVerifyOpts) int {
	a, err := attest.ParseIdentity(b)
	if err != nil {
		output.WriteError(jsonMode, err)
		return 1
	}

	if !opts.pinned() {
		if jsonMode {
			_ = output.WriteJSON(struct {
				Artifact  string   `json:"artifact"`
				Checked   bool     `json:"checked"`
				Reason    string   `json:"reason"`
				Subject   string   `json:"subject"`
				Principal string   `json:"principal"`
				Roles     []string `json:"roles"`
				NotBefore string   `json:"not_before"`
				NotAfter  string   `json:"not_after"`
				Issuer    string   `json:"issuer"`
				SignedBy  []string `json:"signed_by"`
			}{
				Artifact: "identity", Checked: false, Reason: "no_issuer_pinned",
				Subject: a.Subject, Principal: a.Principal, Roles: a.Roles,
				NotBefore: a.IssuedAt, NotAfter: a.ExpiresAt,
				Issuer: a.Issuer, SignedBy: sortedSigners(a),
			})
			return 1
		}
		output.WriteHuman("UNVERIFIED identity — no issuer key supplied (--issuer <file>)\n")
		output.WriteHuman("  the fields below are what the FILE says, checked by nobody:\n")
		output.WriteHuman("  subject: %s\n  principal: %s (%s)\n  roles: %s\n",
			a.Subject, a.Principal, a.PrincipalType, strings.Join(a.Roles, ", "))
		output.WriteHuman("  window: %s .. %s\n  names issuer: %s\n", a.IssuedAt, a.ExpiresAt, a.Issuer)
		for _, s := range sortedSigners(a) {
			output.WriteHuman("  signed by: %s\n", s)
		}
		return 1
	}

	iopts, err := opts.resolve()
	if err != nil {
		output.WriteError(jsonMode, err)
		return 1
	}

	res, err := attest.VerifyIdentity(a, iopts)
	if err != nil {
		output.WriteError(jsonMode, err)
		return 1
	}
	if jsonMode {
		_ = output.WriteJSON(res)
		if res.Valid {
			return 0
		}
		return 1
	}
	if !res.Valid {
		output.WriteHuman("INVALID identity — %s (%s) as of %s\n", res.Reason, res.ReasonClass, res.EvaluatedAt)
		if res.Detail != "" {
			output.WriteHuman("  %s\n", res.Detail)
		}
		return 1
	}
	output.WriteHuman("VALID identity — %s (%s) as of %s\n", res.Principal, res.PrincipalType, res.EvaluatedAt)
	output.WriteHuman("  subject: %s\n  roles: %s\n  window: %s .. %s\n",
		res.Subject, strings.Join(res.Roles, ", "), res.NotBefore, res.NotAfter)
	for _, s := range res.VerifiedBy {
		output.WriteHuman("  verified by pinned issuer: %s\n", s)
	}
	if res.Detail != "" {
		output.WriteHuman("  note: %s\n", res.Detail)
	}
	return 0
}

// sortedSigners lists the issuer fingerprints an artifact carries a signature
// under, in sorted order so two runs print the same thing.
func sortedSigners(a *attest.IdentityAttestation) []string {
	out := make([]string, 0, len(a.Signatures))
	for fpr := range a.Signatures {
		out = append(out, fpr)
	}
	sort.Strings(out)
	return out
}

// loadIssuerKeys reads issuer PUBLIC keys from a file: one per line, each either
// base64 of the 32 raw Ed25519 bytes or an OpenSSH "ssh-ed25519 AAAA…" line.
// Blank lines and # comments are skipped.
//
// This is the operator handing the verifier a parameter. Nothing in Netherchat
// looks for this file on its own, there is no default path, and no key ships
// with the binary.
func loadIssuerKeys(path string) ([]ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var keys []ed25519.PublicKey
	for i, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "ssh-ed25519 ") {
			pub, err := parseAuthorizedEd25519(line)
			if err != nil {
				return nil, fmt.Errorf("%s line %d: %w", path, i+1, err)
			}
			keys = append(keys, pub)
			continue
		}
		raw, derr := base64.StdEncoding.DecodeString(line)
		if derr != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%s line %d: not an Ed25519 public key (want base64 of 32 bytes, or an ssh-ed25519 line)", path, i+1)
		}
		keys = append(keys, ed25519.PublicKey(raw))
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%s contains no issuer keys", path)
	}
	return keys, nil
}

// parseAuthorizedEd25519 reads one OpenSSH "ssh-ed25519 AAAA… comment" line and
// returns the raw Ed25519 public key, so an operator can paste an issuer's
// published key line straight into the file instead of re-encoding it.
func parseAuthorizedEd25519(line string) (ed25519.PublicKey, error) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, fmt.Errorf("not a readable OpenSSH public key line: %w", err)
	}
	cpk, ok := pk.(ssh.CryptoPublicKey)
	if !ok {
		return nil, fmt.Errorf("OpenSSH key of type %q carries no raw key", pk.Type())
	}
	pub, ok := cpk.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("OpenSSH key of type %q is not Ed25519", pk.Type())
	}
	return pub, nil
}
