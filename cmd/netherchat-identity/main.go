// Command netherchat-identity is the ISSUER-side tool for Netherchat's
// identity/v2 attestations: it mints an issuing key, signs bindings of a key
// fingerprint to a principal and roles, and signs revocation statements.
//
//	netherchat-identity keygen [--out <path>]
//	netherchat-identity show   [--key <path>]
//	netherchat-identity issue  --subject SHA256:… --principal alice@acme.example --display-name "Alice Reyes" --type person --role qa
//	netherchat-identity revoke --statement-id acme-2026-08-19 --number 42 --serial <serial>
//
// # WHY THIS IS A SEPARATE BINARY
//
// This is a certificate-authority tool. The audience is whoever runs the
// authority, not whoever is in the room, and its whole job is to hold a private
// key that everyone else's verification rests on. Shipping it inside the chat
// client would put CA signing one typo away from an ordinary user and would
// suggest the client is the authority, which is exactly the confusion the seam
// rules exist to prevent: Netherchat holds no trust anchors, and the tool that
// MAKES one should not be the tool that runs a war room.
//
// It reaches Netherchat only through the sealedrecord façade — the same public,
// relay-free API an enterprise CA integration outside this module would use.
// That is deliberate: if this tool can produce a valid attestation with nothing
// but the façade, so can a third party's, and the claim "swap the issuer for
// your organization's CA" is about the FORMAT rather than about this code.
//
// # THE DEFAULT LIFETIME IS A SECURITY PARAMETER
//
// Issuer compromise has no in-format recovery: there is no cross-signature, no
// path validation, and no way to tell a verifier "stop trusting this key" other
// than reaching every verifier and changing what they pinned. And offline
// revocation is weak by construction — a reader with no network checks the
// statement they happen to hold, which may be months stale.
//
// So the validity WINDOW is the only lifecycle mechanism that works everywhere,
// and the default has to be short enough that a credential nobody remembers
// stops working on its own. The default here is 90 days. A lifetime beyond a
// year takes --long-lived, so it is a deliberate act with a visible flag rather
// than a number somebody typed once.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/salehkreiner/netherchat/internal/cliargs"
	"github.com/salehkreiner/netherchat/sealedrecord"
	"golang.org/x/crypto/ssh"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "keygen":
		keygenCmd(os.Args[2:])
	case "show":
		showCmd(os.Args[2:])
	case "issue":
		issueCmd(os.Args[2:])
	case "revoke":
		revokeCmd(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "netherchat-identity: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `netherchat-identity — issue and revoke identity/v2 attestations

usage:
  netherchat-identity keygen [--out <path>]        mint an issuing key (and its .pub)
  netherchat-identity show   [--key <path>]        print the issuer fingerprint to publish
  netherchat-identity issue  --subject <SHA256:…> --principal <id> --type <person|service|agent>
                             --role <r> [--role <r>] [--display-name <name>] [--valid 90d]
                             [--out identity.json]
  netherchat-identity revoke --statement-id <id> --number <n> --serial <s> [--serial <s>]
                             [--reason <text>] [--next-update 30d] [--out revocation.json]

The issuing key is the trust anchor for everyone who pins it. There is no
recovery if it is lost and no in-format recovery if it is stolen: the only
remedy is reaching every verifier and changing what they pinned.

Verifiers pin the PUBLIC key. Publish the .pub line; never the key file.
`)
}

// defaultLifetime is the validity window an attestation gets when the operator
// does not choose one. See the package doc for why this is short.
const defaultLifetime = 90 * 24 * time.Hour

// longLivedThreshold is the point past which issuing takes an explicit flag.
const longLivedThreshold = 365 * 24 * time.Hour

// issuerKeyFile is the on-disk issuing key. The private key is the whole of the
// authority, so the file carries a comment saying so — the same discipline the
// client's own identity file uses.
type issuerKeyFile struct {
	Comment     string `json:"_comment"`
	Version     string `json:"netherchat_issuer_key"`
	Fingerprint string `json:"fingerprint"`
	SignPriv    string `json:"sign_priv"` // base64, 64 bytes
}

const issuerKeyComment = "Netherchat ISSUING key. Everyone who pins this authority trusts whatever it signs. " +
	"Keep it secret and offline where you can. There is NO recovery if it is lost, and no " +
	"in-format recovery if it is stolen."

// defaultIssuerDir returns where an issuing key lives by default.
//
// On Windows this is %LOCALAPPDATA%, NOT %APPDATA%. The difference is not
// cosmetic: on a domain-joined machine %APPDATA% is the roaming profile, which
// is copied to a file server at logon and logoff. Putting a certificate
// authority's private key there hands a copy to the file server, its backups,
// and anyone who can read either — for a key whose whole value is that only one
// party holds it. %LOCALAPPDATA% stays on the machine.
//
// The client's own identity file uses os.UserConfigDir(), which IS %APPDATA%.
// That is a pre-existing choice for a different key with a different blast
// radius, and moving it is scheduled work elsewhere; this tool does not inherit
// it, because a CA key is the one key where roaming is indefensible.
func defaultIssuerDir() (string, error) {
	if goos == "windows" {
		if d := getenv("LOCALAPPDATA"); d != "" {
			return filepath.Join(d, "netherchat", "issuer"), nil
		}
		return "", errors.New("LOCALAPPDATA is not set; pass --out explicitly")
	}
	if d := getenv("XDG_DATA_HOME"); d != "" {
		return filepath.Join(d, "netherchat", "issuer"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share", "netherchat", "issuer"), nil
}

func defaultKeyPath() (string, error) {
	dir, err := defaultIssuerDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "issuer.json"), nil
}

// goos, getenv and stdout are the three things keygen's advisory depends on
// that a test cannot otherwise choose. They are variables so the WINDOWS branch
// is drivable from Linux and the LINUX branch from Windows: roadmap §8 records
// that WSL is structurally blind to OS-conditional behaviour on the platform
// that ships, and a message that only one gate can read is a message only one
// gate can catch being wrong.
var (
	goos             = runtime.GOOS
	getenv           = os.Getenv
	stdout io.Writer = os.Stdout
)

// keygenCmd runs runKeygen and exits on its code. The split is runVerify's, for
// runVerify's reason: everything from argv to the printed advisory has to be
// reachable from a test, and a refusal that calls os.Exit is not.
func keygenCmd(args []string) {
	if code := runKeygen(args); code != 0 {
		os.Exit(code)
	}
}

func runKeygen(args []string) int {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "where to write the issuing key (default: the per-user issuer directory)")
	force := fs.Bool("force", false, "overwrite an existing key file")
	allowNetwork := fs.Bool("allow-network-path", false,
		"write the issuing key to a path this tool can tell is on another host (a UNC share); refused without it")
	cliargs.MustParse("netherchat-identity keygen", fs, args, 0)

	path := *out
	if path == "" {
		p, err := defaultKeyPath()
		if err != nil {
			fatal(err)
		}
		path = p
	}
	// Before os.Stat, and before any key material exists: a stat of a UNC path
	// already reaches the host, and the whole point of the refusal is that
	// nothing about this key touches a machine that is not this one.
	if !*allowNetwork {
		if msg := networkPathRefusal(path); msg != "" {
			fmt.Fprint(os.Stderr, "netherchat-identity: "+msg)
			return 1
		}
	}
	if _, err := os.Stat(path); err == nil && !*force {
		fatal(fmt.Errorf("%s already exists — refusing to overwrite an issuing key without --force", path))
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		fatal(err)
	}
	kf := issuerKeyFile{
		Comment:     issuerKeyComment,
		Version:     "v1",
		Fingerprint: sealedrecord.Fingerprint(pub),
		SignPriv:    base64.StdEncoding.EncodeToString(priv),
	}
	b, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		fatal(err)
	}
	line, err := authorizedKeyLine(pub, "netherchat-issuer")
	if err != nil {
		fatal(err)
	}
	pubPath := strings.TrimSuffix(path, filepath.Ext(path)) + ".pub"
	if err := os.WriteFile(pubPath, []byte(line), 0o644); err != nil {
		fatal(err)
	}

	fmt.Fprintf(stdout, "issuing key written to %s\n", path)
	fmt.Fprintf(stdout, "public key written to %s\n", pubPath)
	fmt.Fprintf(stdout, "fingerprint: %s\n\n", kf.Fingerprint)
	fmt.Fprint(stdout, "Publish the .pub line. Verifiers pin the PUBLIC key, and pinning is the only\n"+
		"thing that makes an attestation mean anything: an unpinned issuer's signature is\n"+
		"never examined. Keep the key file to this machine.\n")
	if a := localityAdvisory(path); a != "" {
		fmt.Fprint(stdout, "\n"+a)
	}
	fmt.Fprint(stdout, "\nFile permissions are set to 0600. On Windows that is advisory: NTFS ACLs are\n"+
		"what actually restrict the file, and this tool does not set them.\n")
	return 0
}

// localityAdvisory returns the paragraph keygen prints about WHERE the key now
// lives, and it is a function of the PATH rather than of the operating system.
//
// It used to be the second of those. The paragraph asserted "This path is under
// %LOCALAPPDATA%, not %APPDATA%" whenever GOOS was windows, whatever --out
// said, so every explicit destination — including the roaming profile the
// paragraph exists to warn about, and a file server — was told the key had
// landed somewhere safe. That is roadmap §8's reassurance defect, and the first
// instance of it found in a runtime message rather than a doc comment
// (docs/phase5-self-hosting-doc-2026-08-21.md §7.3).
//
// The three branches are the three things this tool actually knows, and the
// third is the load-bearing one: an arbitrary path might be a mapped drive or a
// synced folder, and saying nothing there would re-make the same defect one
// level up, where silence reads as safety.
func localityAdvisory(path string) string {
	if goos != "windows" {
		// %APPDATA% and %LOCALAPPDATA% do not exist elsewhere, and a claim
		// invented for another platform would be a new instance of the defect
		// rather than a fix for it. The locality question is real on POSIX too
		// (an --out under an NFS mount is the same hazard) and answering it
		// needs a mount table, which is work this session did not do.
		return ""
	}
	switch {
	case underDir(path, getenv("LOCALAPPDATA")):
		return "This path is under %LOCALAPPDATA%, not %APPDATA%. On a domain-joined machine\n" +
			"%APPDATA% roams to a file server at logon and logoff, which would put a copy of\n" +
			"this key — and of every backup of that server — outside this machine.\n"
	case underDir(path, getenv("APPDATA")):
		return "This path is under %APPDATA%, which is the ROAMING profile. On a domain-joined\n" +
			"machine %APPDATA% is copied to a file server at logon and logoff, which would put\n" +
			"a copy of this key — and of every backup of that server — outside this machine.\n" +
			"Move it under %LOCALAPPDATA% before you log off; the default location\n" +
			"(keygen with no --out) is already there.\n"
	default:
		return "The key is at " + path + ", which is where you asked for it.\n" +
			"This tool cannot tell whether that stays on this machine: a mapped network drive,\n" +
			"a folder a sync client watches, and an ordinary local directory look identical\n" +
			"from here. If it is either of the first two, a copy of this key is already\n" +
			"elsewhere. The default location (keygen with no --out) is under %LOCALAPPDATA%,\n" +
			"which does not roam.\n"
	}
}

// underDir reports whether path is dir or sits inside it, comparing the strings
// the operator actually gave rather than resolving them. Resolution would need
// a filesystem that may not be reachable — the UNC case is refused precisely
// because touching it is the harm — and the question here is only which
// documented profile directory the operator named.
func underDir(path, dir string) bool {
	if dir == "" {
		return false
	}
	norm := func(s string) string {
		s = strings.ReplaceAll(s, `\`, "/")
		if goos == "windows" {
			s = strings.ToLower(s)
		}
		return strings.TrimRight(s, "/")
	}
	p, d := norm(path), norm(dir)
	return p == d || strings.HasPrefix(p, d+"/")
}

// networkPathReason is uncReason bound to this process's OS. It is a variable so
// a test can drive the OVERRIDE path without a writable UNC share.
var networkPathReason = func(path string) string { return uncReason(path, goos) }

// uncReason names the host when path is a UNC share, and returns "" when it is
// not — or when this tool cannot tell, which is most of the time.
//
// The rule is deliberately narrow, and its narrowness is why the advisory above
// still has to be honest about the paths this does not catch. A leading double
// BACKSLASH is a UNC path on Windows and is never a path a person types on
// purpose on POSIX, so it is classified the same way on both and the guard is
// exercised on both gates. The forward-slash spelling is UNC only on Windows,
// where //server/share is a share; on POSIX //mnt/data is an ordinary path and
// refusing it would be a false refusal.
//
// goos is a parameter rather than the package variable so the Windows rule is
// testable from Linux and the POSIX rule from Windows (roadmap §8: WSL is
// structurally blind to OS-conditional behaviour on the platform that ships).
func uncReason(path, goos string) string {
	if len(path) < 3 {
		return ""
	}
	isSep := func(c byte) bool {
		if goos == "windows" {
			return c == '\\' || c == '/'
		}
		return c == '\\'
	}
	if !isSep(path[0]) || !isSep(path[1]) || isSep(path[2]) {
		return ""
	}
	host := path[2:]
	if i := strings.IndexAny(host, `\/`); i >= 0 {
		host = host[:i]
	}
	if host == "" {
		return ""
	}
	return "it names a share on the host " + host
}

// networkPathRefusal is what keygen prints instead of writing an issuing key to
// a destination it can tell is on another machine, or "" when there is nothing
// to refuse.
//
// WARN OR REFUSE, AND WHY THIS ONE REFUSES. A warning is only worth printing if
// the operator can still act on it, and the test separates the two cases in this
// tool cleanly. %APPDATA% roams at LOGOFF, so a warning arrives while the key is
// still only on this machine and moving it is a real option — that one warns. A
// share is written NOW: os.WriteFile returns after the bytes are on the server,
// so any message about it is a notification of an accomplished fact. The key is
// then in that server's storage, in its backups, and on every restore of either,
// and an issuing key has no in-format recovery — no cross-signature, no path
// validation, no way to tell a verifier to stop trusting it short of reaching
// every verifier and changing what they pinned (see this file's package doc).
// Deleting the file does not undo the copy.
//
// So the refusal comes before the key exists, and there is an override, because
// a refusal with no way through pushes an operator who genuinely needs one into
// something worse — and --allow-network-path is the same shape as --force and
// --long-lived elsewhere in this tool: a deliberate act with a visible name.
func networkPathRefusal(path string) string {
	reason := networkPathReason(path)
	if reason == "" {
		return ""
	}
	return "refusing to write an issuing key to " + path + "\n\n" +
		"That path is not on this machine — " + reason + ". A certificate authority's\n" +
		"private key written there is on that host, in its backups, and on every restore\n" +
		"of either. There is no in-format recovery for a stolen issuing key: the only\n" +
		"remedy is reaching every verifier and changing what they pinned, and deleting\n" +
		"the file afterwards does not undo the copy.\n\n" +
		"This is a refusal and not a warning because a warning would come too late — the\n" +
		"key is on the server the moment it is written, before anything could be printed\n" +
		"about it.\n\n" +
		"Write it to this machine and move it deliberately if you must:\n" +
		"  netherchat-identity keygen --out <a path on this machine>\n\n" +
		"Pass --allow-network-path to mean it.\n"
}

func showCmd(args []string) {
	fs := flag.NewFlagSet("show", flag.ExitOnError)
	key := fs.String("key", "", "issuing key file (default: the per-user issuer directory)")
	cliargs.MustParse("netherchat-identity show", fs, args, 0)

	priv, path := mustLoadKey(*key)
	pub := priv.Public().(ed25519.PublicKey)
	line, err := authorizedKeyLine(pub, "netherchat-issuer")
	if err != nil {
		fatal(err)
	}
	fmt.Printf("key file:    %s\n", path)
	fmt.Printf("fingerprint: %s\n", sealedrecord.Fingerprint(pub))
	fmt.Printf("public key:  %s", line)
}

func issueCmd(args []string) {
	fs := flag.NewFlagSet("issue", flag.ExitOnError)
	key := fs.String("key", "", "issuing key file (default: the per-user issuer directory)")
	subject := fs.String("subject", "", "SHA256:… fingerprint of the subject's identity key (required)")
	principal := fs.String("principal", "", "the identifier being bound: a UPN, an email, an employee id (required)")
	displayName := fs.String("display-name", "", "the name this principal is known by, as a directory would show it (optional; signed either way)")
	ptype := fs.String("type", "person", "principal type: person | service | agent (opaque; the library compares it to nothing)")
	valid := fs.String("valid", "90d", "validity window from now: 90d, 12w, 720h")
	serial := fs.String("serial", "", "issuer-unique id for this statement, the unit of revocation (default: generated)")
	out := fs.String("out", "identity.json", "where to write the attestation")
	longLived := fs.Bool("long-lived", false, "permit a window longer than a year")
	var roles roleList
	fs.Var(&roles, "role", "a role the issuer asserts for this principal (repeatable)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netherchat-identity issue --subject SHA256:… --principal <id> --type person --role <r> [--display-name <name>] [--valid 90d]")
		fs.PrintDefaults()
	}
	cliargs.MustParse("netherchat-identity issue", fs, args, 0)

	if *subject == "" || *principal == "" || len(roles) == 0 {
		fs.Usage()
		os.Exit(2)
	}
	lifetime, err := parseLifetime(*valid)
	if err != nil {
		fatal(err)
	}
	if err := checkLifetime(lifetime, *longLived); err != nil {
		fatal(err)
	}

	priv, _ := mustLoadKey(*key)
	pub := priv.Public().(ed25519.PublicKey)
	fpr := sealedrecord.Fingerprint(pub)

	sn := *serial
	if sn == "" {
		sn = generateSerial()
	}

	// --display-name is optional and the tool does not invent one when it is
	// omitted: an empty display name is this authority stating that it asserts no
	// name, which is a different thing from asserting the principal as a name. It
	// is signed either way — the preimage writes the field whether or not it is
	// set — and it is passed through untouched, not trimmed and not case-folded,
	// because a role is treated that way for the same reason and a name is more
	// load-bearing than a role. What a consumer does when it is absent is the
	// consumer's decision; this tool only records what the issuer said.
	spec := sealedrecord.IdentitySpec{
		Serial:        sn,
		Subject:       *subject,
		Principal:     *principal,
		DisplayName:   *displayName,
		PrincipalType: *ptype,
		Roles:         roles,
		ExpiresAt:     time.Now().UTC().Add(lifetime).Format(time.RFC3339),
		Algorithm:     sealedrecord.AlgorithmEd25519,
		Issuer:        fpr,
	}
	// Build unsigned first, sign the preimage that build produced, then attach:
	// issued_at is stamped by the constructor and is inside the signed bytes, so
	// re-running the constructor after signing would sign one moment and ship
	// another.
	unsigned := sealedrecord.NewIdentityAttestation(spec, nil, nil)
	sig := ed25519.Sign(priv, sealedrecord.IdentitySigningBytes(unsigned))
	att := unsigned.WithSignatures(
		map[string][]byte{fpr: sig},
		map[string][]byte{fpr: pub},
	)

	b, err := att.Marshal()
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		fatal(err)
	}
	fmt.Printf("issued %s\n", *out)
	fmt.Printf("  serial:    %s\n  subject:   %s\n  principal: %s (%s)\n",
		att.Serial, att.Subject, att.Principal, att.PrincipalType)
	// The display-name line is printed whether or not there is one. An absence an
	// operator can see is a choice; an absence they cannot see is a surprise later,
	// when a screen shows a UPN where a name was expected.
	if att.DisplayName != "" {
		fmt.Printf("  display:   %s\n", att.DisplayName)
	} else {
		fmt.Printf("  display:   (none — pass --display-name to sign one; consumers show the principal without it)\n")
	}
	fmt.Printf("  roles:     %s\n", strings.Join(att.Roles, ", "))
	fmt.Printf("  window:    %s .. %s\n  issuer:    %s\n", att.IssuedAt, att.ExpiresAt, att.Issuer)
	fmt.Print("\nThis file grants nothing. It is a statement ABOUT a key, and only the holder of\n" +
		"that key can act as the subject, so it is safe to copy anywhere.\n")
}

func revokeCmd(args []string) {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	key := fs.String("key", "", "issuing key file (default: the per-user issuer directory)")
	statementID := fs.String("statement-id", "", "stable id for this statement, recorded in evidence (required)")
	number := fs.Uint64("number", 0, "monotonic statement number; a higher number supersedes (required, from 1)")
	reason := fs.String("reason", "", "opaque cause, applied to every serial in this statement")
	nextUpdate := fs.String("next-update", "", "when a fresher statement is intended: 30d, 720h (reported, never enforced)")
	out := fs.String("out", "revocation.json", "where to write the statement")
	var serials roleList
	fs.Var(&serials, "serial", "a serial to withdraw (repeatable)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netherchat-identity revoke --statement-id <id> --number <n> --serial <s> [--serial <s>]")
		fs.PrintDefaults()
	}
	cliargs.MustParse("netherchat-identity revoke", fs, args, 0)

	if *statementID == "" || *number == 0 || len(serials) == 0 {
		fs.Usage()
		os.Exit(2)
	}

	priv, _ := mustLoadKey(*key)
	pub := priv.Public().(ed25519.PublicKey)
	fpr := sealedrecord.Fingerprint(pub)

	now := time.Now().UTC()
	next := ""
	if *nextUpdate != "" {
		d, err := parseLifetime(*nextUpdate)
		if err != nil {
			fatal(err)
		}
		next = now.Add(d).Format(time.RFC3339)
	}
	revoked := make([]sealedrecord.RevokedSerial, len(serials))
	for i, s := range serials {
		revoked[i] = sealedrecord.RevokedSerial{
			Serial:    s,
			RevokedAt: now.Format(time.RFC3339),
			Reason:    *reason,
		}
	}

	spec := sealedrecord.RevocationSpec{
		Issuer:      fpr,
		StatementID: *statementID,
		Number:      *number,
		NextUpdate:  next,
		Revoked:     revoked,
	}
	unsigned := sealedrecord.NewRevocation(spec, nil, nil)
	sig := ed25519.Sign(priv, sealedrecord.RevocationSigningBytes(unsigned))
	stmt := unsigned.WithSignatures(
		map[string][]byte{fpr: sig},
		map[string][]byte{fpr: pub},
	)

	b, err := stmt.Marshal()
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		fatal(err)
	}
	fmt.Printf("wrote %s — statement %s number %d, %d serial(s)\n", *out, stmt.StatementID, stmt.Number, len(stmt.Revoked))
	fmt.Print("\nA verifier offline checks the statement it HOLDS. What this proves to a later\n" +
		"reader is \"at time T, serial N was not listed by statement R\" — never \"N is not\n" +
		"revoked\". Distribute it, and expect readers to be behind.\n")
}

// roleList collects a repeatable flag without splitting on commas: a role is an
// opaque string matched byte-for-byte downstream, so cutting one at a comma
// would silently change what a signature means.
type roleList []string

func (r *roleList) String() string     { return strings.Join(*r, ", ") }
func (r *roleList) Set(v string) error { *r = append(*r, v); return nil }

// parseLifetime accepts a Go duration plus the day and week suffixes an operator
// will actually type. A credential lifetime in hours is a unit nobody reasons
// about correctly.
func parseLifetime(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return defaultLifetime, nil
	}
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil {
			return 0, fmt.Errorf("%q is not a duration (try 90d, 12w, or 720h)", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	if n, ok := strings.CutSuffix(s, "w"); ok {
		weeks, err := strconv.Atoi(n)
		if err != nil {
			return 0, fmt.Errorf("%q is not a duration (try 90d, 12w, or 720h)", s)
		}
		return time.Duration(weeks) * 7 * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%q is not a duration (try 90d, 12w, or 720h)", s)
	}
	return d, nil
}

// checkLifetime enforces the two rules on a validity window, and it is a
// separate function because the default lifetime is a security parameter and a
// security parameter with no test is a number somebody typed.
//
// A window past a year takes --long-lived. The window is the only lifecycle
// mechanism that works everywhere: a reader offline cannot fetch a fresh
// revocation statement, so a long window is a binding that keeps verifying long
// after anyone is watching, and issuer compromise has no in-format recovery.
func checkLifetime(d time.Duration, longLived bool) error {
	if d <= 0 {
		return errors.New("--valid must be a positive duration")
	}
	if d > longLivedThreshold && !longLived {
		return fmt.Errorf("a %s window is longer than a year; pass --long-lived to mean it.\n"+
			"The validity window is the only lifecycle mechanism that works with no network —\n"+
			"a reader offline checks whatever revocation statement they happen to hold, which\n"+
			"may be months stale — so a long window is a binding nobody can retire", d)
	}
	return nil
}

// generateSerial mints an issuer-unique id: a UTC date for legibility plus eight
// random hex characters so two issued in the same second do not collide. The
// serial is the unit of revocation, so uniqueness is the only property that
// matters and the date is purely for a human reading a revocation list.
func generateSerial() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		fatal(err)
	}
	return time.Now().UTC().Format("20060102") + "-" + hex.EncodeToString(b[:])
}

// mustLoadKey resolves and loads the issuing key, exiting on failure. It returns
// the key and the path it came from.
func mustLoadKey(path string) (ed25519.PrivateKey, string) {
	if path == "" {
		p, err := defaultKeyPath()
		if err != nil {
			fatal(err)
		}
		path = p
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fatal(fmt.Errorf("no issuing key at %s — run: netherchat-identity keygen", path))
		}
		fatal(err)
	}
	var kf issuerKeyFile
	if err := json.Unmarshal(b, &kf); err != nil {
		fatal(fmt.Errorf("parse %s: %w", path, err))
	}
	raw, err := base64.StdEncoding.DecodeString(kf.SignPriv)
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		fatal(fmt.Errorf("%s does not hold an Ed25519 private key", path))
	}
	return ed25519.PrivateKey(raw), path
}

// authorizedKeyLine renders a public key as the OpenSSH line an operator
// publishes, so pinning an issuer is a copy-paste rather than a base64 exercise.
func authorizedKeyLine(pub ed25519.PublicKey, comment string) (string, error) {
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", err
	}
	line := strings.TrimRight(string(ssh.MarshalAuthorizedKey(sshPub)), "\n")
	return line + " " + comment + "\n", nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "netherchat-identity: "+err.Error())
	os.Exit(1)
}
