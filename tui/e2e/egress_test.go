// Structural guard for the relay's egress claim, a sibling of
// TestServerBinaryDoesNotLinkClientCrypto in e2e_test.go.
//
// README.md and the package doc of cmd/netherchat-server both state that the relay
// makes no outbound network calls out of the box, and name the opt-in exceptions
// exactly. That precision is only as good as the next pull request: an http.Post
// added anywhere under server/ would silently falsify a public claim. These two
// tests make the claim checkable instead of asserted.
//
// # WHY AST AND NOT A REGEX SOURCE SCAN
//
// The alternative — `go list -deps` plus grepping the source for "http.Post(" and
// friends — is defeatable by things that are not even adversarial: an aliased
// import (`import nethttp "net/http"`), a call split across lines, a matching
// string inside a comment or a test fixture producing a false positive. Parsing
// gives exact answers to exactly the questions that matter: which package does
// each identifier in this file actually refer to, and is this a real selector
// expression rather than text that looks like one. `go list` still does the part
// it is good at — telling us which packages the server binary links — and go/ast
// does the part grep is bad at. Comments and string literals cannot produce a
// finding, because parsing without parser.ParseComments never puts them in the
// tree, and a string is a BasicLit rather than a SelectorExpr.
//
// WHAT THIS DOES NOT COVER, STATED PLAINLY
//
//   - Only first-party packages are parsed. A third-party dependency's own source
//     is not scanned, so TestServerEgressModuleDepsAllowlisted below pins the set
//     of modules that reach the server binary at all — a new library cannot enter
//     the relay without a visible diff, whatever it does inside.
//   - Egress reached purely through an interface whose concrete implementation is
//     injected from outside the linked graph is not visible here. Anything that
//     actually constructs a client in server code does reference one of the
//     watched identifiers, so this is a narrow gap, not a general escape hatch.
//   - The relay is an HTTP *server*; inbound handling is not egress and is not
//     flagged. Only the client-side half of net/http is watched.
package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const (
	// netherchatModule is this repository's module path. Packages outside it are
	// third-party and are covered by the module allowlist instead.
	netherchatModule = "github.com/salehkreiner/netherchat"

	// serverMainPkg is the relay binary. Its dependency graph — not the whole
	// repository — is the scope of both tests. The connectors under
	// cmd/netherchat-* are separate binaries that legitimately call out to Slack,
	// Teams, PagerDuty and so on; they are not in this graph and never trip these
	// guards.
	serverMainPkg = netherchatModule + "/cmd/netherchat-server"

	// egressGuardFile is named in failure messages so the fix is one click away.
	egressGuardFile = "tui/e2e/egress_test.go"
)

// egressAPI is the watch list: for each package that can open an outbound
// connection, the identifiers that mean "this code can dial out". Types count,
// not just functions — a package that names http.Client has the capability even
// if the Get is a method call the parser cannot attribute on its own.
//
// Inbound-only identifiers are deliberately absent. http.Handler, http.Request,
// http.ResponseWriter, http.StatusOK, net.Listen and tls.Config appear all over
// the relay and must never be findings, or the guard becomes noise and someone
// eventually deletes it.
var egressAPI = map[string]map[string]bool{
	"net/http": {
		"Get": true, "Post": true, "PostForm": true, "Head": true,
		"NewRequest": true, "NewRequestWithContext": true,
		"DefaultClient": true, "DefaultTransport": true,
		"Client": true, "Transport": true, "RoundTripper": true,
		"ProxyFromEnvironment": true, "ProxyURL": true,
	},
	"net/http/httputil": {
		// A reverse proxy is egress: it opens a connection to an upstream.
		"ReverseProxy": true, "NewSingleHostReverseProxy": true,
		"DumpRequestOut": true, "NewClientConn": true, "NewProxyClientConn": true,
	},
	"net": {
		"Dial": true, "DialTimeout": true, "DialIP": true, "DialTCP": true,
		"DialUDP": true, "DialUnix": true, "Dialer": true,
		// Name resolution is an outbound packet too.
		"LookupHost": true, "LookupIP": true, "LookupAddr": true, "LookupCNAME": true,
		"LookupMX": true, "LookupNS": true, "LookupSRV": true, "LookupTXT": true,
		"Resolver": true,
	},
	"crypto/tls": {"Dial": true, "DialWithDialer": true, "Client": true},
	"net/smtp":   {"Dial": true, "SendMail": true, "NewClient": true},
	// The relay only ever Accepts WebSocket connections. Dial would mean the relay
	// is connecting to something.
	"github.com/coder/websocket": {"Dial": true},
	// Starting tor launches a process that joins the tor network.
	"github.com/cretz/bine/tor": {"Start": true},
}

// egressAllowance is one approved outbound call site, keyed by package rather
// than by file or line so that ordinary refactoring — moving a function between
// files in the same package, reordering, reformatting, renaming an import alias —
// does not disturb it. Only moving egress into a *different* package, which is a
// real change to where the relay can call out from, needs an edit here.
type egressAllowance struct {
	Pkg     string   // full import path
	Refs    []string // canonical "<pkgname>.<Ident>" references, alias-independent
	Feature string   // the operator-facing switch that turns this on
	Why     string   // what it calls, and what makes it opt-in
}

// allowedEgress is the complete list of outbound call sites permitted in the
// relay. It is the machine-readable form of the sentence in README.md and in the
// cmd/netherchat-server package doc. Adding an entry is a deliberate act with a
// diff a reviewer will see; that is the entire point of keeping it here.
var allowedEgress = []egressAllowance{
	{
		Pkg:     netherchatModule + "/server/internal/api",
		Refs:    []string{"http.NewRequestWithContext", "http.DefaultClient"},
		Feature: "a [[route]] with a reply_url",
		Why: "postReply POSTs a spawned war room's join links to the operator-configured " +
			"reply_url. No reply_url in the config means no call is ever constructed.",
	},
	{
		Pkg:     netherchatModule + "/server",
		Refs:    []string{"tor.Start"},
		Feature: "--tor",
		Why: "startOnion launches a local tor daemon and publishes a v3 onion service. " +
			"Off unless --tor is passed, and the tor binary is the operator's to install.",
	},
	{
		Pkg:     serverMainPkg,
		Refs:    []string{"http.Client"},
		Feature: "--healthcheck",
		Why: "runHealthcheck GETs http://127.0.0.1:<port>/health so the FROM-scratch image " +
			"can declare a Docker HEALTHCHECK without a shell or curl. Loopback only, and " +
			"only when the process is started with --healthcheck.",
	},
}

// TestServerEgressCallSitesAllowlisted parses every first-party package the relay
// binary links and fails when it finds an outbound-network call site that is not
// on allowedEgress — or an allowlist entry that no longer corresponds to real
// code, which would mean the documented claim has drifted the other way.
func TestServerEgressCallSitesAllowlisted(t *testing.T) {
	pkgs := serverLinkedPackages(t)

	firstParty := 0
	found := map[string]token.Position{} // "pkg\x00ref" -> where we first saw it
	fset := token.NewFileSet()

	for _, p := range pkgs {
		if p.Module == nil || p.Module.Path != netherchatModule {
			continue // third-party: covered by the module allowlist instead
		}
		firstParty++
		for _, name := range p.GoFiles { // GoFiles is what the binary compiles: no _test.go
			file := filepath.Join(p.Dir, name)
			refs, err := scanFileForEgress(fset, file)
			if err != nil {
				t.Fatalf("scanning %s: %v", file, err)
			}
			for _, r := range refs {
				key := p.ImportPath + "\x00" + r.Ref
				if _, seen := found[key]; !seen {
					found[key] = r.Pos
				}
			}
		}
	}

	// A graph this small means go list matched nothing useful; failing loudly beats
	// a green test that inspected an empty set.
	if firstParty < 5 {
		t.Fatalf("only %d first-party packages found in the %s dependency graph; the guard is not inspecting anything", firstParty, serverMainPkg)
	}
	t.Logf("scanned %d first-party packages linked by %s", firstParty, serverMainPkg)

	allowed := map[string]egressAllowance{}
	for _, a := range allowedEgress {
		for _, ref := range a.Refs {
			allowed[a.Pkg+"\x00"+ref] = a
		}
	}

	var unexpected []string
	for key, pos := range found {
		if _, ok := allowed[key]; ok {
			continue
		}
		pkg, ref, _ := strings.Cut(key, "\x00")
		unexpected = append(unexpected, fmt.Sprintf("  %s\n      in package %s\n      at %s", ref, pkg, pos))
	}
	sort.Strings(unexpected)

	if len(unexpected) > 0 {
		t.Errorf(`the relay gained %d outbound-network call site(s) that are not on the allowlist:

%s

netherchat-server is documented as making NO outbound network calls out of the box, with
a named, closed set of opt-in exceptions. A new call site makes that claim false.

If the call is INTENTIONAL, three things change together:
  1. add it to allowedEgress in %s, with the operator switch that gates it
  2. update the egress sentence in README.md ("Encrypted messaging" section)
  3. update the package doc of cmd/netherchat-server/main.go

If it is NOT intentional, remove the call — do not widen the allowlist to make the
build green.`, len(unexpected), strings.Join(unexpected, "\n\n"), egressGuardFile)
	}

	var stale []string
	for key, a := range allowed {
		if _, ok := found[key]; ok {
			continue
		}
		pkg, ref, _ := strings.Cut(key, "\x00")
		stale = append(stale, fmt.Sprintf("  %s in package %s (allowed for: %s)", ref, pkg, a.Feature))
	}
	sort.Strings(stale)

	if len(stale) > 0 {
		t.Errorf(`allowedEgress permits %d call site(s) that no longer exist in the relay:

%s

An allowlist that over-permits is not a guard. If the feature was removed or moved to a
different package, drop or move the entry in %s — and if an exception is gone, the claim
in README.md and cmd/netherchat-server/main.go can now be made stronger. Say so there.`,
			len(stale), strings.Join(stale, "\n"), egressGuardFile)
	}
}

// allowedServerModules pins which third-party modules reach the relay binary, and
// why. The AST scan above cannot see inside a dependency's source, so this is what
// stops a new library from quietly adding egress the relay would then perform on
// its own: no module gets into the server binary without an edit here.
//
// Modules, not packages: a dependency bump reshuffles package sets constantly, and
// GOOS reshuffles them too (golang.org/x/sys/windows here, golang.org/x/sys/unix on
// the CI runner), so pinning package paths would be unworkable noise. Module paths
// are far steadier — but they are NOT platform-independent, and an earlier version
// of this comment claimed they were. That claim is what made the miss plausible:
// github.com/google/uuid reaches the binary through modernc.org/libc's unix build
// files, so it is absent on Windows, present on Linux and macOS. A green Windows run
// was read as proof, and it reached main and went red on the CI runner.
//
// The whole matrix is therefore the unit of truth, not the host:
// TestServerEgressModuleDepsAllowlisted checks the UNION over every released
// platform. Which means an entry below can be legitimately absent from YOUR build —
// see the presence notes on the platform-conditional ones. Version numbers are
// deliberately not pinned; go.mod and go.sum already do that job.
var allowedServerModules = map[string]string{
	netherchatModule:                  "this module",
	"github.com/coder/websocket":      "the relay's WebSocket transport (Accept only; see egressAPI)",
	"github.com/pelletier/go-toml/v2": "parses netherchat.toml",
	"golang.org/x/time":               "rate limiting",
	"golang.org/x/crypto":             "hkdf for the at-rest key; ed25519/sha3 for the onion key",

	// --tor, opt-in. bine drives a local tor process; x/net supplies the SOCKS
	// dialer bine needs. Present in the binary either way, exercised only with --tor.
	"github.com/cretz/bine": "embedded tor controller behind --tor",
	"golang.org/x/net":      "socks/proxy dialer, pulled in by github.com/cretz/bine",

	// Optional SQLite persistence (off by default). Pure Go, which is what keeps
	// CGO_ENABLED=0 true; the cost is this dependency tail.
	"modernc.org/sqlite":               "pure-Go SQLite driver for [persistence]",
	"modernc.org/libc":                 "modernc.org/sqlite runtime",
	"modernc.org/mathutil":             "modernc.org/sqlite dependency",
	"modernc.org/memory":               "modernc.org/sqlite dependency",
	"github.com/dustin/go-humanize":    "modernc.org/sqlite dependency",
	"github.com/ncruces/go-strftime":   "modernc.org/sqlite dependency; windows and darwin only",
	"github.com/mattn/go-isatty":       "modernc.org/libc dependency; windows and darwin only",
	"github.com/google/uuid":           "modernc.org/libc dependency, via its unix build files; linux and darwin only",
	"github.com/remyoudompheng/bigfft": "modernc.org/mathutil dependency",
	"golang.org/x/sys":                 "syscall shims for modernc.org/libc and x/crypto",
}

// serverBuildTargets is the platform matrix the relay is released for, mirroring the
// netherchat-server build in .goreleaser.yaml (goos: [linux, darwin, windows] x
// goarch: [amd64, arm64]). Every entry is a binary a user can download, so every
// entry is covered by the egress claim and belongs in the union below.
//
// GOARCH is enumerated even though no module currently enters or leaves on
// architecture alone. modernc.org/libc does carry per-arch files, and "we checked a
// subset and it looked fine" is the precise reasoning this guard now exists to
// refuse. All six `go list` invocations together take well under a second.
var serverBuildTargets = []struct{ GOOS, GOARCH string }{
	{"linux", "amd64"}, {"linux", "arm64"},
	{"darwin", "amd64"}, {"darwin", "arm64"},
	{"windows", "amd64"}, {"windows", "arm64"},
}

// TestServerEgressModuleDepsAllowlisted fails when a module that is not on
// allowedServerModules enters the relay binary's dependency graph on ANY released
// platform.
//
// It resolves the graph once per entry in serverBuildTargets and checks the union,
// because the module set is GOOS-conditional and a host-only check is not a check:
// github.com/google/uuid enters through modernc.org/libc's unix build files, so the
// host run on a Windows machine went green and the Linux runner went red. The union
// puts that failure on the developer's own terminal, before the push.
//
// The check stays one-directional: an unlisted module fails, a listed module that is
// absent does not. Absence is now a weaker signal than it looks — a module can be
// missing from every target here and still be real on a platform outside the release
// matrix — so a stale entry is left to review rather than turned into a red build.
func TestServerEgressModuleDepsAllowlisted(t *testing.T) {
	seen := map[string]string{} // module path -> "example package (on the first platform it appeared)"
	platforms := make([]string, 0, len(serverBuildTargets))
	counts := make([]string, 0, len(serverBuildTargets))

	for _, tgt := range serverBuildTargets {
		platform := tgt.GOOS + "/" + tgt.GOARCH
		platforms = append(platforms, platform)

		onThisPlatform := map[string]bool{}
		for _, p := range serverLinkedPackagesFor(t, tgt.GOOS, tgt.GOARCH) {
			if p.Module == nil {
				continue // standard library: no module, and vendored by the toolchain
			}
			onThisPlatform[p.Module.Path] = true
			if _, ok := seen[p.Module.Path]; !ok {
				seen[p.Module.Path] = fmt.Sprintf("%s (on %s)", p.ImportPath, platform)
			}
		}

		// Per-platform, not just the union: a target that silently resolved to an
		// empty or truncated graph would otherwise hide inside a healthy total.
		if len(onThisPlatform) < 2 {
			t.Fatalf("found %d modules for %s in the %s dependency graph; the guard is not inspecting anything", len(onThisPlatform), platform, serverMainPkg)
		}
		counts = append(counts, fmt.Sprintf("%s=%d", platform, len(onThisPlatform)))
	}

	t.Logf("%d modules reach %s across %d platforms (%s)", len(seen), serverMainPkg, len(serverBuildTargets), strings.Join(counts, " "))

	var unexpected []string
	for mod, example := range seen {
		if _, ok := allowedServerModules[mod]; ok {
			continue
		}
		unexpected = append(unexpected, fmt.Sprintf("  %s\n      first reached via %s", mod, example))
	}
	sort.Strings(unexpected)

	if len(unexpected) > 0 {
		t.Errorf(`the relay binary gained %d third-party module(s) not on the allowlist:

%s

Every module here runs inside netherchat-server, so each one is trusted with the "no
outbound network calls out of the box" claim that README.md makes on the relay's behalf.
This list exists so that trust is granted deliberately rather than inherited from a
transitive upgrade.

This is the UNION over every released platform, so the module named above may well be
absent from a build on your own machine — build constraints decide, and the platform it
was found on is named with it. Checking only the host is how github.com/google/uuid
reached main. Platforms checked:

  %s

If the dependency is INTENTIONAL, add it to allowedServerModules in %s with a one-line
reason — and if it can call out, say which operator switch gates that, and update the
egress claim in README.md and cmd/netherchat-server/main.go to match.`,
			len(unexpected), strings.Join(unexpected, "\n\n"), strings.Join(platforms, ", "), egressGuardFile)
	}
}

// --- plumbing ---------------------------------------------------------------

// goListPkg holds the `go list -json` fields these guards need.
type goListPkg struct {
	ImportPath string
	Dir        string
	GoFiles    []string
	Module     *struct{ Path string }
}

// serverLinkedPackages returns every package the relay binary links on the host
// platform, in dependency order.
func serverLinkedPackages(t *testing.T) []goListPkg {
	t.Helper()
	return serverLinkedPackagesFor(t, "", "")
}

// serverLinkedPackagesFor returns every package the relay binary links when built
// for goos/goarch, in dependency order. Empty strings mean the host platform.
//
// Unlike the crypto boundary guard next door this does not skip when the toolchain
// is unavailable: a guard that can silently not run is not a guard, and `go test`
// running at all means `go list` is there. That applies per platform — a target that
// cannot be resolved is a failure, not a quietly smaller union.
func serverLinkedPackagesFor(t *testing.T, goos, goarch string) []goListPkg {
	t.Helper()

	platform := "the host platform"
	cmd := exec.Command("go", "list", "-deps", "-json=ImportPath,Dir,GoFiles,Module", serverMainPkg)
	if goos != "" {
		platform = goos + "/" + goarch
		// go list reads build constraints from the environment, which is the whole
		// mechanism here: it makes another platform's module set visible from this
		// one. CGO_ENABLED is pinned to the value every real build uses (see
		// .goreleaser.yaml and CLAUDE.md) so that a developer machine with a C
		// compiler installed does not resolve the host target differently from the
		// cross ones — that asymmetry is the same bug in a smaller costume.
		// A later Env entry wins over an earlier one, so these override the inherited
		// values rather than colliding with them.
		cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0")
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -deps %s for %s: %v\n%s", serverMainPkg, platform, err, stderr.String())
	}

	var pkgs []goListPkg
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p goListPkg
		if err := dec.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("decoding go list output for %s: %v", platform, err)
		}
		pkgs = append(pkgs, p)
	}
	if len(pkgs) == 0 {
		t.Fatalf("go list -deps %s for %s returned no packages", serverMainPkg, platform)
	}
	return pkgs
}

// egressRef is one watched identifier found in the source.
type egressRef struct {
	Ref string // "<pkgname>.<Ident>", e.g. "http.DefaultClient"
	Pos token.Position
}

// scanFileForEgress parses one Go file and reports the watched identifiers it
// references. The returned Ref uses the imported package's real name rather than
// whatever local alias the file chose, so `import nethttp "net/http"` and a plain
// import produce the same allowlist key.
func scanFileForEgress(fset *token.FileSet, file string) ([]egressRef, error) {
	f, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}

	// Resolve, per file, which local identifiers refer to a watched package.
	local := map[string]string{} // local name -> import path
	for _, imp := range f.Imports {
		importPath, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		if _, watched := egressAPI[importPath]; !watched {
			continue
		}
		name := path.Base(importPath)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		switch name {
		case "_":
			continue // blank import: cannot be called through
		case ".":
			// A dot-import would put Get and Dial into file scope unqualified,
			// where this scan cannot see them. Refuse rather than under-report.
			return nil, fmt.Errorf("dot-import of %q defeats the egress guard; import it normally", importPath)
		}
		local[name] = importPath
	}
	if len(local) == 0 {
		return nil, nil
	}

	var refs []egressRef
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			return true // e.g. a.b.C — not a package qualifier
		}
		importPath, ok := local[id.Name]
		if !ok || !egressAPI[importPath][sel.Sel.Name] {
			return true
		}
		refs = append(refs, egressRef{
			Ref: path.Base(importPath) + "." + sel.Sel.Name,
			Pos: fset.Position(sel.Pos()),
		})
		return true
	})
	return refs, nil
}
