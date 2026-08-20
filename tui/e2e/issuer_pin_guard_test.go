// Structural guards for the read-side issuer pin (D-L).
//
// The rule the pin lives under is roadmap §6 rule 1 as revised: NO ISSUER
// CONFIGURATION ON ANY PATH THAT PRODUCES EVIDENCE. The old wording — "there is
// no --issuer flag on connect" — was a proxy for it, and a proxy that forbade a
// screen from checking a credential against a key its own operator supplied.
// The revised rule permits that and forbids the thing the old one was protecting:
// a producer making evidence a function of its own configuration.
//
// A rule stated in prose is a rule until somebody adds a line. These are the two
// places a line would have to go, made mechanical:
//
//	the KEYS reach exactly one function          — nothing else can consult them,
//	                                               so nothing else can let them
//	                                               change what it emits
//	the both-names HANDLE RESOLVER reaches only
//	the two commands that report                 — /action writes the handle an
//	                                               operator typed into the record
//	                                               chain, so a resolver that
//	                                               answers to an issuer-signed
//	                                               name must never reach it
//
// Both are verified by construction: §"the deliberate violations" in the D-L
// change record breaks each one and quotes the failure.
package e2e

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const issuerPinGuardFile = "tui/e2e/issuer_pin_guard_test.go"

// issuerPinKeyField is the Model field holding the operator's trust anchors. It
// is named distinctly so this guard can find every reference to it by name
// without type information — rename it and TestTheIssuerPinFieldIsLive fails
// rather than the scope silently emptying.
const issuerPinKeyField = "pinnedIssuerKeys"

// issuerPinReaders are the only functions allowed to name issuerKeys.
//
//	usePin    the single assignment point, so a pin enters the model once
//	attribute the single READ, which is where an IdentityResult comes from
var issuerPinReaders = map[string]string{
	"usePin":    "the one place a pin enters the model",
	"attribute": "the one place a pin is consulted, and the only source of an IdentityResult",
}

// handleResolver answers to a participant's WIRE name and to the name a pinned
// issuer signed. The second half is why its reach is bounded.
const handleResolver = "resolveHandle"

// handleResolverCallers are the commands that REPORT what this client knows
// about a participant. Nothing here puts a name on the wire or into a record.
var handleResolverCallers = map[string]string{
	"runVerify": "/verify — reports a SAS and marks a peer verified in memory",
	"runWhois":  "/whois — prints a fingerprint, a pin status and a carried claim",
}

// tuiSourceFiles parses every non-test .go file under tui/, which is the whole
// client half of the module. The relay cannot reach any of this and neither can
// cmd/, which is where an operator legitimately names a key file.
func tuiSourceFiles(t *testing.T) ([]scopedFile, *token.FileSet) {
	t.Helper()
	root := identityModuleRoot(t)
	fset := token.NewFileSet()
	var out []scopedFile
	err := filepath.Walk(filepath.Join(root, "tui"), func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		af, perr := parser.ParseFile(fset, p, nil, parser.ParseComments)
		if perr != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		out = append(out, scopedFile{Rel: filepath.ToSlash(rel), AST: af, FSet: fset})
		return nil
	})
	if err != nil {
		t.Fatalf("walking tui/: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("parsed no files under tui/; these guards are inspecting nothing")
	}
	return out, fset
}

// identifierSites returns every function that names ident, as
// "file:line: funcName", plus the total number of occurrences.
func identifierSites(files []scopedFile, ident string) (sites []string, total int) {
	for _, f := range files {
		for _, decl := range f.AST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				id, ok := n.(*ast.Ident)
				if !ok || id.Name != ident {
					return true
				}
				total++
				sites = append(sites, fmt.Sprintf("%s:%d: %s", f.Rel,
					f.FSet.Position(id.Pos()).Line, fn.Name.Name))
				return true
			})
		}
	}
	sort.Strings(sites)
	return sites, total
}

func siteFunc(site string) string {
	i := strings.LastIndex(site, ": ")
	if i < 0 {
		return site
	}
	return site[i+2:]
}

// TestTheIssuerPinFieldIsLive is the anti-vacuity check for the guard below. An
// absence proved inside a scope derived from a name is vacuously true the moment
// the name is gone.
func TestTheIssuerPinFieldIsLive(t *testing.T) {
	files, _ := tuiSourceFiles(t)
	_, n := identifierSites(files, issuerPinKeyField)
	if n < 2 {
		t.Fatalf("%q appears %d time(s) in non-test source under tui/. A pin has to be written once and "+
			"read once at minimum; either the field was renamed (update issuerPinKeyField in %s) or "+
			"the read-side pin is gone.", issuerPinKeyField, n, issuerPinGuardFile)
	}
	if _, n := identifierSites(files, handleResolver); n == 0 {
		t.Fatalf("no non-test file under tui/ names %q; the record-path guard below inspects nothing", handleResolver)
	}
}

// TestTheIssuerPinIsReadByOneFunction: the operator's trust anchors reach the
// function that produces an IdentityResult and nothing else.
//
// This is the mechanical form of the revised rule. A future evidence path that
// wanted to consult the pin — a roster that named verified names, an approval
// that carried a checked principal, a record entry stamped with an issuer —
// would have to name this field to do it, and would land here first.
func TestTheIssuerPinIsReadByOneFunction(t *testing.T) {
	files, _ := tuiSourceFiles(t)
	sites, total := identifierSites(files, issuerPinKeyField)

	var strays []string
	for _, s := range sites {
		if _, ok := issuerPinReaders[siteFunc(s)]; !ok {
			strays = append(strays, s)
		}
	}
	if len(strays) > 0 {
		allowed := make([]string, 0, len(issuerPinReaders))
		for fn, why := range issuerPinReaders {
			allowed = append(allowed, fmt.Sprintf("%s — %s", fn, why))
		}
		sort.Strings(allowed)
		t.Fatalf("%d function(s) outside the allowed set name %q:\n  %s\n\n"+
			"Roadmap §6 rule 1, as revised by D-L: no issuer configuration on any path that produces\n"+
			"evidence. The pin decides what a SCREEN renders; a second reader is how it starts\n"+
			"deciding what this client emits. Allowed:\n  %s\nGuard: %s",
			len(strays), issuerPinKeyField, strings.Join(strays, "\n  "),
			strings.Join(allowed, "\n  "), issuerPinGuardFile)
	}
	t.Logf("%q: %d reference(s) across %d allowed function(s)", issuerPinKeyField, total, len(issuerPinReaders))
}

// TestTheRecordPathTakesTheWireHandleOnly: the resolver that answers to an
// issuer-signed name reaches only the commands that report.
//
// /action @handle <text> hands the string an operator typed to the client, which
// puts it in a record entry. If it resolved a signed name, the CONTENT of a
// record would depend on whether its author had pinned a key — evidence as a
// function of the producer's configuration, which is the exact thing the seam
// rule exists to prevent, arriving by the back door D-L opened.
func TestTheRecordPathTakesTheWireHandleOnly(t *testing.T) {
	files, _ := tuiSourceFiles(t)
	sites, total := identifierSites(files, handleResolver)

	var strays []string
	for _, s := range sites {
		fn := siteFunc(s)
		if fn == handleResolver { // the declaration itself
			continue
		}
		if _, ok := handleResolverCallers[fn]; !ok {
			strays = append(strays, s)
		}
	}
	if len(strays) > 0 {
		allowed := make([]string, 0, len(handleResolverCallers))
		for fn, why := range handleResolverCallers {
			allowed = append(allowed, fmt.Sprintf("%s — %s", fn, why))
		}
		sort.Strings(allowed)
		t.Fatalf("%d function(s) outside the allowed set call %q:\n  %s\n\n"+
			"A signed name is a name a READER checked. It addresses a person on the two surfaces that\n"+
			"report what this client knows; it must not select what goes on the wire or into the record,\n"+
			"because those must read the same to everyone regardless of who pinned what. Allowed:\n  %s\n"+
			"Guard: %s",
			len(strays), handleResolver, strings.Join(strays, "\n  "),
			strings.Join(allowed, "\n  "), issuerPinGuardFile)
	}
	t.Logf("%q: %d reference(s), all inside the reporting commands", handleResolver, total)
}

// TestTheAttributionDecisionReadsNoClock. attest never calls time.Now(), which
// is what makes a record re-verifiable forever; the file that decides a LIVE
// row's state keeps the same discipline one layer up. The evaluation time is
// supplied by whatever event triggered the check — a member arriving, or the
// clock tick — so a rendered state carries the instant it was decided at instead
// of the instant somebody happened to redraw.
func TestTheAttributionDecisionReadsNoClock(t *testing.T) {
	files, _ := tuiSourceFiles(t)
	const decisionFile = "tui/ui/app/issuerpin.go"
	var found bool
	for _, f := range files {
		if f.Rel != decisionFile {
			continue
		}
		found = true
		ast.Inspect(f.AST, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok || id.Name != "time" {
				return true
			}
			if sel.Sel.Name == "Now" || sel.Sel.Name == "Since" {
				t.Errorf("%s:%d: time.%s — the attribution decision reads a clock instead of taking one. "+
					"A row would then say what it says because of when it was drawn.",
					f.Rel, f.FSet.Position(sel.Pos()).Line, sel.Sel.Name)
			}
			return true
		})
	}
	if !found {
		t.Fatalf("%s was not parsed; this guard is inspecting nothing (was the file renamed? update %s)",
			decisionFile, issuerPinGuardFile)
	}
}
