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

// A DEFECT FOUND FIVE TIMES IS A CLASS, AND A CLASS GETS A GUARD.
//
// The shape: range over a Go map whose keys are fingerprints or proposal ids, and
// leave the loop early — `return` on the first entry that fails, or `break` on the
// first entry at all. The verdict is unaffected (every signature has to verify, so
// any failure is fatal whichever is met first), but the VALUE A PERSON READS is
// then a function of Go's randomized map iteration:
//
//	attest.VerifyRoster              Phase 2      which co-signature is bad
//	roster_test.go's tamper test     Phase 2      the same defect, in a test
//	attest.VerifyReceipt             Phase 3c     which co-signature is bad
//	record.Verify (seal loop)        Phase 3c     which seal signature is bad
//	record.verifyArtifactApprovals   Phase 3c     which artifact's approval is bad
//	netherchat-itsm's provenance     Phase 3c     which signature a ticket carries
//
// The last three were one import and one directory away from the sweep the prompt
// asked for, which is why this guard is module-wide rather than package-scoped.
//
// WHAT IT ALLOWS. Ranging these maps to COLLECT is fine and common — every report
// renderer does it to build a table — because a loop that visits every entry has
// no order-dependent output. What it forbids is leaving early, because that is
// exactly when "which one did we reach" becomes an answer somebody reads. The fix
// is always the same three lines: collect the keys, sort them, range the slice.

const mapOrderGuardFile = "tui/e2e/map_order_guard_test.go"

// orderSensitiveMaps are the fingerprint- and id-keyed maps whose iteration order
// has reached a human. They are named rather than inferred because a guard over
// "every map in the module" would be unmaintainable and would fire on caches.
var orderSensitiveMaps = map[string]bool{
	"Signatures":        true,
	"SignerKeys":        true,
	"ArtifactApprovals": true,
	"Endorsements":      true,
	"IdentityBindings":  true,
}

// TestNoVerifierLeavesAMapRangeEarly walks every non-test .go file in the module.
func TestNoVerifierLeavesAMapRangeEarly(t *testing.T) {
	root := moduleRootFrom(t, ".")
	ranges := 0
	var findings []string

	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// vendor/, node_modules/ and web/ hold no Go this guard governs.
			if name := info.Name(); name == "node_modules" || name == "vendor" || name == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		af, perr := parser.ParseFile(fset, p, nil, parser.ParseComments)
		if perr != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)

		ast.Inspect(af, func(n ast.Node) bool {
			rng, ok := n.(*ast.RangeStmt)
			if !ok {
				return true
			}
			sel, ok := rng.X.(*ast.SelectorExpr)
			if !ok || !orderSensitiveMaps[sel.Sel.Name] {
				return true
			}
			ranges++
			if why := leavesEarly(rng.Body); why != "" {
				findings = append(findings, fmt.Sprintf("%s:%d: range over .%s %s",
					rel, fset.Position(rng.Pos()).Line, sel.Sel.Name, why))
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking the module: %v", err)
	}

	if ranges == 0 {
		t.Fatalf("no range over %v in non-test source; this guard is inspecting nothing "+
			"(were the fields renamed? update %s)", sortedNames(orderSensitiveMaps), mapOrderGuardFile)
	}
	if len(findings) > 0 {
		sort.Strings(findings)
		t.Fatalf("%d loop(s) leave a map range early:\n  %s\n\n"+
			"Go randomizes map iteration, so the entry such a loop stops on — and therefore the "+
			"fingerprint or id it names to an operator — changes between runs on identical input. "+
			"Collect the keys, sort them, range the slice. Guard: %s",
			len(findings), strings.Join(findings, "\n  "), mapOrderGuardFile)
	}
	t.Logf("%d range(s) over order-sensitive maps, none leaving early", ranges)
}

// leavesEarly reports why a range body's outcome depends on which entry it
// happened to reach first, or "" when it visits them all. Nested loops and
// closures are stepped over: their return and break belong to themselves.
func leavesEarly(body *ast.BlockStmt) string {
	var why string
	var walk func(ast.Node) bool
	walk = func(n ast.Node) bool {
		if why != "" {
			return false
		}
		switch v := n.(type) {
		case *ast.FuncLit, *ast.RangeStmt, *ast.ForStmt:
			if n != ast.Node(body) {
				return false
			}
		case *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
			// A break inside a switch leaves the switch, not the range.
			return false
		case *ast.ReturnStmt:
			why = "returns from inside the loop"
			return false
		case *ast.BranchStmt:
			if v.Tok == token.BREAK {
				why = "breaks out of the loop"
				return false
			}
		}
		return true
	}
	for _, st := range body.List {
		ast.Inspect(st, walk)
	}
	return why
}

func sortedNames(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
