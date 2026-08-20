// A field added to protocol.Member and left out of one of its construction
// sites compiles, ships, and is silent.
//
// There are three sites and they are field-by-field literals, not copies:
// tui/client's outgoing Hello, the relay's Member built from a received Hello
// (server/internal/ws), and the relay-LESS pair-mode Member built from the same
// Hello (tui/sneakernet). The third is the one that goes missing, and no
// behavioural test can cover it from the outside: interop-live runs a relay, so
// it structurally cannot exercise the sneakernet literal at all.
//
// So this guard reads the literals rather than the behaviour. Every keyed
// protocol.Member / protocol.Hello composite literal in non-test source must
// name every field the struct declares. It fails on the NEXT field too, which
// is the point — the behavioural tests beside it prove today's field travels,
// and this proves tomorrow's cannot be forgotten at one site out of three.
//
// Test files are out of scope on purpose: a test that builds a two-field Member
// to exercise one code path is doing the right thing, and forcing it to name
// every field would make the fixtures lie about what they are testing.
package e2e

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// presenceCarrierGuardFile is named in failures so the fix is one click away.
const presenceCarrierGuardFile = "tui/e2e/presence_carrier_test.go"

// presenceCarriers are the wire structs whose construction sites are
// field-by-field. Both are in package protocol.
var presenceCarriers = []string{"Member", "Hello"}

// carrierLiteral is one construction site found in the tree.
type carrierLiteral struct {
	Type   string // "Member" or "Hello"
	Where  string // rel/path.go:LINE
	Keys   map[string]bool
	Keyed  bool
	Nested bool // written inside another composite literal
}

// moduleRootFrom walks up from dir to the go.mod.
func moduleRootFrom(t *testing.T, dir string) string {
	t.Helper()
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(abs, "go.mod")); err == nil {
			return abs
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			break
		}
		abs = parent
	}
	t.Fatal("cannot locate the module root")
	return ""
}

// walkNonTestGo parses every non-test .go file under the module root and calls
// fn with each. The skipped directories match the identity seam guard's.
func walkNonTestGo(t *testing.T, fn func(rel string, fset *token.FileSet, af *ast.File)) {
	t.Helper()
	root := moduleRootFrom(t, ".")
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case "node_modules", ".git", "terraform-provider-netherchat", "web":
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
			return nil // the build is what catches an unparseable file
		}
		rel, _ := filepath.Rel(root, p)
		fn(filepath.ToSlash(rel), fset, af)
		return nil
	})
	if err != nil {
		t.Fatalf("walking the module: %v", err)
	}
}

// carrierFields reads the declared field names of protocol.Member and
// protocol.Hello from the source, so the guard tracks the struct instead of a
// list somebody has to remember to update.
func carrierFields(t *testing.T) map[string][]string {
	t.Helper()
	want := map[string]bool{}
	for _, n := range presenceCarriers {
		want[n] = true
	}
	out := map[string][]string{}
	walkNonTestGo(t, func(rel string, _ *token.FileSet, af *ast.File) {
		if af.Name.Name != "protocol" {
			return
		}
		for _, d := range af.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok || !want[ts.Name.Name] {
					continue
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok || st.Fields == nil {
					continue
				}
				var names []string
				for _, f := range st.Fields.List {
					for _, n := range f.Names {
						names = append(names, n.Name)
					}
				}
				sort.Strings(names)
				out[ts.Name.Name] = names
			}
		}
	})
	return out
}

// findCarrierLiterals collects every protocol.Member / protocol.Hello composite
// literal in non-test source.
func findCarrierLiterals(t *testing.T) []carrierLiteral {
	t.Helper()
	want := map[string]bool{}
	for _, n := range presenceCarriers {
		want[n] = true
	}
	var out []carrierLiteral
	walkNonTestGo(t, func(rel string, fset *token.FileSet, af *ast.File) {
		nested := map[ast.Node]bool{}
		ast.Inspect(af, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			for _, el := range cl.Elts {
				if kv, ok := el.(*ast.KeyValueExpr); ok {
					if inner, ok := kv.Value.(*ast.CompositeLit); ok {
						nested[inner] = true
					}
				}
			}
			return true
		})
		ast.Inspect(af, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			sel, ok := cl.Type.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "protocol" || !want[sel.Sel.Name] {
				return true
			}
			lit := carrierLiteral{
				Type:   sel.Sel.Name,
				Where:  rel + ":" + itoa(fset.Position(cl.Pos()).Line),
				Keys:   map[string]bool{},
				Keyed:  true,
				Nested: nested[cl],
			}
			for _, el := range cl.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					lit.Keyed = false
					continue
				}
				if id, ok := kv.Key.(*ast.Ident); ok {
					lit.Keys[id.Name] = true
				}
			}
			out = append(out, lit)
			return true
		})
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Where < out[j].Where })
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestEveryPresenceCarrierLiteralNamesEveryField is the guard. An empty literal
// (protocol.Member{}) is exempt: it is a zero value, not a construction site
// that forgot something.
func TestEveryPresenceCarrierLiteralNamesEveryField(t *testing.T) {
	fields := carrierFields(t)
	for _, name := range presenceCarriers {
		if len(fields[name]) == 0 {
			t.Fatalf("could not read the field list of protocol.%s from source; the guard is "+
				"comparing against nothing. Renamed or moved? Update presenceCarriers in %s.",
				name, presenceCarrierGuardFile)
		}
	}

	lits := findCarrierLiterals(t)
	if len(lits) == 0 {
		t.Fatalf("found no protocol.Member or protocol.Hello literal in non-test source; the guard "+
			"is inspecting nothing. Scope and rationale: %s", presenceCarrierGuardFile)
	}

	var findings []string
	seen := map[string]int{}
	for _, lit := range lits {
		if len(lit.Keys) == 0 && lit.Keyed {
			continue // protocol.Member{} — a zero value
		}
		seen[lit.Type]++
		if !lit.Keyed {
			findings = append(findings, lit.Where+": positional protocol."+lit.Type+
				" literal — a field added to the struct changes what every position means")
			continue
		}
		var missing []string
		for _, f := range fields[lit.Type] {
			if !lit.Keys[f] {
				missing = append(missing, f)
			}
		}
		if len(missing) > 0 {
			findings = append(findings, lit.Where+": protocol."+lit.Type+" literal omits "+
				strings.Join(missing, ", "))
		}
	}

	// Anti-vacuity: both carriers must actually be constructed somewhere, or the
	// absence proved above is an absence of literals rather than of omissions.
	for _, name := range presenceCarriers {
		if seen[name] == 0 {
			t.Fatalf("no non-empty protocol.%s literal in non-test source; this guard's whole subject "+
				"is those literals. Guard: %s", name, presenceCarrierGuardFile)
		}
	}

	if len(findings) > 0 {
		sort.Strings(findings)
		t.Fatalf("%d presence-carrier construction site(s) do not name every field:\n  %s\n\n"+
			"protocol.Member and protocol.Hello are copied field by field at three sites — the client's\n"+
			"outgoing Hello, the relay's Member, and the sneakernet coordinator's Member. A field named\n"+
			"at two of them and not the third compiles, ships, and drops silently in relay-less pair\n"+
			"mode, which interop-live runs a relay and therefore cannot catch.\n"+
			"Guard: %s", len(findings), strings.Join(findings, "\n  "), presenceCarrierGuardFile)
	}

	var where []string
	for _, lit := range lits {
		if len(lit.Keys) == 0 {
			continue
		}
		where = append(where, lit.Where+" ("+lit.Type+")")
	}
	t.Logf("checked %d construction site(s) against protocol.Member{%s} and protocol.Hello{%s}:\n  %s",
		len(where), strings.Join(fields["Member"], " "), strings.Join(fields["Hello"], " "),
		strings.Join(where, "\n  "))
}

// TestSneakernetProvisionsThroughOneFunction backs a sentence in
// tui/sneakernet/session.go that would otherwise be a reassurance standing
// exactly where the failure is: "All four Sneakernet entry points go through
// it." Four hand-rolled copies of "build a client, provision it, connect" is the
// same shape as the three field-by-field Member literals, and a fifth entry
// point that built its own client would silently drop the credential in exactly
// the mode nothing else covers.
//
// So: in non-test sneakernet source, client.NewWithIdentity may be called from
// newSessionClient and nowhere else.
func TestSneakernetProvisionsThroughOneFunction(t *testing.T) {
	const owner = "newSessionClient"
	root := moduleRootFrom(t, ".")
	dir := filepath.Join(root, "tui", "sneakernet")

	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	var findings []string
	for _, p := range files {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		af, perr := parser.ParseFile(fset, p, nil, parser.ParseComments)
		if perr != nil {
			continue
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		for _, decl := range af.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || pkg.Name != "client" || sel.Sel.Name != "NewWithIdentity" {
					return true
				}
				calls++
				if fn.Name.Name != owner {
					findings = append(findings, rel+":"+itoa(fset.Position(call.Pos()).Line)+
						": "+fn.Name.Name+" builds its own client instead of calling "+owner)
				}
				return true
			})
		}
	}

	if calls == 0 {
		t.Fatalf("no call to client.NewWithIdentity in tui/sneakernet; either the package stopped "+
			"building clients or this guard is looking in the wrong place. Guard: %s",
			presenceCarrierGuardFile)
	}
	if len(findings) > 0 {
		sort.Strings(findings)
		t.Fatalf("%d Sneakernet entry point(s) build a client outside %s:\n  %s\n\n"+
			"Provisioning (UseIdentity before ConnectWith) lives in that one function. A client built\n"+
			"anywhere else carries no credential, in the one mode interop-live cannot exercise.\n"+
			"Guard: %s", len(findings), owner, strings.Join(findings, "\n  "), presenceCarrierGuardFile)
	}
	t.Logf("%d call(s) to client.NewWithIdentity, all inside %s", calls, owner)
}
