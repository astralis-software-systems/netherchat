package sealedrecord

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// TestFacadeReexportsFullPublicSurface enforces that this façade re-exports the
// entire exported surface of the implementation packages (tui/record,
// tui/report, tui/attest). It parses the source of each package and fails if any
// exported top-level declaration (function, type, const, or var — methods come
// along with type aliases automatically) is not also exported by sealedrecord.
//
// This turns "keep the façade in sync" from a manual chore into a build-time
// guarantee: add a new exported symbol to an implementation package and this test
// fails until you either re-export it here or record a deliberate omission in
// notReExported. It uses go/parser (not a `go` subprocess), so it is fast and
// hermetic.
func TestFacadeReexportsFullPublicSurface(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the test source file")
	}
	root := filepath.Dir(thisFile) // .../sealedrecord
	facade := exportedTopLevel(t, root)

	implDirs := []string{
		filepath.Join(root, "..", "tui", "record"),
		filepath.Join(root, "..", "tui", "report"),
		filepath.Join(root, "..", "tui", "attest"),
	}

	// notReExported lists implementation symbols intentionally NOT surfaced on the
	// façade, each mapped to the reason. It is empty by design: the façade mirrors
	// the full public surface. Add an entry here (with a reason) only when a symbol
	// is deliberately kept out of the public API.
	notReExported := map[string]string{}

	var missing []string
	for _, dir := range implDirs {
		pkg := filepath.Base(dir)
		for name := range exportedTopLevel(t, dir) {
			if facade[name] {
				continue
			}
			if _, ok := notReExported[name]; ok {
				continue
			}
			missing = append(missing, pkg+"."+name)
		}
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("sealedrecord façade is missing re-exports for %d symbol(s):\n  %s\n\n"+
			"Add an alias/var to sealedrecord.go, or record a deliberate omission in notReExported with a reason.",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// exportedTopLevel parses every non-test .go file in dir and returns the set of
// exported, package-level declaration names: functions (excluding methods),
// types, consts, and vars.
func exportedTopLevel(t *testing.T, dir string) map[string]bool {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("glob %s: %v", dir, err)
	}
	if len(files) == 0 {
		t.Fatalf("no .go files found in %s", dir)
	}

	out := map[string]bool{}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, decl := range af.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil && d.Name.IsExported() { // top-level func, not a method
					out[d.Name.Name] = true
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.TypeSpec:
						if s.Name.IsExported() {
							out[s.Name.Name] = true
						}
					case *ast.ValueSpec:
						for _, n := range s.Names {
							if n.IsExported() {
								out[n.Name] = true
							}
						}
					}
				}
			}
		}
	}
	return out
}
