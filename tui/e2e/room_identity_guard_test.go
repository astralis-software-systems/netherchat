package e2e

import (
	"fmt"
	"go/ast"
	"sort"
	"strings"
	"testing"
)

// A record entry cannot land in a room by a route that skipped the D-I decision.
//
// This is the same discipline admitMember holds for a member and newSessionClient
// holds for a Sneakernet client, and it is here for the same reason: the failure
// mode is silent. A second `line{kind: lineRecord, …}` literal somewhere would
// compile, render, and look right for every kind except the one that needs an
// attribution — and an identity entry that arrived through it would fall back to
// printing the artifact's JSON, which is the defect Phase 3c exists to close.
//
// The view CANNOT repair it: deciding an attribution takes an evaluation time,
// and a view that read a clock would re-verify on every keystroke (D-L §3.1). So
// the decision has to happen where the frame lands, and this guard is what keeps
// "where the frame lands" a single place.

const roomIdentityGuardFile = "tui/e2e/room_identity_guard_test.go"

// recordLineOwner is the only function allowed to build a record line.
const recordLineOwner = "appendRecordLine"

// recordLineLiteral names the type and the kind constant the guard looks for.
const (
	recordLineType = "line"
	recordLineKind = "lineRecord"
)

// TestARecordLineIsBuiltInOnePlace: in non-test source under tui/, a composite
// literal of type `line` carrying `kind: lineRecord` may appear only inside
// appendRecordLine.
func TestARecordLineIsBuiltInOnePlace(t *testing.T) {
	files, _ := tuiSourceFiles(t)

	found := 0
	var strays []string
	for _, f := range files {
		for _, decl := range f.AST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				id, ok := lit.Type.(*ast.Ident)
				if !ok || id.Name != recordLineType {
					return true
				}
				if !litSetsKind(lit, recordLineKind) {
					return true
				}
				found++
				if fn.Name.Name != recordLineOwner {
					strays = append(strays, fmt.Sprintf("%s:%d: %s", f.Rel,
						f.FSet.Position(lit.Pos()).Line, fn.Name.Name))
				}
				return true
			})
		}
	}

	if found == 0 {
		t.Fatalf("no %s{kind: %s} literal in non-test source under tui/; either the room buffer "+
			"stopped holding record entries or this guard is inspecting nothing (was a name "+
			"changed? update %s)", recordLineType, recordLineKind, roomIdentityGuardFile)
	}
	if len(strays) > 0 {
		sort.Strings(strays)
		t.Fatalf("%d record line(s) are built outside %s:\n  %s\n\n"+
			"Deciding a filed credential's attribution takes an evaluation time, and a view cannot "+
			"read one. A line built here would render an identity entry as the artifact's raw JSON, "+
			"silently, for exactly the entries the demo is about. Guard: %s",
			len(strays), recordLineOwner, strings.Join(strays, "\n  "), roomIdentityGuardFile)
	}
	t.Logf("%s{kind: %s}: %d literal(s), all inside %s", recordLineType, recordLineKind, found, recordLineOwner)
}

// litSetsKind reports whether a composite literal has a `kind: <name>` element.
func litSetsKind(lit *ast.CompositeLit, name string) bool {
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != "kind" {
			continue
		}
		if val, ok := kv.Value.(*ast.Ident); ok && val.Name == name {
			return true
		}
	}
	return false
}
