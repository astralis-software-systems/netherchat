// Structural guards for the two Netherchat-side seam rules that govern the
// identity layer (roadmap §6 rules 1 and 2; identity spec §9.4). They sit
// beside the blind-relay boundary guard and the relay egress guard because they
// are the same kind of check: a property the documents assert, made mechanical.
//
// # WHY THE SCOPE IS SYMBOLS AND NOT FILENAMES
//
// The specification scoped this to tui/attest/identity*.go,
// tui/record/identity*.go and protocol/identity_signing.go. That scope is wrong
// in a way that matters on day one: the two doc comments the rule most needs to
// police — the contract sentences on VerifyResult.IdentityBindings and on the
// VerifiedIdentity type — live in tui/record/sealed.go, whose name matches no
// pattern above. A filename-scoped guard would have passed while the property it
// names was false, which is the failure mode roadmap §8 records three prior
// instances of.
//
// So scope follows the SYMBOLS. A file is in scope when it declares one of
// identitySymbols — as a top-level name OR as a struct field name, which is what
// brings VerifyResult's IdentityBindings field, and therefore sealed.go, into
// scope. Move a symbol to a new file and the scope moves with it; rename one and
// TestIdentitySymbolsAreLive fails rather than the scope silently shrinking.
//
// # WHAT "NO SUFFICIENCY VOCABULARY" MEANS HERE
//
// The rule bans ASSERTING sufficiency, not the letters of a word. The contract
// sentences this layer has to carry are denials — "it never decides what a
// binding entitles", "it does not mean the principal is entitled to anything" —
// and a guard that failed on those would force the code to stop saying the true
// thing. So: in a comment, a banned token is a finding unless the sentence
// carrying it also carries a negation. In an identifier or a string literal
// there is no such exemption, because neither has room for a denial: an error
// string reads "serial must not be empty", never "serial is required".
//
// WHAT THIS DOES NOT COVER, STATED PLAINLY
//
//   - The negation test is per sentence and lexical. "A binding entitles the
//     holder, and nothing here changes that" would pass. It is a tripwire against
//     drift, not a proof about meaning.
//   - Only non-test source is scanned. This file names every banned token and
//     would otherwise be its own first finding.
//   - identityMixedFiles narrows whole-file scope in a file that also holds an
//     older feature's prose, to the declarations that are actually this layer's.
//     Each entry is stale-checked, so it cannot outlive the file's membership in
//     the scope, but prose added to a mixed file OUTSIDE its identity
//     declarations is not checked.
package e2e

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// identitySeamGuardFile is named in failure messages so the fix is one click away.
const identitySeamGuardFile = "tui/e2e/identity_seam_test.go"

// identitySymbols is the identity layer surface, by name. A file declaring any of
// these — top-level, or as a struct field — is in scope for both guards below.
//
// The three the roadmap names explicitly (IdentityBindings, VerifiedIdentity,
// IdentityOutcome) are the ones a filename scope missed; the rest are here so
// the scope is the whole layer rather than the part that happened to be
// discussed.
var identitySymbols = []string{
	// tui/record — the surfacing side. IdentityBindings and IdentityOutcomes are
	// STRUCT FIELDS on VerifyResult in sealed.go; that is the case filenames miss.
	"IdentityBindings", "IdentityOutcomes", "VerifiedIdentity", "IdentityOutcome",
	"VerifyWithIdentity", "VerifyBytesWithIdentity", "AppendIdentity",
	"IdentityEntrySpec", "IsIdentityEntry", "VerifiedIdentitiesOf", "ReasonMalformedArtifact",
	// tui/attest — the format and its verifier.
	"IdentityAttestation", "IdentitySpec", "IdentityOptions", "IdentityResult",
	"IdentityReason", "IdentityReasonClass", "IdentityVersion", "IdentitySchema",
	"NewIdentityAttestation", "ParseIdentity", "VerifyIdentity",
	"RevocationStatement", "RevocationSpec", "RevokedSerial", "RevocationResult",
	"RevocationCheck", "RevocationVersion",
	"NewRevocation", "ParseRevocation", "VerifyRevocation",
	// protocol — the canonical byte layouts.
	"IdentitySigningBytes", "RevocationSigningBytes",
}

// sufficiencyVocabulary is the banned token set (spec §9.4). These are the words
// in which "this credential is enough to do X" gets written; Netherchat's
// identity layer states what an issuer signed and what verified, and stops
// there.
var sufficiencyVocabulary = []string{
	"quorum", "threshold", "required", "sufficient", "authorized", "permitted", "entitle",
}

// negations are the markers that make an occurrence a denial rather than a claim.
var negations = []string{
	"not", "no", "never", "nor", "neither", "nothing", "none", "cannot", "without",
}

// identityMixedFile is a file that holds part of the identity layer AND a body
// of older code with its own vocabulary. In one of these, only the declarations
// that carry identity symbols are the identity layer's prose; the rest belongs
// to whatever feature was there first and is governed by its own conventions.
// Every other in-scope file is checked whole, package doc included.
type identityMixedFile struct {
	File string // slash-separated, module-root-relative
	Why  string
}

// identityMixedFiles is the complete list. Each entry is checked for staleness:
// a file that no longer declares any identity symbol has dropped out of scope,
// and the entry has to go with it rather than sit there protecting nothing.
var identityMixedFiles = []identityMixedFile{
	{
		File: "tui/record/sealed.go",
		Why: "sealed.go is in scope because VerifyResult gained the identity fields, and it " +
			"is the right place for them — but the rest of the file is the artifact-approval " +
			"feature, whose doc comments describe what a CONSUMER's own policy does with a " +
			"verified set. That is the vocabulary of the thing this seam rule points AT, not " +
			"of the layer it constrains, and it predates this layer by two releases.",
	},
}

// watchedTrustAnchorPkgs are the packages an identity-layer library file must
// not reach: reading a file or an environment variable, or declaring a flag, is
// how a library acquires a trust anchor of its own. Issuer keys are parameters.
var watchedTrustAnchorPkgs = map[string]bool{
	"os": true, "flag": true, "ioutil": true, "viper": true,
}

// anchorNamePattern matches a package-level name that would hold issuer key
// material rather than take it as a parameter.
var anchorNamePattern = regexp.MustCompile(`(?i)^(default|builtin|embedded|wellknown)?(issuer|trustanchor|trustroot|rootkey|cakey)`)

// identityModuleRoot walks up from the test's working directory to the go.mod.
func identityModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("cannot locate the module root (no go.mod above the test's working directory)")
	return ""
}

// scopedFile is one in-scope source file and the identity symbols it declares.
type scopedFile struct {
	Rel   string // slash-separated, module-root-relative
	AST   *ast.File
	FSet  *token.FileSet
	Decls []string // identity symbols declared here
}

// identityScope parses every non-test .go file in the module and returns those
// declaring at least one identitySymbol, plus where each symbol was found.
//
// node_modules is skipped (a vendored npm package ships Go source inside the
// module tree, per spec A.3 caveat 3) and so is the separate provider module.
func identityScope(t *testing.T) ([]scopedFile, map[string]string) {
	t.Helper()
	root := identityModuleRoot(t)
	want := make(map[string]bool, len(identitySymbols))
	for _, s := range identitySymbols {
		want[s] = true
	}
	found := map[string]string{} // symbol -> relative file it was found in

	var out []scopedFile
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
			return nil // not parseable on its own terms; the build catches that
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)

		var declared []string
		for name := range declaredNames(af) {
			if want[name] {
				declared = append(declared, name)
				if _, seen := found[name]; !seen {
					found[name] = rel
				}
			}
		}
		if len(declared) > 0 {
			sort.Strings(declared)
			out = append(out, scopedFile{Rel: rel, AST: af, FSet: fset, Decls: declared})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rel < out[j].Rel })
	return out, found
}

// declaredNames returns every name a file declares: top-level funcs, types,
// consts and vars, plus STRUCT FIELD names. Field names are the reason this is
// not a top-level scan — VerifyResult.IdentityBindings is a field, and the
// contract sentence that has to be policed is its doc comment.
func declaredNames(af *ast.File) map[string]bool {
	out := map[string]bool{}
	for _, decl := range af.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			out[d.Name.Name] = true
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					out[s.Name.Name] = true
				case *ast.ValueSpec:
					for _, n := range s.Names {
						out[n.Name] = true
					}
				}
			}
		}
	}
	ast.Inspect(af, func(n ast.Node) bool {
		st, ok := n.(*ast.StructType)
		if !ok || st.Fields == nil {
			return true
		}
		for _, f := range st.Fields.List {
			for _, name := range f.Names {
				out[name.Name] = true
			}
		}
		return true
	})
	return out
}

// TestIdentitySymbolsAreLive is the anti-vacuity check. Both guards below prove
// an ABSENCE inside a scope derived from these names, and an absence is
// vacuously true the moment the scope is empty. A renamed or deleted symbol
// therefore fails HERE, loudly, instead of quietly shrinking the guards' scope
// to nothing — which is precisely how a filename-scoped grep dies.
func TestIdentitySymbolsAreLive(t *testing.T) {
	files, found := identityScope(t)
	if len(files) == 0 {
		t.Fatal("no file in the module declares any identity-layer symbol; the seam guards are inspecting nothing")
	}
	var missing []string
	for _, s := range identitySymbols {
		if _, ok := found[s]; !ok {
			missing = append(missing, s)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("identitySymbols names %d symbol(s) that no non-test file declares:\n  %s\n\n"+
			"Either the symbol was renamed or moved (update identitySymbols in %s, so the seam\n"+
			"guards keep covering it) or it was deleted (drop it from the list).",
			len(missing), strings.Join(missing, "\n  "), identitySeamGuardFile)
	}
	rels := make([]string, len(files))
	for i, f := range files {
		rels[i] = f.Rel + "  [" + strings.Join(f.Decls, " ") + "]"
	}
	t.Logf("identity seam scope: %d file(s)\n  %s", len(files), strings.Join(rels, "\n  "))
}

// bannedToken finds a sufficiency token in s and reports it, or "" for none.
// A token inside a compound ("required-role", "RequiredRoles") still counts; a
// token that is merely the tail of a longer word does not.
func bannedToken(s string) string {
	low := strings.ToLower(s)
	for _, w := range sufficiencyVocabulary {
		for i := 0; i+len(w) <= len(low); i++ {
			if low[i:i+len(w)] != w {
				continue
			}
			if i == 0 || !isWordByte(low[i-1]) {
				return w
			}
		}
	}
	return ""
}

func isWordByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

// sentenceSplit ends a clause. Semicolons and COLONS count, and the colon is
// there because leaving it out was a hole this guard was caught in: the sentence
//
//	it attaches no meaning to a principal or a role: a verified binding entitles
//	its principal to act in the roles it names
//
// carries its negation in the half before the colon and its claim in the half
// after, so a full-stop-only split read the "no" as covering the "entitles" and
// passed an assertion. A denial has to sit in the same clause as the word it
// denies, which is also how a reader parses it.
var sentenceSplit = regexp.MustCompile(`[.;:!?]`)

// sentences splits comment text into clauses. Comment lines are joined first,
// because the sentence a denial lives in routinely wraps across three of them.
func sentences(comment string) []string {
	lines := strings.Split(comment, "\n")
	for i, ln := range lines {
		ln = strings.TrimSpace(ln)
		ln = strings.TrimPrefix(ln, "//")
		ln = strings.TrimPrefix(ln, "/*")
		ln = strings.TrimSuffix(ln, "*/")
		lines[i] = strings.TrimSpace(ln)
	}
	return sentenceSplit.Split(strings.Join(lines, " "), -1)
}

// denies reports whether a sentence carries a negation, which is what turns an
// occurrence of a banned token from a claim into the denial this layer must
// make.
func denies(sentence string) bool {
	low := strings.ToLower(sentence)
	for _, n := range negations {
		for i := 0; i+len(n) <= len(low); i++ {
			if low[i:i+len(n)] != n {
				continue
			}
			startOK := i == 0 || !isWordByte(low[i-1])
			endOK := i+len(n) == len(low) || !isWordByte(low[i+len(n)])
			if startOK && endOK {
				return true
			}
		}
	}
	return false
}

// TestIdentityLayerHasNoSufficiencyVocabulary is roadmap §6 seam rule 2, made
// mechanical: the identity layer states what an issuer signed and what verified,
// and never states what that is enough for.
func TestIdentityLayerHasNoSufficiencyVocabulary(t *testing.T) {
	files, _ := identityScope(t)
	if len(files) == 0 {
		t.Fatal("identity seam scope is empty; the guard is inspecting nothing")
	}
	mixed := map[string]bool{}
	for _, m := range identityMixedFiles {
		mixed[m.File] = true
	}
	inScopeFiles := map[string]bool{}

	var findings []string
	// Positive control: every in-scope file carries doc comments, so zero comment
	// groups scanned would mean the parse lost them and the absence proved below
	// would be an artifact of a broken scan rather than a property of the code.
	comments := 0

	for _, f := range files {
		inScopeFiles[f.Rel] = true
		narrow := mixed[f.Rel]
		declSymbols := map[string]bool{}
		for _, s := range f.Decls {
			declSymbols[s] = true
		}
		// The package doc is part of a file's own prose, so a whole-file scope
		// covers it. A mixed file's package doc predates the layer, like the rest
		// of it.
		if !narrow && f.AST.Doc != nil {
			comments++
			for _, s := range sentences(f.AST.Doc.Text()) {
				tok := bannedToken(s)
				if tok == "" || denies(s) {
					continue
				}
				findings = append(findings, fmt.Sprintf("%s: package doc asserts %q — %q",
					f.Rel, tok, strings.TrimSpace(s)))
			}
		}
		for _, decl := range f.AST.Decls {
			name := declName(decl)
			if narrow && !declaresAnyOf(decl, declSymbols) {
				continue
			}
			for _, c := range commentsIn(f.AST, decl) {
				comments++
				for _, s := range sentences(c) {
					tok := bannedToken(s)
					if tok == "" || denies(s) {
						continue
					}
					findings = append(findings, fmt.Sprintf("%s: %s: comment asserts %q — %q",
						f.Rel, nameOrAnon(name), tok, strings.TrimSpace(s)))
				}
			}
			// Identifiers and string literals get no denial exemption: neither has
			// room for one.
			ast.Inspect(decl, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.Ident:
					if tok := bannedToken(x.Name); tok != "" {
						findings = append(findings, fmt.Sprintf("%s:%d: %s: identifier %q carries %q",
							f.Rel, f.FSet.Position(x.Pos()).Line, nameOrAnon(name), x.Name, tok))
					}
				case *ast.BasicLit:
					if x.Kind == token.STRING {
						if tok := bannedToken(x.Value); tok != "" {
							findings = append(findings, fmt.Sprintf("%s:%d: %s: string literal %s carries %q",
								f.Rel, f.FSet.Position(x.Pos()).Line, nameOrAnon(name), x.Value, tok))
						}
					}
				}
				return true
			})
		}
	}

	if comments == 0 {
		t.Fatal("scanned 0 comment groups across the identity scope; the parser is not returning comments and this guard checks nothing")
	}
	for _, m := range identityMixedFiles {
		if !inScopeFiles[m.File] {
			t.Fatalf("identityMixedFiles has a stale entry: %s declares no identity symbol any more,\n"+
				"so it is not in scope and the entry narrows nothing. Delete it in %s.",
				m.File, identitySeamGuardFile)
		}
	}

	if len(findings) > 0 {
		sort.Strings(findings)
		t.Fatalf("the identity layer uses sufficiency vocabulary in %d place(s):\n  %s\n\n"+
			"Roadmap §6 seam rule 2: Netherchat's identity layer says what an issuer signed and\n"+
			"what verified against a caller-supplied key. It does not say what that is enough for —\n"+
			"that sentence belongs to the consumer. A denial reads fine (\"it never decides what a\n"+
			"binding entitles\"); a claim does not.\n"+
			"Banned tokens: %s.  Scope and rationale: %s",
			len(findings), strings.Join(findings, "\n  "),
			strings.Join(sufficiencyVocabulary, ", "), identitySeamGuardFile)
	}
	t.Logf("scanned %d comment group(s) across %d in-scope file(s) for %d banned token(s)",
		comments, len(files), len(sufficiencyVocabulary))
}

// TestIdentityLayerHoldsNoTrustAnchors is roadmap §6 seam rule 1: Netherchat
// holds no trust anchors. Issuer keys and the evaluation time are parameters, so
// the library half of the identity layer must not read a file, an environment
// variable, or a flag, and must not declare a package-level name that would hold
// issuer key material.
//
// cmd/ is excluded on purpose: a command-line tool is exactly where an operator
// supplies a key path, and forbidding it there would forbid the issuer tool from
// existing.
func TestIdentityLayerHoldsNoTrustAnchors(t *testing.T) {
	files, _ := identityScope(t)
	var library []scopedFile
	for _, f := range files {
		if strings.HasPrefix(f.Rel, "cmd/") {
			continue
		}
		library = append(library, f)
	}
	if len(library) == 0 {
		t.Fatal("no library file is in the identity seam scope; the guard is inspecting nothing")
	}

	var findings []string
	selectors := 0
	for _, f := range library {
		ast.Inspect(f.AST, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			selectors++
			if watchedTrustAnchorPkgs[id.Name] {
				findings = append(findings, fmt.Sprintf("%s:%d: %s.%s — the identity layer reaches outside its parameters",
					f.Rel, f.FSet.Position(sel.Pos()).Line, id.Name, sel.Sel.Name))
			}
			return true
		})
		for _, decl := range f.AST.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || (gd.Tok != token.VAR && gd.Tok != token.CONST) {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, name := range vs.Names {
					if anchorNamePattern.MatchString(name.Name) {
						findings = append(findings, fmt.Sprintf("%s:%d: package-level %s — a trust anchor belongs to the caller, not to this module",
							f.Rel, f.FSet.Position(name.Pos()).Line, name.Name))
					}
				}
			}
		}
	}

	// Positive control: these files are full of qualified calls (json.NewDecoder,
	// ed25519.Verify). Zero selectors means the walk found nothing, and the
	// absence below would be an artifact of a broken scan.
	if selectors == 0 {
		t.Fatalf("found 0 package-qualified selectors across %d in-scope library file(s); the scan is not inspecting anything", len(library))
	}

	if len(findings) > 0 {
		sort.Strings(findings)
		t.Fatalf("the identity library holds or reads a trust anchor in %d place(s):\n  %s\n\n"+
			"Roadmap §6 seam rule 1: issuer keys are parameters, never configuration. Netherchat\n"+
			"reads no issuer file, has no issuer flag on connect, and ships no default key. A tool\n"+
			"under cmd/ may take a key path from an operator; the library may not go looking.\n"+
			"Guard: %s", len(findings), strings.Join(findings, "\n  "), identitySeamGuardFile)
	}
	t.Logf("scanned %d package-qualified selector(s) across %d in-scope library file(s)", selectors, len(library))
}

// declName returns the name of a top-level declaration for reporting, or "" for
// a declaration group with no single name (an import block, a multi-name var
// group).
func declName(d ast.Decl) string {
	switch x := d.(type) {
	case *ast.FuncDecl:
		return x.Name.Name
	case *ast.GenDecl:
		for _, spec := range x.Specs {
			switch s := spec.(type) {
			case *ast.TypeSpec:
				return s.Name.Name
			case *ast.ValueSpec:
				if len(s.Names) > 0 {
					return s.Names[0].Name
				}
			}
		}
	}
	return ""
}

// declaresAnyOf reports whether a declaration introduces one of the named
// symbols, counting struct field names. It is what narrows a mixed file to the
// declarations that are actually this layer's.
func declaresAnyOf(d ast.Decl, names map[string]bool) bool {
	hit := false
	ast.Inspect(d, func(n ast.Node) bool {
		if hit {
			return false
		}
		switch x := n.(type) {
		case *ast.FuncDecl:
			if names[x.Name.Name] {
				hit = true
			}
		case *ast.TypeSpec:
			if names[x.Name.Name] {
				hit = true
			}
		case *ast.ValueSpec:
			for _, nm := range x.Names {
				if names[nm.Name] {
					hit = true
				}
			}
		case *ast.Field:
			for _, nm := range x.Names {
				if names[nm.Name] {
					hit = true
				}
			}
		}
		return !hit
	})
	return hit
}

func nameOrAnon(n string) string {
	if n == "" {
		return "(declaration group)"
	}
	return n
}

// commentsIn returns the doc comment of a declaration plus every comment
// lexically inside it — field docs, inline notes, the lot.
func commentsIn(af *ast.File, d ast.Decl) []string {
	var out []string
	switch x := d.(type) {
	case *ast.FuncDecl:
		if x.Doc != nil {
			out = append(out, x.Doc.Text())
		}
	case *ast.GenDecl:
		if x.Doc != nil {
			out = append(out, x.Doc.Text())
		}
	}
	lo, hi := d.Pos(), d.End()
	for _, cg := range af.Comments {
		if cg.Pos() >= lo && cg.End() <= hi {
			out = append(out, cg.Text())
		}
	}
	return out
}
