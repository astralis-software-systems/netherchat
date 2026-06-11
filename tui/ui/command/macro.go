package command

import (
	"fmt"
	"sort"
	"strings"
)

// MacroSep separates the individual commands inside a macro expansion (§2.5), e.g.
//
//	resolved = "/decide incident resolved · /vanish"
const MacroSep = "·"

// MacroSet is a validated collection of slash-command macros (§2.5) loaded from the
// [macros] table in netherchat.toml. A macro maps a name to an expansion of one or
// more slash commands separated by MacroSep. The nil MacroSet is usable and empty.
type MacroSet struct {
	m map[string]string
}

// LoadMacros validates raw macros against the built-in command set and returns a
// MacroSet (§2.5). It rejects, with a clear error:
//   - a macro whose name collides with a built-in command,
//   - an empty name or expansion,
//   - a macro referencing a command that is neither a built-in nor another macro,
//   - circular macro expansion.
//
// Validation happens at startup so a misconfigured macro fails loudly instead of
// surprising someone at 3am.
func LoadMacros(raw map[string]string, builtins *Set) (*MacroSet, error) {
	ms := &MacroSet{m: make(map[string]string, len(raw))}
	for name, exp := range raw {
		name = strings.TrimSpace(strings.TrimPrefix(name, "/"))
		if name == "" {
			return nil, fmt.Errorf("a macro has an empty name")
		}
		if _, isBuiltin := builtins.Get(name); isBuiltin {
			return nil, fmt.Errorf("macro %q conflicts with the built-in command /%s", name, name)
		}
		if strings.TrimSpace(exp) == "" {
			return nil, fmt.Errorf("macro %q has an empty expansion", name)
		}
		ms.m[name] = exp
	}
	// Now that every name is known, validate references and detect cycles.
	for name := range ms.m {
		if err := ms.validate(name, builtins, nil); err != nil {
			return nil, err
		}
	}
	return ms, nil
}

// validate walks a macro's expansion, verifying every referenced command exists
// (built-in or macro) and that following macro references forms no cycle. path is
// the chain of macros currently being expanded.
func (ms *MacroSet) validate(name string, builtins *Set, path []string) error {
	for _, p := range path {
		if p == name {
			return fmt.Errorf("macro %q expands circularly (%s → %s)", path[0], strings.Join(path, " → "), name)
		}
	}
	for _, part := range splitMacro(ms.m[name]) {
		cmd := commandName(part)
		if cmd == "" {
			continue
		}
		_, isBuiltin := builtins.Get(cmd)
		_, isMacro := ms.m[cmd]
		if !isBuiltin && !isMacro {
			return fmt.Errorf("macro %q references unknown command /%s", name, cmd)
		}
		if isMacro {
			if err := ms.validate(cmd, builtins, append(path, name)); err != nil {
				return err
			}
		}
	}
	return nil
}

// Get returns a macro's raw expansion string.
func (ms *MacroSet) Get(name string) (string, bool) {
	if ms == nil {
		return "", false
	}
	e, ok := ms.m[name]
	return e, ok
}

// Expand flattens a macro name into the ordered list of CONCRETE slash commands to
// run (nested macros resolved). It returns (nil, false) when name is not a macro.
// Cycles cannot occur — they are rejected by LoadMacros.
func (ms *MacroSet) Expand(name string) ([]string, bool) {
	if ms == nil {
		return nil, false
	}
	if _, ok := ms.m[name]; !ok {
		return nil, false
	}
	var out []string
	ms.expand(name, &out)
	return out, true
}

func (ms *MacroSet) expand(name string, out *[]string) {
	for _, part := range splitMacro(ms.m[name]) {
		if _, isMacro := ms.m[commandName(part)]; isMacro {
			ms.expand(commandName(part), out)
		} else {
			*out = append(*out, part)
		}
	}
}

// Commands returns the macros as autocomplete Command entries — the macro name and
// a hint (the first 40 characters of its expansion), sorted by name (§2.5).
func (ms *MacroSet) Commands() []Command {
	if ms == nil {
		return nil
	}
	names := make([]string, 0, len(ms.m))
	for n := range ms.m {
		names = append(names, n)
	}
	sort.Strings(names)
	cmds := make([]Command, 0, len(names))
	for _, n := range names {
		cmds = append(cmds, Command{Name: n, Help: "macro: " + truncateHint(ms.m[n], 40)})
	}
	return cmds
}

// splitMacro splits an expansion on MacroSep into trimmed, non-empty commands.
func splitMacro(exp string) []string {
	var out []string
	for _, p := range strings.Split(exp, MacroSep) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// commandName extracts the leading command name from a "/cmd args" fragment.
func commandName(part string) string {
	part = strings.TrimPrefix(strings.TrimSpace(part), "/")
	name, _, _ := strings.Cut(part, " ")
	return name
}

func truncateHint(s string, n int) string {
	s = strings.TrimSpace(s)
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}
