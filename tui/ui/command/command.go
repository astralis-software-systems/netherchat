// Package command is the slash-command engine for the TUI: parsing and
// autocomplete. It is UI-agnostic and action-agnostic — it knows command names,
// usage and how to suggest completions; the app maps a parsed command to an
// actual action (switching themes, calling the client, etc).
package command

import "strings"

// Command describes one slash command.
type Command struct {
	Name string
	Args string // usage hint shown in /help, e.g. "<name>"
	Help string
	// Complete returns candidate values for the current partial argument
	// (nil if the command takes no completable argument).
	Complete func(partial string) []string
}

// Suggestion is one autocomplete candidate.
type Suggestion struct {
	Value   string // full input to replace the line with when accepted
	Display string // short label shown in the popup
	Desc    string // description shown alongside
}

// Set is an ordered collection of commands.
type Set struct {
	commands []Command
	index    map[string]Command
}

// New builds a command set.
func New(cmds ...Command) *Set {
	s := &Set{commands: cmds, index: make(map[string]Command, len(cmds))}
	for _, c := range cmds {
		s.index[c.Name] = c
	}
	return s
}

// Commands returns the commands in registration order.
func (s *Set) Commands() []Command { return s.commands }

// Add appends commands to the set (used to register validated macros alongside the
// built-ins for autocomplete and /help, §2.5).
func (s *Set) Add(cmds ...Command) {
	for _, c := range cmds {
		s.commands = append(s.commands, c)
		s.index[c.Name] = c
	}
}

// Get looks up a command by name.
func (s *Set) Get(name string) (Command, bool) {
	c, ok := s.index[name]
	return c, ok
}

// IsCommand reports whether input is a slash command (starts with '/').
func IsCommand(input string) bool { return strings.HasPrefix(input, "/") }

// Parse splits a slash command into its name and trimmed argument string.
func (s *Set) Parse(input string) (name, arg string, ok bool) {
	if !IsCommand(input) {
		return "", "", false
	}
	body := strings.TrimSpace(strings.TrimPrefix(input, "/"))
	name, arg, _ = strings.Cut(body, " ")
	return name, strings.TrimSpace(arg), true
}

// Suggest returns autocomplete candidates for the current (possibly partial)
// input. When the command name is still being typed it suggests command names;
// once a command and a space are present it defers to that command's Complete.
func (s *Set) Suggest(input string) []Suggestion {
	if !IsCommand(input) {
		return nil
	}
	rest := strings.TrimPrefix(input, "/")

	// Still typing the command name (no space yet).
	if !strings.Contains(rest, " ") {
		var out []Suggestion
		for _, c := range s.commands {
			if strings.HasPrefix(c.Name, rest) {
				label := "/" + c.Name
				if c.Args != "" {
					label += " " + c.Args
				}
				out = append(out, Suggestion{Value: "/" + c.Name, Display: label, Desc: c.Help})
			}
		}
		return out
	}

	// Completing an argument.
	name, arg, _ := strings.Cut(rest, " ")
	c, ok := s.index[name]
	if !ok || c.Complete == nil {
		return nil
	}
	var out []Suggestion
	for _, v := range c.Complete(arg) {
		out = append(out, Suggestion{Value: "/" + name + " " + v, Display: v})
	}
	return out
}

// FilterPrefix returns the options that start with prefix (all of them if the
// prefix is empty). Handy for Complete functions over a fixed set of values.
func FilterPrefix(options []string, prefix string) []string {
	var out []string
	for _, o := range options {
		if strings.HasPrefix(o, prefix) {
			out = append(out, o)
		}
	}
	return out
}
