package render

// CollapseState tracks which collapsible blocks (long code blocks and long
// stack traces) the user has expanded via /expand. Blocks are identified by a
// sequential integer id scoped to the room session; the ids are assigned at
// render time in buffer order, so they are stable across re-renders and reset
// to 1 when the room's line buffer is cleared (e.g. /vanish — see Reset).
//
// The zero value is not ready; use NewCollapseState. A nil *CollapseState is
// safe to query (everything reads as collapsed), which keeps callers simple.
type CollapseState struct {
	expanded map[int]bool
	all      bool // /expand all — every block is shown in full
}

// NewCollapseState returns an empty state in which every block starts collapsed.
func NewCollapseState() *CollapseState {
	return &CollapseState{expanded: make(map[int]bool)}
}

// Expanded reports whether block id should be rendered in full.
func (c *CollapseState) Expanded(id int) bool {
	if c == nil {
		return false
	}
	return c.all || c.expanded[id]
}

// Expand marks a single block id as expanded (/expand <id>).
func (c *CollapseState) Expand(id int) {
	if c == nil {
		return
	}
	if c.expanded == nil {
		c.expanded = make(map[int]bool)
	}
	c.expanded[id] = true
}

// ExpandAll marks every block as expanded (/expand all).
func (c *CollapseState) ExpandAll() {
	if c == nil {
		return
	}
	c.all = true
}

// Reset returns the state to all-collapsed. Called when the room's history is
// cleared (/vanish, /clear) so reused block ids don't inherit stale expansion.
func (c *CollapseState) Reset() {
	if c == nil {
		return
	}
	c.expanded = make(map[int]bool)
	c.all = false
}
