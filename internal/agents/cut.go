package agents

import (
	"fmt"
	"slices"
	"strings"
)

// Cut-set search bounds. The exact search enumerates action subsets in
// increasing size; it is exact while it stays within these budgets, and
// otherwise the greedy result is returned with Minimal=false.
const (
	// MaxCutWork bounds the total graph work (subset checks × graph size)
	// spent on greedy plus exact search.
	MaxCutWork = 200_000_000
	// MaxExactCandidates bounds the candidate actions for exact search.
	MaxExactCandidates = 40
)

// Action kinds.
const (
	ActionGate   = "gate"
	ActionRemove = "remove"
)

// Action is one manifest change: gate a tool (in every agent) with
// human_approval, or remove a tool from one agent.
type Action struct {
	Kind  string `json:"kind"`
	Tool  string `json:"tool"`
	Agent string `json:"agent,omitempty"` // remove only
}

func (a Action) String() string {
	if a.Kind == ActionGate {
		return fmt.Sprintf("gate `%s`", a.Tool)
	}
	return fmt.Sprintf("remove `%s` from `%s`", a.Tool, a.Agent)
}

func (st state) with(acts []Action) state {
	n := state{gated: map[string]bool{}, removed: map[[2]string]bool{}}
	for k, v := range st.gated {
		n.gated[k] = v
	}
	for _, a := range acts {
		if a.Kind == ActionGate {
			n.gated[a.Tool] = true
		} else {
			n.removed[[2]string{a.Agent, a.Tool}] = true
		}
	}
	return n
}

type cutSearch struct {
	g    *graph
	base state
	work int
}

// feasible reports whether acts eliminate every violation, charging work.
// ok is false when the budget is spent.
func (c *cutSearch) feasible(acts []Action) (clean, ok bool) {
	if c.work += c.g.cost(); c.work > MaxCutWork {
		return false, false
	}
	n, _ := c.g.violations(c.base.with(acts), false, true)
	return n == 0, true
}

func (c *cutSearch) count(acts []Action) (int, bool) {
	if c.work += c.g.cost(); c.work > MaxCutWork {
		return 0, false
	}
	n, _ := c.g.violations(c.base.with(acts), false, false)
	return n, true
}

// minimalCut returns the smallest action set that removes every violation,
// and whether it is proven minimal. Ties go to the earliest candidates in
// preference order: gate a boundary sink, remove an exec sink, gate an exec
// sink, gate another tool, remove another tool.
func minimalCut(g *graph, base state) ([]Action, bool) {
	if n, _ := g.violations(base, false, true); n == 0 {
		return nil, true
	}
	c := &cutSearch{g: g, base: base}
	cands := candidates(g, base)

	// Always-feasible fallback: gate every tool that ends a violating path.
	// (Gating blocks paths into a node; actions only ever remove paths.)
	best := trivialCut(g, base)
	if greedy, ok := c.greedy(cands); ok {
		best = greedy
	}
	if len(best) == 1 {
		return best, true // there is a violation, so at least one action is needed
	}
	if len(cands) > MaxExactCandidates {
		return best, false
	}
	// Exact: no smaller feasible subset exists if sizes 1..len(best)-1 are
	// exhausted. Then best (or the first smaller hit) is minimal.
	for k := 1; k < len(best); k++ {
		idx := make([]int, k)
		for i := range idx {
			idx[i] = i
		}
		for {
			acts := make([]Action, k)
			for i, j := range idx {
				acts[i] = cands[j]
			}
			clean, ok := c.feasible(acts)
			if !ok {
				return best, false
			}
			if clean {
				return acts, true
			}
			if !nextComb(idx, len(cands)) {
				break
			}
		}
	}
	return best, true
}

// nextComb advances idx to the next k-combination of [0,n) in lexicographic
// order.
func nextComb(idx []int, n int) bool {
	k := len(idx)
	i := k - 1
	for i >= 0 && idx[i] == n-k+i {
		i--
	}
	if i < 0 {
		return false
	}
	idx[i]++
	for j := i + 1; j < k; j++ {
		idx[j] = idx[j-1] + 1
	}
	return true
}

// greedy repeatedly takes the candidate leaving the fewest violations, then
// drops any action the rest no longer need.
func (c *cutSearch) greedy(cands []Action) ([]Action, bool) {
	var chosen []Action
	used := make([]bool, len(cands))
	for {
		cur, ok := c.count(chosen)
		if !ok {
			return nil, false
		}
		if cur == 0 {
			break
		}
		bestI, bestN := -1, cur
		for i, a := range cands {
			if used[i] {
				continue
			}
			n, ok := c.count(append(slices.Clip(chosen), a))
			if !ok {
				return nil, false
			}
			if n < bestN {
				bestI, bestN = i, n
			}
		}
		if bestI < 0 {
			return nil, false // can't happen: gating a violating sink always helps
		}
		used[bestI] = true
		chosen = append(chosen, cands[bestI])
	}
	for i := len(chosen) - 1; i >= 0; i-- {
		rest := slices.Concat(chosen[:i], chosen[i+1:])
		clean, ok := c.feasible(rest)
		if !ok {
			return nil, false
		}
		if clean {
			chosen = rest
		}
	}
	return orderLike(chosen, cands), true
}

func orderLike(acts, cands []Action) []Action {
	pos := map[Action]int{}
	for i, a := range cands {
		pos[a] = i
	}
	out := slices.Clone(acts)
	slices.SortFunc(out, func(a, b Action) int { return pos[a] - pos[b] })
	return out
}

func trivialCut(g *graph, base state) []Action {
	set := map[string]bool{}
	for a, agent := range g.agents {
		for _, t := range g.tools[a] {
			if g.defs[t].Sink() && base.open(agent, t) {
				set[t] = true
			}
		}
	}
	var out []Action
	for _, t := range sortedKeys(set) {
		out = append(out, Action{Kind: ActionGate, Tool: t})
	}
	return out
}

// candidates lists the actions that can matter, in preference order. A tool
// matters only in an agent that some source agent reaches and from which
// some sink agent is reachable (ignoring gates: a sound over-approximation).
// remove(A,T) is dropped where it is equivalent to gate(T) or a no-op.
func candidates(g *graph, base state) []Action {
	n := len(g.agents)
	reach := make([][]bool, n) // reach[x][y]: y reachable from x (x itself included)
	for x := range n {
		reach[x] = make([]bool, n)
		reach[x][x] = true
		q := []int{x}
		for len(q) > 0 {
			y := q[0]
			q = q[1:]
			for _, z := range g.handoffs[y] {
				if !reach[x][z] {
					reach[x][z] = true
					q = append(q, z)
				}
			}
		}
	}
	has := func(x int, pred func(Tool) bool) bool {
		for _, t := range g.tools[x] {
			if pred(g.defs[t]) && base.active(g.agents[x], t) {
				return true
			}
		}
		return false
	}
	relevant := make([]bool, n)
	for x := range n {
		fromSource, toSink := false, false
		for y := range n {
			fromSource = fromSource || (reach[y][x] && has(y, Tool.Sensitive))
			toSink = toSink || (reach[x][y] && has(y, Tool.Sink))
		}
		relevant[x] = fromSource && toSink
	}
	agentsOf := map[string]int{}
	relevantTool := map[string]bool{}
	for x := range n {
		for _, t := range g.tools[x] {
			if base.active(g.agents[x], t) {
				agentsOf[t]++
				if relevant[x] {
					relevantTool[t] = true
				}
			}
		}
	}
	var groups [5][]Action
	for _, t := range sortedKeys(relevantTool) {
		if base.gated[t] {
			continue
		}
		d := g.defs[t]
		switch {
		case d.Exec() && !d.Sensitive() && agentsOf[t] == 1:
			// Same effect as removing its one instance, which is preferred
			// for exec (approving arbitrary code is a weak control).
		case d.Sink() && !d.Exec():
			groups[0] = append(groups[0], Action{Kind: ActionGate, Tool: t})
		case d.Exec():
			groups[2] = append(groups[2], Action{Kind: ActionGate, Tool: t})
		default:
			groups[3] = append(groups[3], Action{Kind: ActionGate, Tool: t})
		}
	}
	type member struct{ agent, tool string }
	var ms []member
	for x := range n {
		if !relevant[x] {
			continue
		}
		for _, t := range g.tools[x] {
			if base.active(g.agents[x], t) {
				ms = append(ms, member{g.agents[x], t})
			}
		}
	}
	slices.SortFunc(ms, func(a, b member) int {
		return strings.Compare(a.tool+"\x00"+a.agent, b.tool+"\x00"+b.agent)
	})
	for _, m := range ms {
		d := g.defs[m.tool]
		if !d.Sensitive() && (base.gated[m.tool] || (agentsOf[m.tool] == 1 && !d.Exec())) {
			continue // no-op, or the same effect as gating the tool
		}
		a := Action{Kind: ActionRemove, Tool: m.tool, Agent: m.agent}
		if d.Exec() {
			groups[1] = append(groups[1], a)
		} else {
			groups[4] = append(groups[4], a)
		}
	}
	return slices.Concat(groups[:]...)
}

// suggestion renders a cut set as a sentence.
func suggestion(acts []Action, minimal bool) string {
	if len(acts) == 0 {
		return ""
	}
	parts := make([]string, len(acts))
	for i, a := range acts {
		parts[i] = a.String()
	}
	s := parts[0]
	if len(parts) > 1 {
		s = strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
	}
	if minimal {
		return fmt.Sprintf("Smallest fix (%d change%s, proven minimal): %s.", len(acts), plural(len(acts)), s)
	}
	return fmt.Sprintf("Suggested fix (%d change%s, greedy, not proven minimal): %s.", len(acts), plural(len(acts)), s)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
