package agents

import (
	"slices"
	"strings"
)

// MaxReportedPaths caps the violating (source, sink) pairs listed with an
// example path. Result.Violations always carries the full count.
const MaxReportedPaths = 100

// Path is one violating (source, sink) pair with one shortest example path,
// as agent-qualified nodes ("analyst:read_file").
type Path struct {
	Source string   `json:"source"`
	Sink   string   `json:"sink"`
	Kind   string   `json:"kind"` // "boundary_crossing", "exec" or "boundary_crossing+exec"
	Nodes  []string `json:"nodes"`
}

// String renders the path as "a:x → a:y".
func (p Path) String() string { return strings.Join(p.Nodes, " → ") }

// graph is the manifest in index form, agents sorted by name and each
// agent's tools sorted, so every traversal is deterministic.
type graph struct {
	agents   []string
	tools    [][]string // per agent
	handoffs [][]int    // per agent, sorted indices
	defs     map[string]Tool
	edges    int
	nodes    int
}

func newGraph(m *Manifest) *graph {
	g := &graph{defs: m.Tools}
	as := slices.Clone(m.Agents)
	slices.SortFunc(as, func(a, b Agent) int { return strings.Compare(a.Name, b.Name) })
	idx := map[string]int{}
	for i, a := range as {
		idx[a.Name] = i
		g.agents = append(g.agents, a.Name)
		ts := slices.Clone(a.Tools)
		slices.Sort(ts)
		g.tools = append(g.tools, ts)
		g.nodes += len(ts)
	}
	for _, a := range as {
		var hs []int
		for _, h := range a.Handoffs {
			hs = append(hs, idx[h])
		}
		slices.Sort(hs)
		g.handoffs = append(g.handoffs, hs)
		g.edges += len(hs)
	}
	return g
}

// state is a hypothetical manifest: the declared one plus cut-set actions.
type state struct {
	gated   map[string]bool    // tool name
	removed map[[2]string]bool // {agent, tool}
}

func (st state) active(agent, tool string) bool { return !st.removed[[2]string{agent, tool}] }

// open reports whether data may flow into (and so through) the node.
func (st state) open(agent, tool string) bool { return st.active(agent, tool) && !st.gated[tool] }

// cost bounds the work of one violations() call (one reach per agent), for
// the cut-set budget.
func (g *graph) cost() int { return (1 + len(g.agents)) * (1 + len(g.agents) + g.edges + g.nodes) }

// violations counts violating (source, sink) pairs under st. With collect it
// also returns up to MaxReportedPaths pairs in (source agent, source tool,
// sink agent, sink tool) order, each with a shortest path. With firstOnly it
// stops at the first violation.
func (g *graph) violations(st state, collect, firstOnly bool) (int, []Path) {
	total := 0
	var paths []Path
	parent := make([]int, len(g.agents))
	for a, agent := range g.agents {
		var sources []string
		for _, t := range g.tools[a] {
			if g.defs[t].Sensitive() && st.active(agent, t) {
				sources = append(sources, t)
			}
		}
		if len(sources) == 0 {
			continue
		}
		reached := g.reach(st, a, parent)
		type sinkNode struct {
			agent int
			tool  string
		}
		var sinks []sinkNode
		for _, x := range reached {
			for _, t := range g.tools[x] {
				if g.defs[t].Sink() && st.open(g.agents[x], t) {
					sinks = append(sinks, sinkNode{x, t})
				}
			}
		}
		if len(sinks) == 0 {
			continue
		}
		total += len(sources) * len(sinks)
		if firstOnly {
			return total, nil
		}
		if !collect || len(paths) >= MaxReportedPaths {
			continue
		}
		for _, s := range sources {
			for _, k := range sinks {
				if len(paths) >= MaxReportedPaths {
					break
				}
				paths = append(paths, g.path(st, a, s, k.agent, k.tool, parent))
			}
		}
	}
	return total, paths
}

// reach returns the agents (sorted by index) whose tools a source in agent
// src can feed, filling parent with a BFS tree. src always relays to its
// handoffs (the source itself feeds them); any other agent relays only
// through an open tool.
func (g *graph) reach(st state, src int, parent []int) []int {
	for i := range parent {
		parent[i] = -2
	}
	parent[src] = -1
	queue := []int{src}
	for len(queue) > 0 {
		x := queue[0]
		queue = queue[1:]
		if x != src && g.relay(st, x) == "" {
			continue
		}
		for _, y := range g.handoffs[x] {
			if parent[y] == -2 {
				parent[y] = x
				queue = append(queue, y)
			}
		}
	}
	var out []int
	for i, p := range parent {
		if p != -2 {
			out = append(out, i)
		}
	}
	return out
}

// relay returns the first open tool of agent x, or "".
func (g *graph) relay(st state, x int) string {
	for _, t := range g.tools[x] {
		if st.open(g.agents[x], t) {
			return t
		}
	}
	return ""
}

func (g *graph) path(st state, src int, s string, dst int, k string, parent []int) Path {
	var hops []int // intermediate agents, dst back to src exclusive
	for x := parent[dst]; dst != src && x != src && x >= 0; x = parent[x] {
		hops = append(hops, x)
	}
	slices.Reverse(hops)
	p := Path{Source: g.agents[src] + ":" + s, Sink: g.agents[dst] + ":" + k, Kind: sinkKind(g.defs[k])}
	p.Nodes = []string{p.Source}
	for _, x := range hops {
		p.Nodes = append(p.Nodes, g.agents[x]+":"+g.relay(st, x))
	}
	if p.Sink != p.Source {
		p.Nodes = append(p.Nodes, p.Sink)
	}
	return p
}

func sinkKind(t Tool) string {
	b, e := slices.Contains(t.Sinks, SinkBoundary), t.Exec()
	switch {
	case b && e:
		return SinkBoundary + "+" + SinkExec
	case e:
		return SinkExec
	}
	return SinkBoundary
}
