package agents

// This file ports the graded lattice of mesa-ibi-scanner v0.3.2
// (docs/LATTICE.md §1–5 and §8, mesa_ibi_scanner/lattice.py; Apache-2.0,
// same author): closure fixpoint with flow caps and gated-edge removal,
// INV01 and near-miss verdicts, witness paths and the minimal edge cut.
// It is a pure function of the graph; every tie is broken by vertex id or
// edge key, exactly as the reference does.

import (
	"cmp"
	"fmt"
	"slices"
)

// MESASpec names the definition this package implements. It is recorded in
// the evidence so that a change of definition is visible. The graded
// lattice first shipped in mesa-ibi-scanner 0.4.0 (the v0.3.2 tag predates
// it); the port follows docs/LATTICE.md and lattice.py at commit b9cb325.
const MESASpec = "mesa-ibi-scanner 0.4.0 LATTICE (b9cb325)"

// Dimensions, in MESA order: privilege, untrusted input, egress.
const (
	DimP = iota
	DimU
	DimE
)

var dimNames = [3]string{"P", "U", "E"}
var dimLong = [3]string{"privilege (P)", "untrusted input (U)", "egress (E)"}

// Levels is a MESA level vector (P, U, E), each component 0–3.
type Levels [3]int

// MarshalJSON writes {"P":p,"U":u,"E":e}.
func (l Levels) MarshalJSON() ([]byte, error) {
	return fmt.Appendf(nil, `{"P":%d,"U":%d,"E":%d}`, l[0], l[1], l[2]), nil
}

func (l Levels) String() string { return fmt.Sprintf("(P=%d, U=%d, E=%d)", l[0], l[1], l[2]) }

// Threshold is MESA's `production` zone threshold, which is also its default
// zone. gapproof never lets a manifest choose a zone (D-032).
var Threshold = Levels{2, 2, 2}

var top = Levels{3, 3, 3}

// Flow types and their caps (LATTICE §3). An unknown flow type gets
// (3, 3, 3): the over-inclusion rule.
const (
	FlowWrite        = "write"
	FlowRead         = "read"
	FlowGoalMessage  = "goal-message"
	FlowProxyEgress  = "proxy/egress"
	FlowIdentityMint = "identity-mint"
)

var flowCap = map[string]Levels{
	FlowWrite:        {3, 3, 3},
	FlowRead:         {3, 3, 0},
	FlowGoalMessage:  {0, 3, 0},
	FlowProxyEgress:  {0, 0, 3},
	FlowIdentityMint: {3, 0, 3},
}

func join(a, b Levels) Levels {
	return Levels{max(a[0], b[0]), max(a[1], b[1]), max(a[2], b[2])}
}

func attenuate(l, c Levels) Levels {
	return Levels{min(l[0], c[0]), min(l[1], c[1]), min(l[2], c[2])}
}

func geq(a, b Levels) bool { return a[0] >= b[0] && a[1] >= b[1] && a[2] >= b[2] }

type lvertex struct {
	id     string
	agent  bool
	levels Levels
}

type ledge struct {
	src, dst string
	flow     string
	gated    bool
	cap      *Levels // explicit edge cap (MESA schema v0.2), nil if none
	label    string
}

func (e *ledge) effCap() Levels {
	c, ok := flowCap[e.flow]
	if !ok {
		c = top
	}
	if e.cap != nil {
		c = attenuate(c, *e.cap)
	}
	return c
}

// compareEdges is LEdge.key: (src, dst, flow, gated, has cap, cap, label).
func compareEdges(a, b *ledge) int {
	ca, cb := top, top
	if a.cap != nil {
		ca = *a.cap
	}
	if b.cap != nil {
		cb = *b.cap
	}
	return cmp.Or(
		cmp.Compare(a.src, b.src), cmp.Compare(a.dst, b.dst), cmp.Compare(a.flow, b.flow),
		cmpBool(a.gated, b.gated), cmpBool(a.cap != nil, b.cap != nil),
		slices.Compare(ca[:], cb[:]), cmp.Compare(a.label, b.label),
	)
}

func cmpBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case b:
		return -1
	}
	return 1
}

// lgraph is a MESA lattice graph in canonical form once finish() has run:
// vertex ids sorted, edges sorted by key.
type lgraph struct {
	ids   []string
	verts map[string]*lvertex
	edges []*ledge
}

func newLGraph() *lgraph { return &lgraph{verts: map[string]*lvertex{}} }

func (g *lgraph) addVertex(id string, agent bool, l Levels) {
	if _, ok := g.verts[id]; !ok {
		g.ids = append(g.ids, id)
	}
	g.verts[id] = &lvertex{id: id, agent: agent, levels: l}
}

func (g *lgraph) addEdge(e *ledge) {
	if g.verts[e.src] == nil || g.verts[e.dst] == nil {
		panic(fmt.Sprintf("agents: edge endpoints must exist: %s -> %s", e.src, e.dst))
	}
	g.edges = append(g.edges, e)
}

func (g *lgraph) finish() {
	slices.Sort(g.ids)
	slices.SortStableFunc(g.edges, compareEdges)
}

// residual is every ungated edge, in key order (LATTICE §4: cut semantics).
func (g *lgraph) residual() []*ledge {
	var out []*ledge
	for _, e := range g.edges {
		if !e.gated {
			out = append(out, e)
		}
	}
	return out
}

// closure is the least fixpoint of Cl(v) = L(v) ⊔ ⊔ attenuate(Cl(u), cap(e))
// over the residual graph. Each component only rises and is bounded by 3,
// so the worklist terminates after O(|V|) rounds per vertex.
func (g *lgraph) closure(residual []*ledge) map[string]Levels {
	cl := make(map[string]Levels, len(g.ids))
	out := map[string][]*ledge{}
	for _, id := range g.ids {
		cl[id] = g.verts[id].levels
	}
	for _, e := range residual {
		out[e.src] = append(out[e.src], e)
	}
	queue := slices.Clone(g.ids)
	queued := map[string]bool{}
	for _, id := range queue {
		queued[id] = true
	}
	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		queued[u] = false
		for _, e := range out[u] {
			n := join(cl[e.dst], attenuate(cl[u], e.effCap()))
			if n != cl[e.dst] {
				cl[e.dst] = n
				if !queued[e.dst] {
					queued[e.dst] = true
					queue = append(queue, e.dst)
				}
			}
		}
	}
	return cl
}

// verdict is MESA's Finding for one agent.
type verdict struct {
	agent     string
	closure   Levels
	violation bool
	nearMiss  bool
	missing   []int
	witness   [3][]string // vertex ids, source first, the agent last
	cut       []*ledge    // nil when the agent meets the threshold by itself
	cutDim    int         // -1 when cut is nil
}

// evaluate returns one verdict per agent vertex, sorted by id. Witnesses
// and cuts are computed for violating agents only. threshold gives each
// agent's threshold: gapproof always passes the fixed production vector;
// the MESA parity tests pass the fixture's per-agent zone.
func (g *lgraph) evaluate(threshold func(agent string) Levels) []verdict {
	res := g.residual()
	cl := g.closure(res)
	in := map[string][]*ledge{}
	for _, e := range res {
		in[e.dst] = append(in[e.dst], e)
	}
	var out []verdict
	for _, id := range g.ids {
		if !g.verts[id].agent {
			continue
		}
		v := verdict{agent: id, closure: cl[id], cutDim: -1}
		t := threshold(id)
		for d := range 3 {
			if v.closure[d] < t[d] {
				v.missing = append(v.missing, d)
			}
		}
		v.violation = len(v.missing) == 0
		v.nearMiss = len(v.missing) == 1
		if v.violation {
			for d := range 3 {
				v.witness[d] = g.witness(in, id, d, v.closure[d])
			}
			for d := range 3 {
				if g.verts[id].levels[d] >= t[d] {
					continue
				}
				// Ties go to the earlier dimension (P, U, E), so a later
				// one only matters if its cut is strictly smaller.
				limit := -1
				if v.cutDim >= 0 {
					limit = len(v.cut)
				}
				if c, ok := g.minCut(res, id, d, t[d], limit); ok {
					v.cut, v.cutDim = c, d
				}
			}
		}
		out = append(out, v)
	}
	return out
}

// witness is the shortest path from a vertex holding `level` in dimension d
// to x along edges whose cap allows it, ties broken by vertex id (LATTICE
// §8). The BFS runs backwards from x exactly as the reference does.
func (g *lgraph) witness(in map[string][]*ledge, x string, d, level int) []string {
	if g.verts[x].levels[d] >= level {
		return []string{x}
	}
	parent := map[string]string{x: ""}
	frontier := []string{x}
	for len(frontier) > 0 {
		var next []string
		for _, v := range frontier {
			for _, e := range in[v] {
				if _, seen := parent[e.src]; !seen && e.effCap()[d] >= level {
					parent[e.src] = v
					next = append(next, e.src)
				}
			}
		}
		slices.Sort(next)
		for _, u := range next {
			if g.verts[u].levels[d] >= level {
				path := []string{u}
				for p := parent[u]; p != ""; p = parent[p] {
					path = append(path, p)
				}
				return path
			}
		}
		frontier = next
	}
	panic("agents: closure level has no witness; engine invariant broken")
}

// minCut is a minimum edge cut separating {u : L_d(u) ≥ t} from x in the
// subgraph of ungated edges with cap ≥ t in d (LATTICE §8), with unit
// capacities. It returns the source-side cut (the edges leaving the set of
// vertices reachable from the sources in the final residual graph), which
// every maximum flow yields identically, so the result matches the
// reference's Edmonds–Karp. Dinic's algorithm keeps hostile graphs fast.
// With limit ≥ 0 it gives up (ok = false) once the flow reaches limit: such
// a cut would not be strictly smaller than one already found.
func (g *lgraph) minCut(edges []*ledge, x string, d, t, limit int) (cut []*ledge, ok bool) {
	n := len(g.ids) + 1 // vertex i is g.ids[i]; n-1 is the super source
	idx := make(map[string]int, len(g.ids))
	for i, id := range g.ids {
		idx[id] = i
	}
	src, sink := n-1, idx[x]
	var to, capa []int
	var orig []*ledge
	heads := make([][]int, n)
	add := func(u, v, c int, e *ledge) {
		heads[u] = append(heads[u], len(to))
		to, capa, orig = append(to, v), append(capa, c), append(orig, e)
		heads[v] = append(heads[v], len(to))
		to, capa, orig = append(to, u), append(capa, 0), append(orig, nil)
	}
	var usable []*ledge
	for _, e := range edges {
		if e.effCap()[d] >= t {
			usable = append(usable, e)
		}
	}
	for i, id := range g.ids {
		if g.verts[id].levels[d] >= t {
			add(src, i, len(usable)+1, nil)
		}
	}
	for _, e := range usable {
		add(idx[e.src], idx[e.dst], 1, e)
	}
	level := make([]int, n)
	bfs := func() {
		for i := range level {
			level[i] = -1
		}
		level[src] = 0
		q := []int{src}
		for len(q) > 0 {
			u := q[0]
			q = q[1:]
			for _, ai := range heads[u] {
				if capa[ai] > 0 && level[to[ai]] < 0 {
					level[to[ai]] = level[u] + 1
					q = append(q, to[ai])
				}
			}
		}
	}
	it := make([]int, n)
	var push func(u int) bool // one unit along the level graph
	push = func(u int) bool {
		if u == sink {
			return true
		}
		for ; it[u] < len(heads[u]); it[u]++ {
			ai := heads[u][it[u]]
			if v := to[ai]; capa[ai] > 0 && level[v] == level[u]+1 && push(v) {
				capa[ai]--
				capa[ai^1]++
				return true
			}
		}
		return false
	}
	flow := 0
	for {
		bfs()
		if level[sink] < 0 {
			break
		}
		clear(it)
		for push(src) {
			if flow++; limit >= 0 && flow >= limit {
				return nil, false
			}
		}
	}
	// level now marks the residual reachability from the sources.
	for ai := 0; ai < len(to); ai += 2 {
		if e := orig[ai]; e != nil && level[to[ai^1]] >= 0 && level[to[ai]] < 0 {
			cut = append(cut, e)
		}
	}
	slices.SortStableFunc(cut, compareEdges)
	return cut, true
}
