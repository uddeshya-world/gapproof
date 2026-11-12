package agents

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
)

// Property tests ported from mesa-ibi-scanner tests/test_lattice_properties.py
// (P-01, P-03, P-04, P-05, P-11, P-12), plus an independent widest-path
// oracle for the closure (LATTICE §4, last paragraph).

var allFlows = []string{FlowWrite, FlowRead, FlowGoalMessage, FlowProxyEgress, FlowIdentityMint, "unknown-flow"}

func randLevels(r *rand.Rand, maxL int) Levels {
	return Levels{r.IntN(maxL + 1), r.IntN(maxL + 1), r.IntN(maxL + 1)}
}

type spec struct {
	ids    []string
	agent  []bool
	levels []Levels
	edges  []ledge
}

func randSpec(r *rand.Rand, nv, ne int, boolean bool) spec {
	s := spec{}
	maxL := 3
	if boolean {
		maxL = 1
	}
	for i := range nv {
		s.ids = append(s.ids, fmt.Sprintf("v%d", i))
		s.agent = append(s.agent, i == 0 || r.IntN(2) == 0)
		s.levels = append(s.levels, randLevels(r, maxL))
	}
	for range ne {
		e := ledge{src: s.ids[r.IntN(nv)], dst: s.ids[r.IntN(nv)], gated: r.IntN(5) == 0}
		if boolean {
			e.flow = allFlows[r.IntN(5)]
		} else {
			e.flow = allFlows[r.IntN(len(allFlows))]
			if r.IntN(4) == 0 {
				c := randLevels(r, 3)
				e.cap = &c
			}
		}
		s.edges = append(s.edges, e)
	}
	return s
}

func (s spec) build(scale int, skip int) *lgraph {
	g := newLGraph()
	for i, id := range s.ids {
		l := s.levels[i]
		g.addVertex(id, s.agent[i], Levels{l[0] * scale, l[1] * scale, l[2] * scale})
	}
	for i := range s.edges {
		if i != skip {
			e := s.edges[i]
			g.addEdge(&e)
		}
	}
	g.finish()
	return g
}

func closureOf(g *lgraph) map[string]Levels { return g.closure(g.residual()) }

// oracle: Cl_d(v) = max over u of min(L_d(u), bottleneck_d(u → v)).
func oracle(g *lgraph) map[string]Levels {
	out := map[string]Levels{}
	res := g.residual()
	for _, v := range g.ids {
		out[v] = g.verts[v].levels
	}
	for d := range 3 {
		for _, u := range g.ids {
			// widest path from u, Bellman–Ford style.
			w := map[string]int{}
			for _, v := range g.ids {
				w[v] = -1
			}
			w[u] = g.verts[u].levels[d]
			for range len(g.ids) {
				for _, e := range res {
					if x := w[e.src]; x >= 0 {
						w[e.dst] = max(w[e.dst], min(x, e.effCap()[d]))
					}
				}
			}
			for v, x := range w {
				l := out[v]
				l[d] = max(l[d], x)
				out[v] = l
			}
		}
	}
	return out
}

func TestClosureMatchesOracle(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for i := range 2000 {
		g := randSpec(r, 2+r.IntN(7), r.IntN(16), false).build(1, -1)
		if got, want := closureOf(g), oracle(g); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("case %d: closure %v, oracle %v", i, got, want)
		}
	}
}

// P-01: adding an edge never lowers any closure.
func TestP01Monotone(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	for i := range 2000 {
		s := randSpec(r, 2+r.IntN(7), 1+r.IntN(14), false)
		skip := r.IntN(len(s.edges))
		without, with := closureOf(s.build(1, skip)), closureOf(s.build(1, -1))
		for id := range with {
			if !geq(with[id], without[id]) {
				t.Fatalf("case %d: adding edge %+v lowered %s: %v -> %v", i, s.edges[skip], id, without[id], with[id])
			}
		}
	}
}

// P-03: attenuation never raises a level; join is the identity on (0,0,0).
func TestP03Attenuation(t *testing.T) {
	for x := range 64 * 64 {
		l := Levels{x % 4, x / 4 % 4, x / 16 % 4}
		c := Levels{x / 64 % 4, x / 256 % 4, x / 1024 % 4}
		if a := attenuate(l, c); !geq(l, a) || !geq(c, a) {
			t.Fatalf("attenuate(%v, %v) = %v", l, c, a)
		}
		if join(l, Levels{}) != l || join(l, c) != join(c, l) {
			t.Fatal("join")
		}
	}
	for _, f := range allFlows {
		e := ledge{flow: f}
		if !geq(top, e.effCap()) {
			t.Fatal(f)
		}
	}
	if (&ledge{flow: "unknown-flow"}).effCap() != top {
		t.Fatal("unknown flow must be over-inclusive (3,3,3)")
	}
}

// P-04: nothing crosses a gated edge: the closure is the same as with the
// edge deleted, and its endpoints never appear in a witness or cut.
func TestP04Gated(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 6))
	for i := range 2000 {
		s := randSpec(r, 2+r.IntN(7), 1+r.IntN(14), false)
		k := r.IntN(len(s.edges))
		s.edges[k].gated = true
		if a, b := closureOf(s.build(1, -1)), closureOf(s.build(1, k)); fmt.Sprint(a) != fmt.Sprint(b) {
			t.Fatalf("case %d: gated edge changed the closure: %v vs %v", i, a, b)
		}
		g := s.build(1, -1)
		for _, v := range g.evaluate(func(string) Levels { return Threshold }) {
			for _, e := range v.cut {
				if e.gated {
					t.Fatalf("case %d: cut contains a gated edge", i)
				}
			}
		}
	}
}

// P-05: a promoted boolean graph keeps its v0.1 verdict under every zone.
func TestP05BooleanPromotion(t *testing.T) {
	mask := func(f string) [3]bool {
		c := flowCap[f]
		return [3]bool{c[0] == 3, c[1] == 3, c[2] == 3}
	}
	r := rand.New(rand.NewPCG(7, 8))
	zones := []Levels{{3, 3, 3}, {2, 2, 3}, {2, 2, 2}, {1, 1, 1}}
	for i := range 2000 {
		s := randSpec(r, 2+r.IntN(7), r.IntN(14), true)
		// v0.1 engine: boolean fixpoint over the residual graph.
		cl := map[string][3]bool{}
		for j, id := range s.ids {
			cl[id] = [3]bool{s.levels[j][0] == 1, s.levels[j][1] == 1, s.levels[j][2] == 1}
		}
		for changed := true; changed; {
			changed = false
			for _, e := range s.edges {
				if e.gated {
					continue
				}
				m, src, dst := mask(e.flow), cl[e.src], cl[e.dst]
				for d := range 3 {
					if src[d] && m[d] && !dst[d] {
						dst[d], changed = true, true
					}
				}
				cl[e.dst] = dst
			}
		}
		g := s.build(3, -1)
		got := closureOf(g)
		for id, b := range cl {
			want := Levels{}
			for d := range 3 {
				if b[d] {
					want[d] = 3
				}
			}
			if got[id] != want {
				t.Fatalf("case %d: %s closure %v, want 3×%v", i, id, got[id], b)
			}
		}
		for _, z := range zones {
			for _, v := range g.evaluate(func(string) Levels { return z }) {
				if full := cl[v.agent] == [3]bool{true, true, true}; v.violation != full {
					t.Fatalf("case %d zone %v: %s violation=%v, boolean %v", i, z, v.agent, v.violation, cl[v.agent])
				}
			}
		}
	}
}

// checkWitness is P-11: each witness is a real residual path from a vertex
// holding the level to the agent, every cap admits it, and the level it
// delivers is exactly the closure component.
func checkWitness(t testing.TB, g *lgraph, v verdict) {
	t.Helper()
	if !v.violation {
		return
	}
	var joined Levels
	for d := range 3 {
		p := v.witness[d]
		if len(p) == 0 || p[len(p)-1] != v.agent {
			t.Fatalf("%s: witness %v doesn't end at the agent", v.agent, p)
		}
		got := g.verts[p[0]].levels[d]
		for i := 0; i+1 < len(p); i++ {
			best := -1
			for _, e := range g.edges {
				if !e.gated && e.src == p[i] && e.dst == p[i+1] {
					best = max(best, e.effCap()[d])
				}
			}
			if best < v.closure[d] {
				t.Fatalf("%s: witness %v hop %s→%s has no edge admitting %d", v.agent, p, p[i], p[i+1], v.closure[d])
			}
			got = min(got, best)
		}
		if got < v.closure[d] {
			t.Fatalf("%s: witness %v delivers %d < %d", v.agent, p, got, v.closure[d])
		}
		joined[d] = min(got, v.closure[d])
	}
	if joined != v.closure {
		t.Fatalf("%s: witnesses join to %v, closure %v", v.agent, joined, v.closure)
	}
}

func violatesWithout(g *lgraph, agent string, t Levels, drop []*ledge) bool {
	var keep []*ledge
	for _, e := range g.residual() {
		if !slices.Contains(drop, e) {
			keep = append(keep, e)
		}
	}
	return geq(g.closure(keep)[agent], t)
}

// checkCutBreaks is P-12: the cut breaks the violation and no proper subset
// does (by monotonicity, checking the subsets one edge short suffices).
func checkCutBreaks(t testing.TB, g *lgraph, th func(string) Levels, v verdict) {
	t.Helper()
	if !v.violation || v.cut == nil {
		return
	}
	tt := th(v.agent)
	if violatesWithout(g, v.agent, tt, v.cut) {
		t.Fatalf("%s: cut %v doesn't break the violation", v.agent, cutRefs(v.cut))
	}
	if c := g.closure(slices.DeleteFunc(g.residual(), func(e *ledge) bool { return slices.Contains(v.cut, e) }))[v.agent]; c[v.cutDim] >= tt[v.cutDim] {
		t.Fatalf("%s: cut dimension %d not broken", v.agent, v.cutDim)
	}
	for i := range v.cut {
		sub := slices.Delete(slices.Clone(v.cut), i, i+1)
		if !violatesWithout(g, v.agent, tt, sub) {
			t.Fatalf("%s: proper subset %v of cut %v already breaks it", v.agent, cutRefs(sub), cutRefs(v.cut))
		}
	}
}

// P-11 and P-12 on random graphs, with a brute-force minimum cut size.
func TestP11P12WitnessAndCut(t *testing.T) {
	r := rand.New(rand.NewPCG(9, 10))
	th := func(string) Levels { return Threshold }
	checked := 0
	for i := range 3000 {
		s := randSpec(r, 2+r.IntN(6), 1+r.IntN(11), false)
		for j := range s.levels {
			if s.agent[j] && r.IntN(2) == 0 {
				s.levels[j] = Levels{} // agents usually hold nothing themselves, as in gapproof
			}
		}
		g := s.build(1, -1)
		for _, v := range g.evaluate(th) {
			checkWitness(t, g, v)
			checkCutBreaks(t, g, th, v)
			if !v.violation || v.cut == nil {
				continue
			}
			checked++
			res := g.residual()
			best := len(res) + 1
			for mask := 0; mask < 1<<len(res); mask++ {
				var drop []*ledge
				for k, e := range res {
					if mask>>k&1 == 1 {
						drop = append(drop, e)
					}
				}
				if len(drop) < best && !violatesWithout(g, v.agent, Threshold, drop) {
					best = len(drop)
				}
			}
			if best != len(v.cut) {
				t.Fatalf("case %d: %s cut %v (%d), brute-force minimum %d", i, v.agent, cutRefs(v.cut), len(v.cut), best)
			}
		}
	}
	if checked < 100 {
		t.Fatalf("only %d violating agents checked", checked)
	}
}

// Determinism (MESA P-10 analogue): edge insertion order never changes
// verdicts, witnesses or cuts.
func TestEvaluateOrderIndependent(t *testing.T) {
	r := rand.New(rand.NewPCG(11, 12))
	for i := range 500 {
		s := randSpec(r, 2+r.IntN(7), 1+r.IntN(14), false)
		a := s.build(1, -1)
		r.Shuffle(len(s.edges), func(x, y int) { s.edges[x], s.edges[y] = s.edges[y], s.edges[x] })
		b := s.build(1, -1)
		th := func(string) Levels { return Threshold }
		if fa, fb := dump(a.evaluate(th)), dump(b.evaluate(th)); fa != fb {
			t.Fatalf("case %d: order-dependent\n%s\n%s", i, fa, fb)
		}
	}
}

func dump(vs []verdict) string {
	var out []string
	for _, v := range vs {
		out = append(out, fmt.Sprint(v.agent, v.closure, v.witness, cutRefs(v.cut), v.cutDim))
	}
	b, _ := json.Marshal(out)
	return string(b)
}

func TestLevelsJSON(t *testing.T) {
	b, err := json.Marshal(Levels{1, 2, 3})
	if err != nil || string(b) != `{"P":1,"U":2,"E":3}` {
		t.Fatalf("%s %v", b, err)
	}
}

func TestEnginePanicsOnBrokenInvariants(t *testing.T) {
	mustPanic := func(name string, f func()) {
		defer func() {
			if recover() == nil {
				t.Errorf("%s: no panic", name)
			}
		}()
		f()
	}
	mustPanic("dangling edge", func() { newLGraph().addEdge(&ledge{src: "a", dst: "b"}) })
	mustPanic("no witness", func() {
		g := newLGraph()
		g.addVertex("a", true, Levels{})
		g.finish()
		g.witness(map[string][]*ledge{}, "a", DimP, 2)
	})
}

func TestCompareEdgesTotal(t *testing.T) {
	c := Levels{3, 3, 3}
	a := &ledge{src: "s", dst: "d", flow: FlowRead}
	b := &ledge{src: "s", dst: "d", flow: FlowRead, cap: &c}
	g := &ledge{src: "s", dst: "d", flow: FlowRead, gated: true}
	if compareEdges(a, b) >= 0 || compareEdges(b, a) <= 0 || compareEdges(a, g) >= 0 || compareEdges(a, a) != 0 {
		t.Fatal("edge order")
	}
}
