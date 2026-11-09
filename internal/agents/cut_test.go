package agents

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
)

// refViolations is an independent, node-level reference for INV-01: explicit
// nodes and edges, DFS per (source, sink) pair. It returns the pairs and the
// shortest node-path length for each.
func refViolations(m *Manifest, st state) map[[2]string]int {
	type node struct{ agent, tool string }
	var nodes []node
	for _, a := range m.Agents {
		for _, t := range a.Tools {
			if st.active(a.Name, t) {
				nodes = append(nodes, node{a.Name, t})
			}
		}
	}
	hand := map[[2]string]bool{}
	for _, a := range m.Agents {
		for _, h := range a.Handoffs {
			hand[[2]string{a.Name, h}] = true
		}
	}
	edge := func(u, v node) bool { return u != v && (u.agent == v.agent || hand[[2]string{u.agent, v.agent}]) }
	out := map[[2]string]int{}
	for _, s := range nodes {
		if !m.Tools[s.tool].Sensitive() {
			continue
		}
		// BFS where every node after s must be open.
		dist := map[node]int{s: 1}
		q := []node{s}
		for len(q) > 0 {
			u := q[0]
			q = q[1:]
			for _, v := range nodes {
				if _, seen := dist[v]; !seen && edge(u, v) && st.open(v.agent, v.tool) {
					dist[v] = dist[u] + 1
					q = append(q, v)
				}
			}
		}
		for _, k := range nodes {
			if !m.Tools[k.tool].Sink() || !st.open(k.agent, k.tool) {
				continue
			}
			key := [2]string{s.agent + ":" + s.tool, k.agent + ":" + k.tool}
			if k == s {
				out[key] = 1
			} else if d, ok := dist[k]; ok {
				out[key] = d
			}
		}
	}
	return out
}

// allActions lists every possible action, unpruned.
func allActions(m *Manifest, base state) []Action {
	var out []Action
	used := map[string]bool{}
	for _, a := range m.Agents {
		for _, t := range a.Tools {
			used[t] = true
			out = append(out, Action{Kind: ActionRemove, Tool: t, Agent: a.Name})
		}
	}
	for _, t := range sortedKeys(used) {
		if !base.gated[t] {
			out = append(out, Action{Kind: ActionGate, Tool: t})
		}
	}
	return out
}

// bruteMinCut returns the minimum cut size over every subset of every action,
// using the reference checker.
func bruteMinCut(m *Manifest, base state) int {
	acts := allActions(m, base)
	for k := 0; k <= len(acts); k++ {
		idx := make([]int, k)
		for i := range idx {
			idx[i] = i
		}
		for {
			sub := make([]Action, k)
			for i, j := range idx {
				sub[i] = acts[j]
			}
			if len(refViolations(m, base.with(sub))) == 0 {
				return k
			}
			if k == 0 || !nextComb(idx, len(acts)) {
				break
			}
		}
	}
	panic("unreachable: removing every tool is always a cut")
}

func checkAgainstReference(t *testing.T, label string, m *Manifest) *Result {
	t.Helper()
	r, _ := m.Check("m.yaml", "")
	base := baseState(m)
	ref := refViolations(m, base)
	if r.Violations != len(ref) {
		t.Fatalf("%s: violations %d, reference %d (%v)", label, r.Violations, len(ref), ref)
	}
	for _, p := range r.Paths {
		d, ok := ref[[2]string{p.Source, p.Sink}]
		if !ok {
			t.Fatalf("%s: reported pair %s → %s not in reference", label, p.Source, p.Sink)
		}
		if len(p.Nodes) != d {
			t.Fatalf("%s: path %s has %d nodes, shortest is %d", label, p, len(p.Nodes), d)
		}
		validPath(t, m, base, p)
	}
	if n := len(refViolations(m, base.with(r.CutSet))); n != 0 {
		t.Fatalf("%s: cut %v leaves %d violations", label, r.CutSet, n)
	}
	return r
}

// validPath checks every hop is a real edge and every node after the first
// is open.
func validPath(t *testing.T, m *Manifest, st state, p Path) {
	t.Helper()
	hand := map[[2]string]bool{}
	held := map[string]bool{}
	for _, a := range m.Agents {
		for _, h := range a.Handoffs {
			hand[[2]string{a.Name, h}] = true
		}
		for _, x := range a.Tools {
			held[a.Name+":"+x] = true
		}
	}
	for i, n := range p.Nodes {
		if !held[n] {
			t.Fatalf("path %s: %s not held", p, n)
		}
		ag, tool, _ := strings.Cut(n, ":")
		if i > 0 {
			if !st.open(ag, tool) {
				t.Fatalf("path %s: %s is not open", p, n)
			}
			prev, _, _ := strings.Cut(p.Nodes[i-1], ":")
			if prev != ag && !hand[[2]string{prev, ag}] {
				t.Fatalf("path %s: no edge into %s", p, n)
			}
		}
	}
}

func TestCutSetMinimalHandcrafted(t *testing.T) {
	graphs := []struct {
		name, yaml string
		want       int
	}{
		{"leaky demo", string(readFixture(t, "leaky.yaml")), 2},
		{"shared hub", `
agents:
  - {name: a, tools: [rd1], handoffs: [hub]}
  - {name: b, tools: [rd2], handoffs: [hub]}
  - {name: hub, tools: [mix], handoffs: [s1, s2]}
  - {name: s1, tools: [post1]}
  - {name: s2, tools: [post2]}
tools: {rd1: {reads: [sensitive]}, rd2: {reads: [sensitive]}, mix: {}, post1: {sinks: [boundary_crossing]}, post2: {sinks: [boundary_crossing]}}`, 1},
		{"one source, many sinks", `
agents:
  - {name: a, tools: [rd], handoffs: [b, c]}
  - {name: b, tools: [p1, p2]}
  - {name: c, tools: [p3]}
tools: {rd: {reads: [sensitive]}, p1: {sinks: [boundary_crossing]}, p2: {sinks: [exec]}, p3: {sinks: [boundary_crossing]}}`, 1},
		{"shared source-sink tool across agents", `
agents:
  - {name: x, tools: [export, rd]}
  - {name: y, tools: [export, run]}
tools: {export: {reads: [sensitive], sinks: [boundary_crossing]}, rd: {reads: [sensitive]}, run: {sinks: [exec]}}`, 2},
		{"parallel relays, crossed sources", `
agents:
  - {name: a, tools: [rd1, w1], handoffs: [r1, r2]}
  - {name: b, tools: [rd2, w2], handoffs: [r1, r2]}
  - {name: r1, tools: [x1], handoffs: [d]}
  - {name: r2, tools: [x2], handoffs: [d]}
  - {name: d, tools: [post, mail]}
tools: {rd1: {reads: [sensitive]}, rd2: {reads: [sensitive]}, w1: {sinks: [exec]}, w2: {sinks: [boundary_crossing]}, x1: {}, x2: {}, post: {sinks: [boundary_crossing]}, mail: {sinks: [boundary_crossing]}}`, 2},
	}
	for _, g := range graphs {
		t.Run(g.name, func(t *testing.T) {
			m, err := ParseManifest([]byte(g.yaml))
			if err != nil {
				t.Fatal(err)
			}
			r := checkAgainstReference(t, g.name, m)
			brute := bruteMinCut(m, baseState(m))
			if brute != g.want {
				t.Fatalf("brute force min = %d, test expects %d", brute, g.want)
			}
			if len(r.CutSet) != brute || !r.CutSetMinimal {
				t.Fatalf("cut %v (minimal=%v), brute-force minimum %d", r.CutSet, r.CutSetMinimal, brute)
			}
		})
	}
}

// TestRandomGraphsAgainstReference cross-checks violation counts, shortest
// paths and cut-set minimality on random small manifests.
func TestRandomGraphsAgainstReference(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	labels := []string{"", "reads: [sensitive]", "sinks: [boundary_crossing]", "sinks: [exec]", "reads: [sensitive], sinks: [boundary_crossing]"}
	iters := 400
	if testing.Short() {
		iters = 50
	}
	for it := range iters {
		nAgents, nTools := 1+rng.IntN(4), 1+rng.IntN(5)
		var b strings.Builder
		b.WriteString("agents:\n")
		members := 0
		for a := range nAgents {
			var ts, hs []string
			for tt := range nTools {
				if members < 8 && rng.IntN(3) == 0 {
					ts = append(ts, fmt.Sprintf("t%d", tt))
					members++
				}
			}
			for h := range nAgents {
				if rng.IntN(3) == 0 {
					hs = append(hs, fmt.Sprintf("a%d", h))
				}
			}
			fmt.Fprintf(&b, "  - {name: a%d, tools: [%s], handoffs: [%s]}\n", a, strings.Join(ts, ", "), strings.Join(hs, ", "))
		}
		b.WriteString("tools:\n")
		var gates []string
		for tt := range nTools {
			fmt.Fprintf(&b, "  t%d: {%s}\n", tt, labels[rng.IntN(len(labels))])
			if rng.IntN(6) == 0 {
				gates = append(gates, fmt.Sprintf("t%d: human_approval", tt))
			}
		}
		fmt.Fprintf(&b, "gates: {%s}\n", strings.Join(gates, ", "))
		m, err := ParseManifest([]byte(b.String()))
		if err != nil {
			t.Fatalf("iter %d: %v\n%s", it, err, b.String())
		}
		label := fmt.Sprintf("iter %d\n%s", it, b.String())
		r := checkAgainstReference(t, label, m)
		if brute := bruteMinCut(m, baseState(m)); len(r.CutSet) != brute || !r.CutSetMinimal {
			t.Fatalf("%s: cut %v (minimal=%v), brute-force minimum %d", label, r.CutSet, r.CutSetMinimal, brute)
		}
	}
}

func TestCutTooManyCandidatesForExact(t *testing.T) {
	// A graph where greedy needs >1 action, but the exact search can't run
	// because the candidate count exceeds MaxExactCandidates.
	var b strings.Builder
	b.WriteString("agents:\n")
	var tools []string
	for i := range MaxExactCandidates {
		tools = append(tools, fmt.Sprintf("p%02d", i))
	}
	fmt.Fprintf(&b, "  - {name: a, tools: [rd, %s]}\n", strings.Join(tools, ", "))
	fmt.Fprintf(&b, "  - {name: b, tools: [rd2, %s]}\n", strings.Join(tools, ", "))
	b.WriteString("tools:\n  rd: {reads: [sensitive]}\n  rd2: {reads: [sensitive]}\n")
	for _, tl := range tools {
		fmt.Fprintf(&b, "  %s: {sinks: [boundary_crossing]}\n", tl)
	}
	m, err := ParseManifest([]byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	r := checkAgainstReference(t, "wide", m)
	// Removing the two sources is optimal and greedy finds it; it just can't
	// be proven within the bounds.
	want := []Action{{Kind: ActionRemove, Tool: "rd", Agent: "a"}, {Kind: ActionRemove, Tool: "rd2", Agent: "b"}}
	if !slices.Equal(r.CutSet, want) || r.CutSetMinimal {
		t.Fatalf("cut %v minimal=%v", r.CutSet, r.CutSetMinimal)
	}
}
