package agents

import "strings"

// Read labels map to a P or U level, sink labels to an E level (D-032).
var (
	readLevels = map[string]Levels{
		ReadSensitive: {3, 0, 0}, // regulated/customer
		ReadInternal:  {2, 0, 0}, // internal
		ReadPublic:    {0, 2, 0}, // anonymous-external
		ReadUntrusted: {0, 3, 0}, // public-writable
	}
	sinkLevels = map[string]Levels{
		SinkInternal: {0, 0, 1}, // mesh-internal
		SinkExec:     {0, 0, 3}, // open-internet (arbitrary code can reach anything)
		// SinkBoundary is E=3, or E=2 with a non-empty targets allowlist.
	}
)

// Levels returns the tool's MESA level vector.
func (t Tool) Levels() Levels {
	var l Levels
	for _, r := range t.Reads {
		l = join(l, readLevels[r])
	}
	for _, s := range t.Sinks {
		if s == SinkBoundary {
			e := 3
			if len(t.Targets) > 0 {
				e = 2 // allowlisted-external
			}
			l = join(l, Levels{0, 0, e})
			continue
		}
		l = join(l, sinkLevels[s])
	}
	return l
}

// toolVertex is the vertex id of tool t held by agent a. Agent names can't
// contain ':', so tool and agent ids never collide.
func toolVertex(a, t string) string { return a + ":" + t }

// buildGraph turns a manifest into a MESA lattice graph (D-032):
//   - each agent is a vertex with L = (0, 0, 0);
//   - each (agent, tool) is a vertex with the tool's levels, so a cut can
//     name one agent's copy of a tool;
//   - a tool feeds its agent along a `read` edge (3,3,0) when it reads
//     anything and a `proxy/egress` edge (0,0,3) when it sinks anything;
//   - a handoff A → B is a `read` edge: B receives A's data and untrusted
//     content, not A's egress;
//   - a human_approval gate marks that tool's edges gated in every agent.
func buildGraph(m *Manifest) *lgraph {
	g := newLGraph()
	for _, a := range m.Agents {
		g.addVertex(a.Name, true, Levels{})
	}
	for _, a := range m.Agents {
		for _, name := range a.Tools {
			t := m.Tools[name]
			id := toolVertex(a.Name, name)
			g.addVertex(id, false, t.Levels())
			_, gated := m.Gates[name]
			if len(t.Reads) > 0 {
				g.addEdge(&ledge{src: id, dst: a.Name, flow: FlowRead, gated: gated})
			}
			if len(t.Sinks) > 0 {
				g.addEdge(&ledge{src: id, dst: a.Name, flow: FlowProxyEgress, gated: gated})
			}
		}
		for _, h := range a.Handoffs {
			g.addEdge(&ledge{src: a.Name, dst: h, flow: FlowRead})
		}
	}
	g.finish()
	return g
}

// CutEdge is one edge of a minimal cut, as a manifest change.
type CutEdge struct {
	Agent   string `json:"agent"`
	Tool    string `json:"tool,omitempty"`    // a tool held by Agent
	Handoff string `json:"handoff,omitempty"` // or a handoff from Agent
}

// String words the change: "gate `x` in `a` (or remove `x` from `a`)", or
// "remove the handoff `a` → `b`".
func (c CutEdge) String() string {
	if c.Handoff != "" {
		return "remove the handoff `" + c.Agent + "` → `" + c.Handoff + "`"
	}
	return "gate `" + c.Tool + "` in `" + c.Agent + "` (or remove `" + c.Tool + "` from `" + c.Agent + "`)"
}

// cutEdge maps a graph edge back to the manifest. Agent vertices have no
// ':' in their id; tool vertices are "agent:tool".
func cutEdge(e *ledge) CutEdge {
	if i := strings.IndexByte(e.src, ':'); i >= 0 {
		return CutEdge{Agent: e.src[:i], Tool: e.src[i+1:]}
	}
	return CutEdge{Agent: e.src, Handoff: e.dst}
}
