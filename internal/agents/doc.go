// Package agents builds the agent capability graph from a vendor-declared
// manifest (agents.yaml, spec §3.5) and checks it against INV-01.
//
// # INV-01: working form, not yet MESA's definition
//
// MESA's own INV-01 definition was not available when this package was
// written. The package implements the spec's *working form* exactly, and it
// must be restated against MESA's definition before v0.2 (see the D-XXX
// decision entry "INV-01 working form"):
//
//	No path from a node with `reads: [sensitive]` to a node with
//	`sinks: [boundary_crossing]` or `sinks: [exec]` unless every such path
//	passes a `human_approval`-gated node.
//
// Graph model:
//   - A node is one tool held by one agent ("analyst:read_file"). The same
//     tool held by two agents is two nodes.
//   - Within one agent, any tool's output can feed any of that agent's tools.
//   - A handoff A→B lets any tool of A feed any tool of B (one direction).
//   - A gated node blocks every path that runs through it or ends at it. It
//     does not block paths that start at it: approving a read does not show
//     the approver where the data goes next.
//   - A tool that both reads sensitive data and sinks is a length-1 violation
//     unless it is gated.
//
// Gates are declared per tool, so gating a tool gates it in every agent.
//
// The manifest is vendor-supplied and hostile: input size, agent, tool,
// handoff and label counts are bounded (see the Max* constants), decoding is
// strict (unknown keys, labels and gate kinds are errors), and analysis is
// polynomial. Paths are never enumerated: each violating (source, sink) pair
// gets one shortest example path, and at most MaxReportedPaths pairs are
// listed (the total is always reported).
//
// The cut set is the smallest set of actions from {gate tool T, remove tool T
// from agent A} that removes every violation. Greedy runs first; an exact
// search over action subsets of smaller size then proves it minimal or finds
// a smaller one. When the candidates exceed MaxExactCandidates or the work
// exceeds MaxCutWork, the greedy (or trivial "gate every violating sink")
// answer is returned and flagged "not proven minimal". Ties go to: gate a
// boundary sink, remove an exec sink, gate an exec sink, gate another tool,
// remove another tool.
//
// Every result is based on a vendor-declared manifest. Gapproof can't see
// whether the deployed agents match it.
package agents
