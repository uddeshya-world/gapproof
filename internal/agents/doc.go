// Package agents builds the agent capability graph from a vendor-declared
// manifest (agents.yaml, spec §3.5) and checks it against INV-01 as MESA
// defines it (D-032).
//
// # INV-01 (MESA graded lattice)
//
// This is a Go port of mesa-ibi-scanner's lattice (docs/LATTICE.md §1–5
// and §8, mesa_ibi_scanner/lattice.py; Apache-2.0, same author; see
// MESASpec). Every vertex has a level vector L = (P, U, E), each 0–3:
// privilege, untrusted input, egress. Gated edges are removed, then the
// closure is the least fixpoint
//
//	Cl(v) = L(v) ⊔ ⊔ { attenuate(Cl(u), cap(e)) : e = u → v }
//
// where attenuate takes the component-wise minimum with the edge's flow
// cap. An agent violates INV-01 when Cl(agent) ≥ (2, 2, 2) component-wise,
// MESA's production threshold and default zone. A manifest can't choose a
// zone or thresholds. An agent with exactly one component below the
// threshold is a near miss (an info finding that never affects AGR).
//
// # Mapping from agents.yaml (D-032)
//
//   - An agent is a vertex with L = (0, 0, 0).
//   - Each (agent, tool) pair is a vertex ("agent:tool"), so a cut can name
//     one agent's copy of a tool.
//   - reads: sensitive P=3, internal P=2, public U=2, untrusted U=3.
//   - sinks: boundary_crossing E=3, or E=2 with a non-empty targets
//     allowlist; internal E=1; exec E=3.
//   - A tool feeds its agent along a `read` edge (cap 3,3,0) if it reads
//     anything, and a `proxy/egress` edge (cap 0,0,3) if it sinks anything.
//   - A handoff A → B is a `read` edge: B gets A's data and untrusted input,
//     not A's egress.
//   - gates: tool: human_approval gates that tool's edges in every agent.
//
// # Findings
//
// Each violating agent gets one AGENT-INV01-<agent> finding (high,
// unwaivable). It carries the closure, a witness path per dimension
// (shortest, ties broken by vertex id) and the minimal edge cut on one
// dimension (Dinic max-flow, source-side cut; the smallest cut wins, ties
// go to P, then U, then E). The cut is worded "gate `x` in `a` (or remove
// `x` from `a`)" or "remove the handoff `a` → `b`". A `gates:` entry gates
// the tool in every agent, which by monotonicity also breaks the violation.
//
// The manifest is vendor-supplied and hostile: input size, agent, tool,
// handoff and label counts are bounded (see the Max* constants), decoding is
// strict (unknown keys, labels and gate kinds are errors), and the analysis
// is polynomial: closure O(|V|·|E|), and per violating agent three max-flow
// computations on unit-capacity graphs.
//
// Every result is based on a vendor-declared manifest. Gapproof can't see
// whether the deployed agents match it.
package agents
