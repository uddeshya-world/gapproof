package agents

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/uddeshya-world/gapproof/internal/evidence"
)

// Rules. An INV-01 violation is RuleINV01Prefix + agent name; it shares
// evidence.RuleAgentPrefix, so AGR counts it and it can't be waived. A near
// miss is RuleNearMissPrefix + agent name, severity info: it never affects
// the level.
const (
	RuleINV01Prefix    = evidence.RuleAgentPrefix // "AGENT-INV01-"
	RuleNearMissPrefix = "AGENT-NEARMISS-"
)

// Statements the report must carry (AGR_SPEC §1, M5 acceptance).
const (
	StatementDeclared = "based on a vendor-declared manifest"
	StatementNoAgents = "no agentic tool use, vendor-declared"
)

var inv01Controls = []string{"AC-3", "AC-4", "AC-6"}

// Result is the agents module outcome. AGR-4 needs Ran && Violations == 0.
type Result struct {
	Ran            bool           `json:"ran"`
	NoAgents       bool           `json:"no_agents"`
	Statement      string         `json:"statement"`
	Manifest       string         `json:"manifest"`
	ManifestSHA256 string         `json:"manifest_sha256"`
	MESASpec       string         `json:"mesa_spec"`
	Threshold      Levels         `json:"threshold"`
	Agents         int            `json:"agents"`
	Tools          int            `json:"tools"`
	Nodes          int            `json:"nodes"`       // (agent, tool) vertices
	Violations     int            `json:"violations"`  // violating agents
	NearMisses     int            `json:"near_misses"` // agents one dimension short
	Verdicts       []AgentVerdict `json:"verdicts"`    // every agent, sorted by name
	Suggestion     string         `json:"suggestion,omitempty"`
}

// AgentVerdict is MESA's per-agent finding.
type AgentVerdict struct {
	Agent        string    `json:"agent"`
	Closure      Levels    `json:"closure"`
	Violation    bool      `json:"violation"`
	NearMiss     bool      `json:"near_miss"`
	Missing      []string  `json:"missing"`                 // dimensions below the threshold
	Witness      *Witness  `json:"witness,omitempty"`       // violations only
	Cut          []CutEdge `json:"cut,omitempty"`           // violations only
	CutDimension string    `json:"cut_dimension,omitempty"` // "P", "U" or "E"
}

// Witness holds one shortest path per dimension, source first, the agent
// last. Vertices are agent names or "agent:tool".
type Witness struct {
	P []string `json:"P"`
	U []string `json:"U"`
	E []string `json:"E"`
}

func (w *Witness) dim(d int) []string { return [3][]string{w.P, w.U, w.E}[d] }

// Analyze parses a manifest (name is how the report refers to it, e.g. the
// file name) and checks INV-01. Output is a pure function of (name, data).
func Analyze(name string, data []byte) (*Result, []evidence.Finding, error) {
	m, err := ParseManifest(data)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", name, err)
	}
	sum := sha256.Sum256(data)
	r, fs := m.Check(name, hex.EncodeToString(sum[:]))
	return r, fs, nil
}

// Check runs INV-01 on a parsed manifest. name and sha256 identify the
// manifest file in the evidence.
func (m *Manifest) Check(name, sha string) (*Result, []evidence.Finding) {
	g := buildGraph(m)
	r := &Result{
		Ran: true, NoAgents: len(m.Agents) == 0, Statement: StatementDeclared,
		Manifest: name, ManifestSHA256: sha, MESASpec: MESASpec, Threshold: Threshold,
		Agents: len(m.Agents), Tools: len(m.Tools), Nodes: len(g.ids) - len(m.Agents),
		Verdicts: []AgentVerdict{},
	}
	if r.NoAgents {
		r.Statement = StatementNoAgents
		return r, nil
	}
	var fixes []string
	for _, v := range g.evaluate(func(string) Levels { return Threshold }) {
		av := AgentVerdict{Agent: v.agent, Closure: v.closure, Violation: v.violation, NearMiss: v.nearMiss, Missing: []string{}}
		for _, d := range v.missing {
			av.Missing = append(av.Missing, dimNames[d])
		}
		if v.violation {
			r.Violations++
			av.Witness = &Witness{P: v.witness[DimP], U: v.witness[DimU], E: v.witness[DimE]}
			for _, e := range v.cut {
				av.Cut = append(av.Cut, cutEdge(e))
			}
			if v.cutDim >= 0 {
				av.CutDimension = dimNames[v.cutDim]
			}
			fixes = append(fixes, "`"+v.agent+"`: "+cutText(av.Cut))
		}
		if v.nearMiss {
			r.NearMisses++
		}
		r.Verdicts = append(r.Verdicts, av)
	}
	if len(fixes) > 0 {
		r.Suggestion = "INV-01 smallest fix per violating agent (MESA minimal cut): " + strings.Join(fixes, "; ") + "."
	}
	return r, r.findings()
}

func cutText(cut []CutEdge) string {
	parts := make([]string, len(cut))
	for i, c := range cut {
		parts[i] = c.String()
	}
	return strings.Join(parts, ", and ")
}

func path(p []string) string { return strings.Join(p, " → ") }

func (r *Result) findings() []evidence.Finding {
	var out []evidence.Finding
	ev := func(detail string) evidence.Evidence {
		return evidence.Evidence{Path: r.Manifest, SHA256: r.ManifestSHA256, Detail: detail}
	}
	for _, v := range r.Verdicts {
		switch {
		case v.Violation:
			var wit []string
			for d := range 3 {
				wit = append(wit, dimNames[d]+": "+path(v.Witness.dim(d)))
			}
			fix := "Apply " + cutText(v.Cut) + "."
			if len(v.Cut) > 1 {
				fix = "Apply all of: " + cutText(v.Cut) + "."
			}
			fix += " A `gates:` entry applies to every agent that holds the tool."
			out = append(out, evidence.Finding{
				Rule:     RuleINV01Prefix + v.Agent,
				Severity: evidence.High,
				Title:    fmt.Sprintf("Agent %s combines private data, untrusted input and egress (INV-01)", v.Agent),
				Explanation: fmt.Sprintf("Based on a vendor-declared manifest: with every human_approval-gated edge removed, agent %s's closure is %s, which meets the INV-01 threshold %s on every dimension (%s). "+
					"Witness paths: %s. Minimal cut (%s, %d edge(s)): %s. "+
					"INV-01 findings can't be waived (AGR_SPEC §4); the mitigation is a gate or a removed tool in the manifest.",
					v.Agent, v.Closure, r.Threshold, r.MESASpec, strings.Join(wit, "; "),
					dimLong[slices.Index(dimNames[:], v.CutDimension)], len(v.Cut), cutText(v.Cut)),
				Evidence: ev(fmt.Sprintf("closure=%s threshold=%s; %s", v.Closure, r.Threshold, strings.Join(wit, "; "))),
				Fix:      fix,
				Controls: slices.Clone(inv01Controls),
			})
		case v.NearMiss:
			d := slices.Index(dimNames[:], v.Missing[0])
			out = append(out, evidence.Finding{
				Rule:     RuleNearMissPrefix + v.Agent,
				Severity: evidence.Info,
				Title:    fmt.Sprintf("Agent %s is one dimension short of INV-01: %s", v.Agent, dimLong[d]),
				Explanation: fmt.Sprintf("Based on a vendor-declared manifest: agent %s's closure is %s. It meets the INV-01 threshold %s on every dimension except %s (%d < %d). "+
					"This is a near miss (%s): it doesn't affect the AGR level, but one more ungated tool or handoff carrying %s would make it a violation.",
					v.Agent, v.Closure, r.Threshold, dimLong[d], v.Closure[d], r.Threshold[d], r.MESASpec, nearMissWhat[d]),
				Evidence: ev(fmt.Sprintf("closure=%s threshold=%s; missing %s", v.Closure, r.Threshold, v.Missing[0])),
				Fix:      fmt.Sprintf("No change required. Keep %s from reaching agent %s ungated, directly or through a handoff.", nearMissWhat[d], v.Agent),
				Controls: slices.Clone(inv01Controls),
			})
		}
	}
	evidence.Sort(out)
	return out
}

var nearMissWhat = [3]string{
	"data at P ≥ 2 (a `reads: [internal]` or `reads: [sensitive]` tool)",
	"untrusted input at U ≥ 2 (a `reads: [public]` or `reads: [untrusted]` tool)",
	"egress at E ≥ 2 (a `boundary_crossing` or `exec` sink)",
}
