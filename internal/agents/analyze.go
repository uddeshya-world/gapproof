package agents

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"

	"github.com/uddeshya-world/gapproof/internal/evidence"
)

// Rules.
const (
	RuleINV01Path      = "AGENT-INV01-PATH"
	RuleINV01Truncated = "AGENT-INV01-PATHS-TRUNCATED"
)

// Statements the report must carry (AGR_SPEC §1, M5 acceptance).
const (
	StatementDeclared = "based on a vendor-declared manifest"
	StatementNoAgents = "no agentic tool use, vendor-declared"
)

var inv01Controls = []string{"AC-3", "AC-4", "AC-6"}

// Result is the agents module outcome. AGR-4 needs Ran && Violations == 0.
type Result struct {
	Ran            bool     `json:"ran"`
	NoAgents       bool     `json:"no_agents"`
	Statement      string   `json:"statement"`
	Manifest       string   `json:"manifest"`
	ManifestSHA256 string   `json:"manifest_sha256"`
	Agents         int      `json:"agents"`
	Tools          int      `json:"tools"`
	Nodes          int      `json:"nodes"`
	Violations     int      `json:"violations"` // violating (source, sink) pairs, never capped
	Paths          []Path   `json:"paths"`      // at most MaxReportedPaths
	PathsTruncated bool     `json:"paths_truncated"`
	CutSet         []Action `json:"cut_set"`
	CutSetMinimal  bool     `json:"cut_set_minimal"`
	Suggestion     string   `json:"suggestion,omitempty"`
}

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
	g := newGraph(m)
	r := &Result{
		Ran: true, NoAgents: len(m.Agents) == 0, Statement: StatementDeclared,
		Manifest: name, ManifestSHA256: sha,
		Agents: len(m.Agents), Tools: len(m.Tools), Nodes: g.nodes,
		Paths: []Path{}, CutSet: []Action{},
	}
	if r.NoAgents {
		r.Statement = StatementNoAgents
		r.CutSetMinimal = true
		return r, nil
	}
	base := state{gated: map[string]bool{}, removed: map[[2]string]bool{}}
	for t := range m.Gates {
		base.gated[t] = true // validated: the only kind is human_approval
	}
	r.Violations, r.Paths = g.violations(base, true, false)
	if r.Paths == nil {
		r.Paths = []Path{}
	}
	r.PathsTruncated = r.Violations > len(r.Paths)
	cut, minimal := minimalCut(g, base)
	if cut != nil {
		r.CutSet = cut
	}
	r.CutSetMinimal = minimal
	r.Suggestion = suggestion(cut, minimal)
	return r, r.findings()
}

func (r *Result) findings() []evidence.Finding {
	var out []evidence.Finding
	for _, p := range r.Paths {
		what := "crosses the network boundary"
		switch p.Kind {
		case SinkExec:
			what = "executes code"
		case SinkBoundary + "+" + SinkExec:
			what = "executes code and crosses the network boundary"
		}
		via := "directly"
		if len(p.Nodes) == 1 {
			via = "in a single tool"
		} else if len(p.Nodes) > 2 {
			via = fmt.Sprintf("through %d intermediate tool(s)", len(p.Nodes)-2)
		}
		out = append(out, evidence.Finding{
			Rule:     RuleINV01Path,
			Severity: evidence.High,
			Title:    fmt.Sprintf("Sensitive data from %s can reach %s with no human approval", p.Source, p.Sink),
			Explanation: fmt.Sprintf("Based on a vendor-declared manifest: %s reads sensitive data, and its output can reach %s (%s), which %s, with no human_approval gate on the path. "+
				"This violates INV-01 (working form, spec §3.5). INV-01 findings can't be waived (AGR_SPEC §4); the mitigation is a gate or a removed tool in the manifest.",
				p.Source, p.Sink, via, what),
			Evidence: evidence.Evidence{Path: r.Manifest, SHA256: r.ManifestSHA256, Detail: p.String()},
			Fix:      r.Suggestion,
			Controls: slices.Clone(inv01Controls),
		})
	}
	if r.PathsTruncated {
		out = append(out, evidence.Finding{
			Rule:     RuleINV01Truncated,
			Severity: evidence.High,
			Title:    fmt.Sprintf("%d more INV-01 violations not listed", r.Violations-len(r.Paths)),
			Explanation: fmt.Sprintf("Based on a vendor-declared manifest: %d (source, sink) pairs violate INV-01; only the first %d are listed with an example path.",
				r.Violations, len(r.Paths)),
			Evidence: evidence.Evidence{Path: r.Manifest, SHA256: r.ManifestSHA256,
				Detail: fmt.Sprintf("violations=%d listed=%d cap=%d", r.Violations, len(r.Paths), MaxReportedPaths)},
			Fix:      r.Suggestion,
			Controls: slices.Clone(inv01Controls),
		})
	}
	evidence.Sort(out)
	return out
}
