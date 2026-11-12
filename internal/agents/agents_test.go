package agents

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/uddeshya-world/gapproof/internal/evidence"
)

func readFixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := ReadManifestFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func analyze(t testing.TB, name string) (*Result, []evidence.Finding) {
	t.Helper()
	r, fs, err := Analyze(name, readFixture(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return r, fs
}

func pathStrings(r *Result) []string {
	var out []string
	for _, p := range r.Paths {
		out = append(out, p.String())
	}
	return out
}

func TestDemoManifests(t *testing.T) {
	leaky, fs := analyze(t, "leaky.yaml")
	wantPaths := []string{
		"analyst:read_file → analyst:http_post",
		"analyst:read_file → analyst:run_python",
		"analyst:search_docs → analyst:http_post",
		"analyst:search_docs → analyst:run_python",
	}
	if got := pathStrings(leaky); !slices.Equal(got, wantPaths) {
		t.Fatalf("leaky paths = %q, want %q", got, wantPaths)
	}
	if !leaky.Ran || leaky.NoAgents || leaky.Violations != 4 || leaky.PathsTruncated {
		t.Fatalf("leaky result = %+v", leaky)
	}
	wantCut := []Action{{Kind: ActionGate, Tool: "http_post"}, {Kind: ActionRemove, Tool: "run_python", Agent: "analyst"}}
	if !slices.Equal(leaky.CutSet, wantCut) || !leaky.CutSetMinimal {
		t.Fatalf("leaky cut = %v minimal=%v, want %v", leaky.CutSet, leaky.CutSetMinimal, wantCut)
	}
	if want := "Smallest fix (2 changes, proven minimal): gate `http_post` and remove `run_python` from `analyst`."; leaky.Suggestion != want {
		t.Fatalf("suggestion = %q", leaky.Suggestion)
	}
	if leaky.Paths[1].Kind != "boundary_crossing+exec" || leaky.Paths[0].Kind != SinkBoundary {
		t.Fatalf("kinds = %v", leaky.Paths)
	}
	if len(fs) != 4 {
		t.Fatalf("leaky findings = %d", len(fs))
	}
	sum := leaky.ManifestSHA256
	if len(sum) != 64 {
		t.Fatalf("sha = %q", sum)
	}
	for i, f := range fs {
		if f.Rule != RuleINV01Path || f.Severity != evidence.High || !slices.Equal(f.Controls, []string{"AC-3", "AC-4", "AC-6"}) {
			t.Errorf("finding %d = %+v", i, f)
		}
		if !strings.Contains(strings.ToLower(f.Explanation), StatementDeclared) {
			t.Errorf("finding %d explanation lacks %q: %s", i, StatementDeclared, f.Explanation)
		}
		if f.Evidence.Path != "leaky.yaml" || f.Evidence.SHA256 != sum || f.Evidence.Detail != wantPaths[i] || f.Fix != leaky.Suggestion {
			t.Errorf("finding %d evidence = %+v fix=%q", i, f.Evidence, f.Fix)
		}
	}

	fixed, fs := analyze(t, "fixed.yaml")
	if !fixed.Ran || fixed.Violations != 0 || len(fixed.Paths) != 0 || len(fixed.CutSet) != 0 || !fixed.CutSetMinimal || fixed.Suggestion != "" || fs != nil {
		t.Fatalf("fixed = %+v, findings %v", fixed, fs)
	}
	if fixed.Statement != StatementDeclared {
		t.Fatalf("fixed statement = %q", fixed.Statement)
	}
}

func TestNoAgents(t *testing.T) {
	r, fs := analyze(t, "none.yaml")
	if !r.Ran || !r.NoAgents || r.Violations != 0 || fs != nil || r.Statement != StatementNoAgents {
		t.Fatalf("none = %+v", r)
	}
}

func TestHandoffPaths(t *testing.T) {
	r, _ := analyze(t, "handoff.yaml")
	want := []string{"retriever:read_db → summarizer:summarize → notifier:send_email"}
	if got := pathStrings(r); !slices.Equal(got, want) {
		t.Fatalf("paths = %q, want %q", got, want)
	}
	// The cheapest fixes are one action; gating the boundary sink is preferred.
	if !slices.Equal(r.CutSet, []Action{{Kind: ActionGate, Tool: "send_email"}}) || !r.CutSetMinimal {
		t.Fatalf("cut = %v", r.CutSet)
	}
	if want := "Smallest fix (1 change, proven minimal): gate `send_email`."; r.Suggestion != want {
		t.Fatalf("suggestion = %q", r.Suggestion)
	}

	cases := []struct {
		name, yaml string
		want       []string
	}{
		{"gated relay blocks the path", `
agents:
  - {name: a, tools: [rd], handoffs: [b]}
  - {name: b, tools: [mid], handoffs: [c]}
  - {name: c, tools: [post]}
tools: {rd: {reads: [sensitive]}, mid: {}, post: {sinks: [boundary_crossing]}}
gates: {mid: human_approval}`, nil},
		{"agent with no tools can't relay", `
agents:
  - {name: a, tools: [rd], handoffs: [b]}
  - {name: b, tools: [], handoffs: [c]}
  - {name: c, tools: [post]}
tools: {rd: {reads: [sensitive]}, post: {sinks: [boundary_crossing]}}`, nil},
		{"handoffs are one-way", `
agents:
  - {name: a, tools: [post], handoffs: [b]}
  - {name: b, tools: [rd]}
tools: {rd: {reads: [sensitive]}, post: {sinks: [boundary_crossing]}}`, nil},
		{"direct handoff, shortest of two routes", `
agents:
  - {name: a, tools: [rd], handoffs: [b, c]}
  - {name: b, tools: [x], handoffs: [c]}
  - {name: c, tools: [post]}
tools: {rd: {reads: [sensitive]}, x: {}, post: {sinks: [exec]}}`, []string{"a:rd → c:post"}},
		{"gated source still feeds", `
agents:
  - {name: a, tools: [rd, post]}
tools: {rd: {reads: [sensitive]}, post: {sinks: [boundary_crossing]}}
gates: {rd: human_approval}`, []string{"a:rd → a:post"}},
		{"source and sink in one tool", `
agents:
  - {name: a, tools: [export]}
tools: {export: {reads: [sensitive], sinks: [boundary_crossing]}}`, []string{"a:export"}},
		{"gated source-sink is not a violation", `
agents:
  - {name: a, tools: [export]}
tools: {export: {reads: [sensitive], sinks: [boundary_crossing]}}
gates: {export: human_approval}`, nil},
		{"internal sink and public read are not INV-01 nodes", `
agents:
  - {name: a, tools: [rd, save]}
tools: {rd: {reads: [public]}, save: {sinks: [internal]}}`, nil},
		{"cyclic handoffs terminate", `
agents:
  - {name: a, tools: [rd], handoffs: [b, a]}
  - {name: b, tools: [x], handoffs: [a, c]}
  - {name: c, tools: [y], handoffs: [b, d]}
  - {name: d, tools: [post], handoffs: [a]}
tools: {rd: {reads: [sensitive]}, x: {}, y: {}, post: {sinks: [boundary_crossing]}}`, []string{"a:rd → b:x → c:y → d:post"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, fs, err := Analyze("m.yaml", []byte(c.yaml))
			if err != nil {
				t.Fatal(err)
			}
			if got := pathStrings(r); !slices.Equal(got, c.want) {
				t.Fatalf("paths = %q, want %q", got, c.want)
			}
			if len(fs) != len(c.want) || r.Violations != len(c.want) {
				t.Fatalf("findings %d, violations %d", len(fs), r.Violations)
			}
		})
	}
}

func TestSingleToolFinding(t *testing.T) {
	_, fs, err := Analyze("m.yaml", []byte(`
agents:
  - {name: a, tools: [export, run]}
tools: {export: {reads: [sensitive], sinks: [boundary_crossing]}, run: {sinks: [exec]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 || !strings.Contains(fs[0].Explanation, "in a single tool") || !strings.Contains(fs[1].Explanation, "executes code") {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestParseErrors(t *testing.T) {
	big := "agents: []\n# " + strings.Repeat("x", MaxManifestBytes) + "\n"
	manyAgents := "agents:\n"
	for i := range MaxAgents + 1 {
		manyAgents += fmt.Sprintf("  - {name: a%d, tools: []}\n", i)
	}
	manyTools := "agents: []\ntools:\n"
	for i := range MaxTools + 1 {
		manyTools += fmt.Sprintf("  t%d: {}\n", i)
	}
	manyNodes := "agents:\n"
	for i := range MaxNodes/MaxTools + 1 {
		manyNodes += fmt.Sprintf("  - {name: a%d, tools: [%s]}\n", i, toolList(MaxTools))
	}
	manyNodes += "tools:\n"
	for i := range MaxTools {
		manyNodes += fmt.Sprintf("  t%d: {}\n", i)
	}
	cases := []struct{ name, yaml, want string }{
		{"empty", "", "empty"},
		{"missing agents", "tools: {}\n", "`agents:` is required"},
		{"unknown top key", "agents: []\nmodels: []\n", "field models not found"},
		{"unknown tool key", "agents: []\ntools: {t: {writes: [x]}}\n", "field writes not found"},
		{"unknown agent key", "agents: [{name: a, tools: [], memory: x}]\n", "field memory not found"},
		{"unknown read label", "agents: []\ntools: {t: {reads: [secret]}}\n", `unknown reads label "secret"`},
		{"unknown sink label", "agents: []\ntools: {t: {sinks: [network]}}\n", `unknown sinks label "network"`},
		{"unknown gate kind", "agents: []\ntools: {t: {}}\ngates: {t: auto_approve}\n", `unknown kind "auto_approve"`},
		{"gate on unknown tool", "agents: []\ngates: {t: human_approval}\n", "gate on unknown tool"},
		{"unknown tool in agent", "agents: [{name: a, tools: [ghost]}]\n", `unknown tool "ghost"`},
		{"unknown handoff", "agents: [{name: a, tools: [], handoffs: [b]}]\n", `handoff to unknown agent "b"`},
		{"duplicate agent", "agents: [{name: a}, {name: a}]\n", "duplicate agent a"},
		{"duplicate tool in agent", "agents: [{name: a, tools: [t, t]}]\ntools: {t: {}}\n", "listed twice"},
		{"duplicate handoff", "agents: [{name: a, handoffs: [a, a]}]\n", "listed twice"},
		{"duplicate yaml key", "agents: []\ntools: {t: {}, t: {}}\n", "already defined"},
		{"bad agent name", "agents: [{name: \"a:b\"}]\n", "name"},
		{"empty agent name", "agents: [{tools: []}]\n", "name"},
		{"bad tool name", "agents: []\ntools: {\"a b\": {}}\n", "tool name"},
		{"two documents", "agents: []\n---\nagents: []\n", "exactly one YAML document"},
		{"not a mapping", "- a\n- b\n", "cannot unmarshal"},
		{"too big", big, "larger than"},
		{"too many agents", manyAgents, "agents (max"},
		{"too many tools", manyTools, "tools (max"},
		{"too many nodes", manyNodes, "agent-tool memberships"},
		{"too many labels", "agents: []\ntools: {t: {reads: [public, public, public, public, public, public, public, public, public]}}\n", "labels (max"},
		{"too many targets", "agents: []\ntools: {t: {targets: [" + strings.TrimSuffix(strings.Repeat("x,", MaxTargetsPerTool+1), ",") + "]}}\n", "targets (max"},
		{"target too long", "agents: []\ntools: {t: {targets: [" + strings.Repeat("x", MaxTargetLen+1) + "]}}\n", "target longer"},
		{"too many agent tools", "agents: [{name: a, tools: [" + toolList(MaxTools+1) + "]}]\n", "tools (max"},
		{"too many handoffs", "agents: [{name: a, handoffs: [" + strings.TrimSuffix(strings.Repeat("a,", MaxHandoffsPerAgent+1), ",") + "]}]\n", "handoffs (max"},
		{"alias bomb", aliasBomb(), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := Analyze("m.yaml", []byte(c.yaml))
			if err == nil {
				t.Fatal("want error")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			if !strings.HasPrefix(err.Error(), "m.yaml: agents manifest: ") {
				t.Fatalf("err not prefixed: %v", err)
			}
		})
	}
}

func toolList(n int) string {
	var xs []string
	for i := range n {
		xs = append(xs, fmt.Sprintf("t%d", i))
	}
	return strings.Join(xs, ", ")
}

// aliasBomb is a billion-laughs document that fits under the size limit.
func aliasBomb() string {
	var b strings.Builder
	b.WriteString("a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n")
	for i := 1; i < 12; i++ {
		fmt.Fprintf(&b, "a%d: &a%d [", i, i)
		for j := range 10 {
			if j > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "*a%d", i-1)
		}
		b.WriteString("]\n")
	}
	b.WriteString("agents: []\n")
	return b.String()
}

func TestReadManifestFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "big.yaml")
	if err := os.WriteFile(p, make([]byte, MaxManifestBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManifestFile(p); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("err = %v", err)
	}
	if _, err := ReadManifestFile(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("want error for missing file")
	}
	if _, err := ReadManifestFile(dir); err == nil {
		t.Fatal("want error reading a directory")
	}
}

func TestDeterministic(t *testing.T) {
	// Agent and tool order in the file must not change the output.
	a := `
agents:
  - {name: z, tools: [rd, post], handoffs: [y]}
  - {name: y, tools: [run]}
tools: {rd: {reads: [sensitive]}, post: {sinks: [boundary_crossing]}, run: {sinks: [exec]}}`
	b := `
tools: {run: {sinks: [exec]}, post: {sinks: [boundary_crossing]}, rd: {reads: [sensitive]}}
agents:
  - {name: y, tools: [run]}
  - {name: z, tools: [post, rd], handoffs: [y]}`
	ra, fa, err := Analyze("m.yaml", []byte(a))
	if err != nil {
		t.Fatal(err)
	}
	rb, fb, err := Analyze("m.yaml", []byte(b))
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(ra.Paths, ra.CutSet, ra.Suggestion) != fmt.Sprint(rb.Paths, rb.CutSet, rb.Suggestion) {
		t.Fatalf("order-dependent:\n%v\n%v", ra, rb)
	}
	for i := range fa {
		fa[i].Evidence.SHA256, fb[i].Evidence.SHA256 = "", ""
	}
	if fmt.Sprint(fa) != fmt.Sprint(fb) {
		t.Fatalf("findings differ")
	}
}

func TestLargeHostileGraph(t *testing.T) {
	// 100 agents × 50 tools, every agent hands off to 99 others: bounded
	// work, capped paths, and the cut falls back to a feasible greedy/trivial
	// answer flagged as not proven minimal.
	var b strings.Builder
	b.WriteString("agents:\n")
	for i := range MaxAgents {
		var ts, hs []string
		for j := range 50 {
			ts = append(ts, fmt.Sprintf("t%03d", (i*50+j)%MaxTools))
		}
		for j := range MaxAgents {
			if j != i {
				hs = append(hs, fmt.Sprintf("a%02d", j))
			}
		}
		fmt.Fprintf(&b, "  - {name: a%02d, tools: [%s], handoffs: [%s]}\n", i, strings.Join(ts, ", "), strings.Join(hs, ", "))
	}
	b.WriteString("tools:\n")
	for i := range MaxTools {
		switch {
		case i%10 == 0:
			fmt.Fprintf(&b, "  t%03d: {reads: [sensitive]}\n", i)
		case i%7 == 0:
			fmt.Fprintf(&b, "  t%03d: {sinks: [boundary_crossing]}\n", i)
		default:
			fmt.Fprintf(&b, "  t%03d: {}\n", i)
		}
	}
	r, fs, err := Analyze("big.yaml", []byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if !r.PathsTruncated || len(r.Paths) != MaxReportedPaths || r.Violations <= MaxReportedPaths {
		t.Fatalf("violations=%d paths=%d truncated=%v", r.Violations, len(r.Paths), r.PathsTruncated)
	}
	if len(fs) != MaxReportedPaths+1 || fs[len(fs)-1].Rule != RuleINV01Truncated {
		t.Fatalf("findings = %d, last %s", len(fs), fs[len(fs)-1].Rule)
	}
	if r.CutSetMinimal || !strings.Contains(r.Suggestion, "not proven minimal") {
		t.Fatalf("cut minimal=%v suggestion=%q", r.CutSetMinimal, r.Suggestion)
	}
	m, _ := ParseManifest([]byte(b.String()))
	g := newGraph(m)
	if n, _ := g.violations(baseState(m).with(r.CutSet), false, false); n != 0 {
		t.Fatalf("cut leaves %d violations", n)
	}
}

func baseState(m *Manifest) state {
	st := state{gated: map[string]bool{}, removed: map[[2]string]bool{}}
	for t := range m.Gates {
		st.gated[t] = true
	}
	return st
}

func TestNextComb(t *testing.T) {
	idx := []int{0, 1}
	var got [][]int
	for {
		got = append(got, slices.Clone(idx))
		if !nextComb(idx, 4) {
			break
		}
	}
	if fmt.Sprint(got) != "[[0 1] [0 2] [0 3] [1 2] [1 3] [2 3]]" {
		t.Fatal(got)
	}
}

func TestSuggestionText(t *testing.T) {
	acts := []Action{{Kind: ActionGate, Tool: "a"}, {Kind: ActionGate, Tool: "b"}, {Kind: ActionRemove, Tool: "c", Agent: "x"}}
	if got := suggestion(acts, false); got != "Suggested fix (3 changes, greedy, not proven minimal): gate `a`, gate `b` and remove `c` from `x`." {
		t.Fatal(got)
	}
	if suggestion(nil, true) != "" {
		t.Fatal("empty cut must give empty suggestion")
	}
}
