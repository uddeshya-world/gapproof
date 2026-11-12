package agents

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

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

func analyzeYAML(t testing.TB, y string) (*Result, []evidence.Finding) {
	t.Helper()
	r, fs, err := Analyze("m.yaml", []byte(y))
	if err != nil {
		t.Fatal(err)
	}
	return r, fs
}

func verdictOf(t testing.TB, r *Result, agent string) AgentVerdict {
	t.Helper()
	for _, v := range r.Verdicts {
		if v.Agent == agent {
			return v
		}
	}
	t.Fatalf("no verdict for %s in %+v", agent, r.Verdicts)
	return AgentVerdict{}
}

func TestMapping(t *testing.T) {
	cases := []struct {
		tool Tool
		want Levels
	}{
		{Tool{}, Levels{0, 0, 0}},
		{Tool{Reads: []string{ReadSensitive}}, Levels{3, 0, 0}},
		{Tool{Reads: []string{ReadInternal}}, Levels{2, 0, 0}},
		{Tool{Reads: []string{ReadPublic}}, Levels{0, 2, 0}},
		{Tool{Reads: []string{ReadUntrusted}}, Levels{0, 3, 0}},
		{Tool{Reads: []string{ReadInternal, ReadSensitive, ReadPublic, ReadUntrusted}}, Levels{3, 3, 0}},
		{Tool{Sinks: []string{SinkBoundary}}, Levels{0, 0, 3}},
		{Tool{Sinks: []string{SinkBoundary}, Targets: []string{"api.example.com"}}, Levels{0, 0, 2}},
		{Tool{Sinks: []string{SinkInternal}}, Levels{0, 0, 1}},
		{Tool{Sinks: []string{SinkExec}, Targets: []string{"x"}}, Levels{0, 0, 3}},
		{Tool{Sinks: []string{SinkInternal, SinkBoundary}, Targets: []string{"x"}}, Levels{0, 0, 2}},
	}
	for _, c := range cases {
		if got := c.tool.Levels(); got != c.want {
			t.Errorf("%+v: levels %v, want %v", c.tool, got, c.want)
		}
	}
	if Threshold != (Levels{2, 2, 2}) {
		t.Fatalf("threshold = %v", Threshold)
	}
}

func TestBuildGraph(t *testing.T) {
	m, err := ParseManifest([]byte(`
agents:
  - {name: a, tools: [rd, post, both, idle], handoffs: [b]}
  - {name: b, tools: [rd]}
tools: {rd: {reads: [public]}, post: {sinks: [internal]}, both: {reads: [internal], sinks: [exec]}, idle: {}}
gates: {rd: human_approval}`))
	if err != nil {
		t.Fatal(err)
	}
	g := buildGraph(m)
	var got []string
	for _, e := range g.edges {
		got = append(got, fmt.Sprintf("%s->%s %s gated=%v", e.src, e.dst, e.flow, e.gated))
	}
	want := []string{
		"a->b read gated=false",
		"a:both->a proxy/egress gated=false",
		"a:both->a read gated=false",
		"a:post->a proxy/egress gated=false",
		"a:rd->a read gated=true",
		"b:rd->b read gated=true",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("edges:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if !slices.Equal(g.ids, []string{"a", "a:both", "a:idle", "a:post", "a:rd", "b", "b:rd"}) {
		t.Fatalf("ids = %v", g.ids)
	}
}

func TestDemoManifests(t *testing.T) {
	leaky, fs := analyze(t, "leaky.yaml")
	if !leaky.Ran || leaky.NoAgents || leaky.Violations != 1 || leaky.NearMisses != 0 || leaky.Nodes != 5 {
		t.Fatalf("leaky result = %+v", leaky)
	}
	if leaky.MESASpec != "mesa-ibi-scanner 0.4.0 LATTICE (b9cb325)" || leaky.Threshold != (Levels{2, 2, 2}) {
		t.Fatalf("spec/threshold = %q %v", leaky.MESASpec, leaky.Threshold)
	}
	v := verdictOf(t, leaky, "analyst")
	if !v.Violation || v.Closure != (Levels{3, 3, 3}) || len(v.Missing) != 0 {
		t.Fatalf("verdict = %+v", v)
	}
	wantW := Witness{
		P: []string{"analyst:read_file", "analyst"},
		U: []string{"analyst:fetch_url", "analyst"},
		E: []string{"analyst:run_python", "analyst"},
	}
	if fmt.Sprint(*v.Witness) != fmt.Sprint(wantW) {
		t.Fatalf("witness = %+v", *v.Witness)
	}
	// U has one source edge; P and E have two each.
	if v.CutDimension != "U" || !slices.Equal(v.Cut, []CutEdge{{Agent: "analyst", Tool: "fetch_url"}}) {
		t.Fatalf("cut = %v on %s", v.Cut, v.CutDimension)
	}
	if want := "INV-01 smallest fix per violating agent (MESA minimal cut): `analyst`: gate `fetch_url` in `analyst` (or remove `fetch_url` from `analyst`)."; leaky.Suggestion != want {
		t.Fatalf("suggestion = %q", leaky.Suggestion)
	}
	if len(fs) != 1 {
		t.Fatalf("leaky findings = %+v", fs)
	}
	f := fs[0]
	if f.Rule != "AGENT-INV01-analyst" || !strings.HasPrefix(f.Rule, evidence.RuleAgentPrefix) || f.Severity != evidence.High ||
		!slices.Equal(f.Controls, []string{"AC-3", "AC-4", "AC-6"}) || evidence.Waivable(f.Rule) {
		t.Fatalf("finding = %+v", f)
	}
	for _, s := range []string{StatementDeclared, "(P=3, U=3, E=3)", "(P=2, U=2, E=2)", "mesa-ibi-scanner 0.4.0 LATTICE (b9cb325)",
		"P: analyst:read_file → analyst", "U: analyst:fetch_url → analyst", "E: analyst:run_python → analyst",
		"Minimal cut (untrusted input (U), 1 edge(s)): gate `fetch_url` in `analyst`"} {
		if !strings.Contains(strings.ToLower(f.Explanation), strings.ToLower(s)) {
			t.Errorf("explanation lacks %q: %s", s, f.Explanation)
		}
	}
	if f.Evidence.Path != "leaky.yaml" || len(f.Evidence.SHA256) != 64 ||
		f.Evidence.Detail != "closure=(P=3, U=3, E=3) threshold=(P=2, U=2, E=2); P: analyst:read_file → analyst; U: analyst:fetch_url → analyst; E: analyst:run_python → analyst" {
		t.Errorf("evidence = %+v", f.Evidence)
	}
	if f.Fix != "Apply gate `fetch_url` in `analyst` (or remove `fetch_url` from `analyst`). A `gates:` entry applies to every agent that holds the tool." {
		t.Errorf("fix = %q", f.Fix)
	}

	fixed, fs := analyze(t, "fixed.yaml")
	if !fixed.Ran || fixed.Violations != 0 || fixed.NearMisses != 1 || fixed.Suggestion != "" || fixed.Statement != StatementDeclared {
		t.Fatalf("fixed = %+v", fixed)
	}
	v = verdictOf(t, fixed, "analyst")
	if v.Violation || !v.NearMiss || v.Closure != (Levels{3, 3, 0}) || !slices.Equal(v.Missing, []string{"E"}) || v.Witness != nil || v.Cut != nil {
		t.Fatalf("fixed verdict = %+v", v)
	}
	if len(fs) != 1 || fs[0].Rule != "AGENT-NEARMISS-analyst" || fs[0].Severity != evidence.Info ||
		strings.HasPrefix(fs[0].Rule, evidence.RuleAgentPrefix) || !strings.Contains(fs[0].Title, "egress (E)") ||
		fs[0].Evidence.Detail != "closure=(P=3, U=3, E=0) threshold=(P=2, U=2, E=2); missing E" {
		t.Fatalf("fixed findings = %+v", fs)
	}
}

// A near miss must never move the AGR level: it is info, outside the
// AGENT-INV01- prefix, and the AGR-3 checks skip info agents findings.
func TestNearMissDoesNotAffectAGR(t *testing.T) {
	_, fs := analyze(t, "fixed.yaml")
	evidence.AssignIDs(fs)
	in := evidence.AGRInput{
		EgressRan: true, TargetStarted: true, WorkloadPassed: true, ObservedWindowS: 60,
		ModulesRan:   []string{evidence.ModEgress, evidence.ModPhoneHome, evidence.ModCrypto, evidence.ModModels, evidence.ModAgents},
		Findings:     fs,
		ModelsHashed: true, AgentsManifest: true,
	}
	if got := evidence.Compute(in); got.Level != evidence.LevelAGR4 {
		t.Fatalf("near miss changed the level: %+v", got)
	}
	_, fs = analyze(t, "leaky.yaml")
	evidence.AssignIDs(fs)
	in.Findings = fs
	if got := evidence.Compute(in); got.Level != evidence.LevelAGR3 || len(got.Blocking) != 1 || !strings.Contains(got.Blocking[0].Reason, "1 INV-01 violation") {
		t.Fatalf("leaky level = %+v", got)
	}
}

func TestNoAgents(t *testing.T) {
	r, fs := analyze(t, "none.yaml")
	if !r.Ran || !r.NoAgents || r.Violations != 0 || fs != nil || r.Statement != StatementNoAgents || r.Threshold != Threshold {
		t.Fatalf("none = %+v", r)
	}
}

func TestHandoff(t *testing.T) {
	r, fs := analyze(t, "handoff.yaml")
	if r.Violations != 1 || r.NearMisses != 2 || len(fs) != 3 {
		t.Fatalf("result = %+v findings %d", r, len(fs))
	}
	v := verdictOf(t, r, "notifier")
	want := Witness{
		P: []string{"retriever:read_db", "retriever", "summarizer", "notifier"},
		U: []string{"retriever:read_inbox", "retriever", "summarizer", "notifier"},
		E: []string{"notifier:send_email", "notifier"},
	}
	if v.Closure != (Levels{3, 3, 3}) || fmt.Sprint(*v.Witness) != fmt.Sprint(want) {
		t.Fatalf("notifier = %+v witness %+v", v, *v.Witness)
	}
	// Every dimension has a one-edge cut; P wins the tie, and the
	// source-side cut is the edge nearest the source.
	if v.CutDimension != "P" || !slices.Equal(v.Cut, []CutEdge{{Agent: "retriever", Tool: "read_db"}}) {
		t.Fatalf("cut = %v on %s", v.Cut, v.CutDimension)
	}
	for _, a := range []string{"retriever", "summarizer"} {
		if v := verdictOf(t, r, a); !v.NearMiss || v.Closure != (Levels{3, 3, 0}) {
			t.Fatalf("%s = %+v", a, v)
		}
	}
	var rules []string
	for _, f := range fs {
		rules = append(rules, f.Rule)
	}
	if !slices.Equal(rules, []string{"AGENT-INV01-notifier", "AGENT-NEARMISS-retriever", "AGENT-NEARMISS-summarizer"}) {
		t.Fatalf("rules = %v", rules)
	}
}

func TestSemantics(t *testing.T) {
	cases := []struct {
		name, yaml string
		agent      string
		closure    Levels
		violation  bool
		cut        []CutEdge
	}{
		{"public browsing is no longer harmless (D-032)", `
agents: [{name: a, tools: [web, db, post]}]
tools: {web: {reads: [public]}, db: {reads: [internal]}, post: {sinks: [boundary_crossing], targets: [api.example.com]}}`,
			"a", Levels{2, 2, 2}, true, []CutEdge{{Agent: "a", Tool: "db"}}},
		{"mesh-internal egress stays below the threshold", `
agents: [{name: a, tools: [web, db, save]}]
tools: {web: {reads: [untrusted]}, db: {reads: [sensitive]}, save: {sinks: [internal]}}`,
			"a", Levels{3, 3, 1}, false, nil},
		{"a gate removes every edge of that tool", `
agents: [{name: a, tools: [web, db, run]}]
tools: {web: {reads: [untrusted]}, db: {reads: [sensitive]}, run: {sinks: [exec]}}
gates: {run: human_approval}`,
			"a", Levels{3, 3, 0}, false, nil},
		{"a handoff carries data and untrusted input, not egress", `
agents:
  - {name: a, tools: [post], handoffs: [b]}
  - {name: b, tools: [web, db]}
tools: {web: {reads: [untrusted]}, db: {reads: [sensitive]}, post: {sinks: [boundary_crossing]}}`,
			"b", Levels{3, 3, 0}, false, nil},
		{"handoff into the egress holder violates; the source-side cut is nearest the source", `
agents:
  - {name: a, tools: [web, db], handoffs: [b]}
  - {name: b, tools: [post]}
tools: {web: {reads: [untrusted]}, db: {reads: [sensitive]}, post: {sinks: [boundary_crossing]}}`,
			"b", Levels{3, 3, 3}, true, []CutEdge{{Agent: "a", Tool: "db"}}},
		{"an agent with no tools still relays", `
agents:
  - {name: a, tools: [web, db], handoffs: [m]}
  - {name: m, tools: [], handoffs: [c]}
  - {name: c, tools: [run]}
tools: {web: {reads: [untrusted]}, db: {reads: [sensitive]}, run: {sinks: [exec]}}`,
			"c", Levels{3, 3, 3}, true, []CutEdge{{Agent: "a", Tool: "db"}}},
		{"one tool can hold all three", `
agents: [{name: a, tools: [inbox]}]
tools: {inbox: {reads: [sensitive, untrusted], sinks: [boundary_crossing]}}`,
			"a", Levels{3, 3, 3}, true, []CutEdge{{Agent: "a", Tool: "inbox"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, fs := analyzeYAML(t, c.yaml)
			v := verdictOf(t, r, c.agent)
			if v.Closure != c.closure || v.Violation != c.violation || !slices.Equal(v.Cut, c.cut) {
				t.Fatalf("verdict = %+v", v)
			}
			if c.violation != slices.ContainsFunc(fs, func(f evidence.Finding) bool { return f.Rule == RuleINV01Prefix+c.agent }) {
				t.Fatalf("findings = %+v", fs)
			}
		})
	}
}

func TestCutWording(t *testing.T) {
	if got := (CutEdge{Agent: "a", Tool: "x"}).String(); got != "gate `x` in `a` (or remove `x` from `a`)" {
		t.Fatal(got)
	}
	if got := (CutEdge{Agent: "a", Handoff: "b"}).String(); got != "remove the handoff `a` → `b`" {
		t.Fatal(got)
	}
	// Two parallel routes: a two-edge cut, worded as "Apply all of".
	_, fs := analyzeYAML(t, `
agents: [{name: a, tools: [w1, w2, db, run]}]
tools: {w1: {reads: [untrusted]}, w2: {reads: [public]}, db: {reads: [sensitive, internal]}, run: {sinks: [exec, boundary_crossing]}}`)
	if len(fs) != 1 || !strings.HasPrefix(fs[0].Fix, "Apply gate `db` in `a`") {
		t.Fatalf("fix = %q", fs[0].Fix)
	}
	_, fs = analyzeYAML(t, `
agents: [{name: a, tools: [w1, w2, d1, d2, e1, e2]}]
tools: {w1: {reads: [untrusted]}, w2: {reads: [public]}, d1: {reads: [sensitive]}, d2: {reads: [internal]}, e1: {sinks: [exec]}, e2: {sinks: [internal, boundary_crossing]}}`)
	if len(fs) != 1 || !strings.HasPrefix(fs[0].Fix, "Apply all of: gate `d1` in `a` (or remove `d1` from `a`), and gate `d2` in `a`") {
		t.Fatalf("fix = %q", fs[0].Fix)
	}
}

func TestJSONShape(t *testing.T) {
	r, _ := analyze(t, "leaky.yaml")
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{`"threshold":{"P":2,"U":2,"E":2}`, `"mesa_spec":"mesa-ibi-scanner 0.4.0 LATTICE (b9cb325)"`,
		`"closure":{"P":3,"U":3,"E":3}`, `"cut_dimension":"U"`, `"cut":[{"agent":"analyst","tool":"fetch_url"}]`} {
		if !strings.Contains(string(b), s) {
			t.Errorf("json lacks %s: %s", s, b)
		}
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
	const noZone = "`zone` and `thresholds` can't be set"
	cases := []struct{ name, yaml, want string }{
		{"empty", "", "empty"},
		{"missing agents", "tools: {}\n", "`agents:` is required"},
		{"unknown top key", "agents: []\nmodels: []\n", "field models not found"},
		{"zone", "agents: []\nzone: research\n", noZone},
		{"null zone", "agents: []\nzone:\n", noZone},
		{"thresholds", "agents: []\nthresholds: {P: 3, U: 3, E: 3}\n", noZone},
		{"agent zone", "agents: [{name: a, zone: research}]\n", "field zone not found"},
		{"agent thresholds", "agents: [{name: a, thresholds: {}}]\n", "field thresholds not found"},
		{"tool levels", "agents: []\ntools: {t: {levels: {P: 0}}}\n", "field levels not found"},
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
	// Every read label is accepted.
	if _, _, err := Analyze("m.yaml", []byte("agents: []\ntools: {t: {reads: [sensitive, internal, public, untrusted]}}\n")); err != nil {
		t.Fatal(err)
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
	// Agent, tool, label and handoff order in the file must not change the output.
	a := `
agents:
  - {name: z, tools: [rd, post, web], handoffs: [y, x]}
  - {name: y, tools: [run]}
  - {name: x, tools: [run, web2]}
tools: {rd: {reads: [sensitive, internal]}, web: {reads: [untrusted]}, web2: {reads: [public]}, post: {sinks: [boundary_crossing]}, run: {sinks: [exec]}}`
	b := `
tools: {run: {sinks: [exec]}, web2: {reads: [public]}, post: {sinks: [boundary_crossing]}, web: {reads: [untrusted]}, rd: {reads: [internal, sensitive]}}
agents:
  - {name: x, tools: [web2, run]}
  - {name: y, tools: [run]}
  - {name: z, tools: [web, post, rd], handoffs: [x, y]}`
	ra, fa := analyzeYAML(t, a)
	rb, fb := analyzeYAML(t, b)
	ra.ManifestSHA256, rb.ManifestSHA256 = "", ""
	ja, _ := json.Marshal(ra)
	jb, _ := json.Marshal(rb)
	if string(ja) != string(jb) {
		t.Fatalf("order-dependent:\n%s\n%s", ja, jb)
	}
	for i := range fa {
		fa[i].Evidence.SHA256, fb[i].Evidence.SHA256 = "", ""
	}
	if fmt.Sprint(fa) != fmt.Sprint(fb) || len(fa) != 3 {
		t.Fatalf("findings differ or wrong count (%d)", len(fa))
	}
}

func TestLargeHostileGraph(t *testing.T) {
	// 100 agents × 50 tools, every agent hands off to every other: the
	// analysis stays polynomial and every agent violates.
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
		case i%10 == 3:
			fmt.Fprintf(&b, "  t%03d: {reads: [untrusted]}\n", i)
		case i%7 == 0:
			fmt.Fprintf(&b, "  t%03d: {sinks: [boundary_crossing]}\n", i)
		default:
			fmt.Fprintf(&b, "  t%03d: {}\n", i)
		}
	}
	start := time.Now()
	r, fs, err := Analyze("big.yaml", []byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if r.Violations != MaxAgents || len(fs) != MaxAgents || r.Nodes != MaxAgents*50 {
		t.Fatalf("violations=%d findings=%d nodes=%d", r.Violations, len(fs), r.Nodes)
	}
	if d := time.Since(start); d > 30*time.Second {
		t.Fatalf("took %v", d)
	}
}
