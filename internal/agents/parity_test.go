package agents

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Golden parity with mesa-ibi-scanner (testdata/mesa/README.md). The 104
// public lattice fixtures run on the Go engine directly; a subset is also
// converted to agents.yaml and run through Analyze.

type mesaLevels struct{ P, U, E int }

func (l mesaLevels) levels() Levels { return Levels{l.P, l.U, l.E} }

type mesaFixture struct {
	ID       string `json:"id"`
	Topology struct {
		Vertices []struct {
			ID     string     `json:"id"`
			Kind   string     `json:"kind"`
			Levels mesaLevels `json:"levels"`
			Zone   string     `json:"zone"`
		} `json:"vertices"`
		Edges []struct {
			Src     string      `json:"src"`
			Dst     string      `json:"dst"`
			Flow    string      `json:"flow_type"`
			PDPGate bool        `json:"pdp_gate"`
			Cap     *mesaLevels `json:"cap"`
			Label   string      `json:"label"`
		} `json:"edges"`
	} `json:"topology"`
	Expected struct {
		Violations []string              `json:"violations"`
		NearMiss   *[]string             `json:"near_miss"`
		Closure    map[string]mesaLevels `json:"closure"`
	} `json:"expected"`
}

func mesaZones(t testing.TB) map[string]Levels {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "mesa", "zones.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		DefaultZone string                `json:"default_zone"`
		Zones       map[string]mesaLevels `json:"zones"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	out := map[string]Levels{}
	for z, l := range doc.Zones {
		out[z] = l.levels()
	}
	// gapproof's fixed threshold is MESA's default zone.
	if doc.DefaultZone != "production" || out["production"] != Threshold {
		t.Fatalf("zones.json default %q = %v, gapproof uses %v", doc.DefaultZone, out[doc.DefaultZone], Threshold)
	}
	return out
}

// loadMESA builds the lattice graph and each agent's threshold.
func loadMESA(t testing.TB, path string) (*mesaFixture, *lgraph, func(string) Levels) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fx mesaFixture
	if err := json.Unmarshal(b, &fx); err != nil {
		t.Fatal(err)
	}
	zones := mesaZones(t)
	zoneOf := map[string]string{}
	g := newLGraph()
	for _, v := range fx.Topology.Vertices {
		g.addVertex(v.ID, v.Kind == "agent", v.Levels.levels())
		zoneOf[v.ID] = v.Zone
		if v.Zone == "" {
			zoneOf[v.ID] = "production"
		}
	}
	for _, e := range fx.Topology.Edges {
		le := &ledge{src: e.Src, dst: e.Dst, flow: e.Flow, gated: e.PDPGate, label: e.Label}
		if e.Cap != nil {
			c := e.Cap.levels()
			le.cap = &c
		}
		g.addEdge(le)
	}
	g.finish()
	return &fx, g, func(id string) Levels { return zones[zoneOf[id]] }
}

func mesaFixtures(t testing.TB) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("testdata", "mesa", "lattice", "*.json"))
	if err != nil || len(files) != 104 {
		t.Fatalf("want the 104 public MESA lattice fixtures, got %d (%v)", len(files), err)
	}
	return files
}

func TestMESAGoldenParity(t *testing.T) {
	for _, path := range mesaFixtures(t) {
		fx, g, th := loadMESA(t, path)
		t.Run(fx.ID, func(t *testing.T) {
			var viol, near []string
			got := map[string]verdict{}
			for _, v := range g.evaluate(th) {
				got[v.agent] = v
				if v.violation {
					viol = append(viol, v.agent)
				}
				if v.nearMiss {
					near = append(near, v.agent)
				}
				checkWitness(t, g, v)
				checkCutBreaks(t, g, th, v)
			}
			if !slices.Equal(viol, fx.Expected.Violations) && (len(viol) > 0 || len(fx.Expected.Violations) > 0) {
				t.Errorf("violations %v, want %v", viol, fx.Expected.Violations)
			}
			if fx.Expected.NearMiss != nil && !slices.Equal(near, *fx.Expected.NearMiss) && (len(near) > 0 || len(*fx.Expected.NearMiss) > 0) {
				t.Errorf("near misses %v, want %v", near, *fx.Expected.NearMiss)
			}
			for id, want := range fx.Expected.Closure {
				if got[id].closure != want.levels() {
					t.Errorf("closure %s = %v, want %v", id, got[id].closure, want.levels())
				}
			}
		})
	}
}

func cutRefs(cut []*ledge) []string {
	var out []string
	for _, e := range cut {
		out = append(out, e.src+"->"+e.dst+" "+e.flow)
	}
	return out
}

// Witnesses and cuts, hand-derived from LATTICE §8 (the fixtures state
// only verdicts and closures). Includes MESA's own unit test
// test_violation_has_witness_and_min_cut.
func TestMESAWitnessAndCut(t *testing.T) {
	cases := []struct {
		fixture, agent string
		witness        [3][]string
		cutDim         int
		cut            []string
	}{
		{"graded-dsewiki-production", "agent:sandbox-coder",
			[3][]string{{"agent:sandbox-coder"}, {"svc:public-wiki", "agent:sandbox-coder"}, {"svc:public-wiki", "agent:sandbox-coder"}},
			// The agent holds P itself, so only U and E are cut; tie → U.
			DimU, []string{"svc:public-wiki->agent:sandbox-coder read"}},
		{"multihop-write-production", "agent:a",
			[3][]string{{"svc:s", "agent:b", "agent:a"}, {"svc:s", "agent:b", "agent:a"}, {"agent:a"}},
			// Source-side cut: the edge leaving the source.
			DimP, []string{"svc:s->agent:b read"}},
		{"graded-writer-u-web-production", "agent:ops",
			[3][]string{{"agent:ops"}, {"svc:web", "agent:researcher", "svc:shared-notes", "agent:ops"}, {"agent:ops"}},
			DimU, []string{"svc:web->agent:researcher read"}},
		{"boundary-production-at", "agent:a",
			[3][]string{{"svc:s", "agent:a"}, {"svc:s", "agent:a"}, {"agent:a"}},
			DimP, []string{"svc:s->agent:a read"}},
	}
	for _, c := range cases {
		_, g, th := loadMESA(t, filepath.Join("testdata", "mesa", "lattice", c.fixture+".json"))
		for _, v := range g.evaluate(th) {
			if v.agent != c.agent {
				continue
			}
			if fmt.Sprint(v.witness) != fmt.Sprint(c.witness) || v.cutDim != c.cutDim || !slices.Equal(cutRefs(v.cut), c.cut) {
				t.Errorf("%s: witness %v cut %v on %d", c.fixture, v.witness, cutRefs(v.cut), v.cutDim)
			}
		}
	}

	// tests/test_lattice_unit.py::test_violation_has_witness_and_min_cut
	g := newLGraph()
	g.addVertex("agent:c", true, Levels{0, 0, 3})
	g.addVertex("svc:data", false, Levels{3, 0, 0})
	g.addVertex("svc:queue", false, Levels{0, 2, 0})
	g.addEdge(&ledge{src: "svc:data", dst: "agent:c", flow: FlowRead})
	g.addEdge(&ledge{src: "svc:queue", dst: "agent:c", flow: FlowRead})
	g.finish()
	v := g.evaluate(func(string) Levels { return Threshold })[0]
	if !v.violation || fmt.Sprint(v.witness) != "[[svc:data agent:c] [svc:queue agent:c] [agent:c]]" ||
		!slices.Equal(cutRefs(v.cut), []string{"svc:data->agent:c read"}) {
		t.Fatalf("verdict %+v", v)
	}
}

// Converted fixtures: the MESA topology restated as agents.yaml (see each
// file's header), run through Analyze. Verdicts and closures must equal the
// MESA fixture's; witnesses and cuts are hand-derived for the gapproof form,
// where an agent's own level becomes a tool and so can itself be cut.
func TestMESAConvertedParity(t *testing.T) {
	cases := []struct {
		fixture string
		witness map[string]Witness // violating agents
		cut     map[string][]CutEdge
	}{
		{"graded-dsewiki-production",
			map[string]Witness{"sandbox-coder": {
				P: []string{"sandbox-coder:internal_data", "sandbox-coder"},
				U: []string{"sandbox-coder:public_wiki", "sandbox-coder"},
				E: []string{"sandbox-coder:public_wiki", "sandbox-coder"}}},
			map[string][]CutEdge{"sandbox-coder": {{Agent: "sandbox-coder", Tool: "internal_data"}}}},
		{"graded-hf-production",
			map[string]Witness{"eval-worker": {
				P: []string{"eval-worker:eval_data", "eval-worker"},
				U: []string{"eval-worker:artifact_registry", "eval-worker"},
				E: []string{"eval-worker:artifact_registry", "eval-worker"}}},
			map[string][]CutEdge{"eval-worker": {{Agent: "eval-worker", Tool: "eval_data"}}}},
		{"graded-hf-synthetic-production", nil, nil},
		{"graded-writer-u-web-production",
			map[string]Witness{"ops": {
				P: []string{"ops:internal_records", "ops"},
				U: []string{"researcher:web", "researcher", "ops"},
				E: []string{"ops:webhook", "ops"}}},
			// Same edge MESA cuts: the writer's web read.
			map[string][]CutEdge{"ops": {{Agent: "researcher", Tool: "web"}}}},
		{"multihop-write-production",
			map[string]Witness{"a": {
				P: []string{"b:s", "b", "a"},
				U: []string{"b:s", "b", "a"},
				E: []string{"a:egress", "a"}}},
			map[string][]CutEdge{"a": {{Agent: "b", Tool: "s"}}}},
		{"gated-production", nil, nil},
		{"boundary-production-at",
			map[string]Witness{"a": {P: []string{"a:s", "a"}, U: []string{"a:s", "a"}, E: []string{"a:egress", "a"}}},
			map[string][]CutEdge{"a": {{Agent: "a", Tool: "s"}}}},
		{"boundary-production-E-below", nil, nil},
		{"v01-dsewiki_like-production",
			map[string]Witness{"sandbox-coder": {
				P: []string{"sandbox-coder:private_data", "sandbox-coder"},
				U: []string{"sandbox-coder:public_get_mutable_wiki", "sandbox-coder"},
				E: []string{"sandbox-coder:public_get_mutable_wiki", "sandbox-coder"}}},
			map[string][]CutEdge{"sandbox-coder": {{Agent: "sandbox-coder", Tool: "private_data"}}}},
	}
	strip := func(ids []string) []string {
		var out []string
		for _, id := range ids {
			out = append(out, strings.TrimPrefix(id, "agent:"))
		}
		return out
	}
	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			fx, _, _ := loadMESA(t, filepath.Join("testdata", "mesa", "lattice", c.fixture+".json"))
			r, fs := analyze(t, filepath.Join("mesa", "converted", c.fixture+".yaml"))
			var viol, near []string
			for _, v := range r.Verdicts {
				if v.Violation {
					viol = append(viol, v.Agent)
					if fmt.Sprint(*v.Witness) != fmt.Sprint(c.witness[v.Agent]) || !slices.Equal(v.Cut, c.cut[v.Agent]) {
						t.Errorf("%s: witness %+v cut %v", v.Agent, *v.Witness, v.Cut)
					}
				}
				if v.NearMiss {
					near = append(near, v.Agent)
				}
				want, ok := fx.Expected.Closure["agent:"+v.Agent]
				if c.fixture == "graded-hf-synthetic-production" {
					want.P = 0 // P=1 (synthetic) has no agents.yaml label; see the file header
				}
				if ok && v.Closure != want.levels() {
					t.Errorf("%s closure %v, want %v", v.Agent, v.Closure, want.levels())
				}
			}
			if fmt.Sprint(viol) != fmt.Sprint(strip(fx.Expected.Violations)) {
				t.Errorf("violations %v, want %v", viol, fx.Expected.Violations)
			}
			if fx.Expected.NearMiss != nil && fmt.Sprint(near) != fmt.Sprint(strip(*fx.Expected.NearMiss)) {
				t.Errorf("near misses %v, want %v", near, *fx.Expected.NearMiss)
			}
			if len(fs) != len(viol)+len(near) {
				t.Errorf("%d findings", len(fs))
			}
		})
	}
}
