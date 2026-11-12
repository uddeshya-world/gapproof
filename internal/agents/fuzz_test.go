package agents

import (
	"testing"
)

// FuzzParseManifest feeds hostile manifests through the loader and, when
// they parse, through the whole analysis. It must never panic, and the
// result must stay internally consistent.
func FuzzParseManifest(f *testing.F) {
	for _, name := range []string{"leaky.yaml", "fixed.yaml", "none.yaml", "handoff.yaml"} {
		f.Add(readFixture(f, name))
	}
	f.Add([]byte("agents: [{name: a, tools: [x], handoffs: [a]}]\ntools: {x: {reads: [sensitive], sinks: [exec]}}\n"))
	f.Add([]byte("agents: []\ntools: {true: {}, 1.5: {}, null: {}}\n"))
	f.Add([]byte("agents: &a [*a]\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, fs, err := Analyze("fuzz.yaml", data)
		if err != nil {
			return
		}
		if len(r.Verdicts) != r.Agents || len(fs) != r.Violations+r.NearMisses {
			t.Fatalf("inconsistent result: %+v, %d findings", r, len(fs))
		}
		for _, v := range r.Verdicts {
			if v.Violation != (len(v.Missing) == 0) || v.NearMiss != (len(v.Missing) == 1) {
				t.Fatalf("verdict %+v", v)
			}
			if v.Violation && (v.Witness == nil || len(v.Cut) == 0 || v.CutDimension == "") {
				t.Fatalf("violation without witness or cut: %+v", v)
			}
		}
	})
}

// FuzzSuggestManifest checks that whatever a tools/list dump contains, a
// successful suggestion parses as a valid manifest.
func FuzzSuggestManifest(f *testing.F) {
	f.Add(readTestdata(f, "mcp-files.json"))
	f.Add(readTestdata(f, "mcp-web.json"))
	f.Add([]byte(`{"tools":[{"name":"true"},{"name":"-x"},{"name":"a.b"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		out, err := SuggestManifest(data)
		if err != nil {
			return
		}
		if _, err := ParseManifest(out); err != nil {
			t.Fatalf("suggestion doesn't parse: %v\n%s", err, out)
		}
	})
}
