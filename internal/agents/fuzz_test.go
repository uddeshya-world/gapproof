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
		if len(r.Paths) > MaxReportedPaths || (r.Violations == 0) != (len(r.Paths) == 0) {
			t.Fatalf("inconsistent result: %+v", r)
		}
		if (r.Violations == 0) != (len(r.CutSet) == 0) {
			t.Fatalf("cut set %v with %d violations", r.CutSet, r.Violations)
		}
		if len(fs) < len(r.Paths) {
			t.Fatalf("%d findings for %d paths", len(fs), len(r.Paths))
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
