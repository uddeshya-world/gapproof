package agents

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

func readTestdata(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSuggestManifestGolden(t *testing.T) {
	out, err := SuggestManifest(readTestdata(t, "mcp-files.json"), readTestdata(t, "mcp-web.json"))
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "suggested.golden.yaml")
	if *update {
		if err := os.WriteFile(golden, out, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if want := readTestdata(t, "suggested.golden.yaml"); !bytes.Equal(out, want) {
		t.Fatalf("output differs from %s (run with -update):\n%s", golden, out)
	}
	again, _ := SuggestManifest(readTestdata(t, "mcp-files.json"), readTestdata(t, "mcp-web.json"))
	if !bytes.Equal(out, again) {
		t.Fatal("SuggestManifest is not deterministic")
	}

	m, err := ParseManifest(out)
	if err != nil {
		t.Fatalf("suggested manifest doesn't parse: %v\n%s", err, out)
	}
	want := map[string]Tool{
		"fetch":              {Sinks: []string{SinkBoundary}},
		"get_time":           {},
		"list_directory":     {},
		"read_file":          {Reads: []string{ReadSensitive}},
		"run_python":         {Sinks: []string{SinkExec}},
		"searchFiles":        {Reads: []string{ReadSensitive}},
		"slack_post_message": {Sinks: []string{SinkBoundary}},
	}
	if fmt.Sprint(m.Tools) != fmt.Sprint(want) {
		t.Fatalf("labels = %v\nwant     %v", m.Tools, want)
	}
	if len(m.Agents) != 1 || len(m.Agents[0].Tools) != len(want) {
		t.Fatalf("agents = %+v", m.Agents)
	}
	for _, s := range []string{"LOW-CONFIDENCE", "A human must confirm", "invalid name \"bad name\\nwith newline\" skipped", "duplicate tool read_file skipped"} {
		if !strings.Contains(string(out), s) {
			t.Errorf("output lacks %q", s)
		}
	}
	// The suggested manifest flows into the analysis.
	r, _ := m.Check("suggested.yaml", "")
	if r.Violations == 0 {
		t.Fatal("suggested manifest should show violations")
	}
}

func TestSuggestManifestEmptyAndErrors(t *testing.T) {
	out, err := SuggestManifest([]byte(`{"tools": []}`))
	if err != nil {
		t.Fatal(err)
	}
	m, err := ParseManifest(out)
	if err != nil || len(m.Agents) != 1 || len(m.Tools) != 0 {
		t.Fatalf("empty dump: %v %+v\n%s", err, m, out)
	}

	many := make([][]byte, MaxDumps+1)
	for i := range many {
		many[i] = []byte(`{"tools": []}`)
	}
	var tooMany strings.Builder
	tooMany.WriteString(`{"tools": [`)
	for i := range MaxTools + 1 {
		if i > 0 {
			tooMany.WriteString(",")
		}
		fmt.Fprintf(&tooMany, `{"name": "t%d"}`, i)
	}
	tooMany.WriteString("]}")
	cases := []struct {
		name  string
		dumps [][]byte
		want  string
	}{
		{"none", nil, "no tools/list dumps"},
		{"too many dumps", many, "dumps (max"},
		{"not json", [][]byte{[]byte("tools: []")}, "dump 1"},
		{"trailing", [][]byte{[]byte(`{"tools": []} {"tools": []}`)}, "trailing data"},
		{"error response", [][]byte{[]byte(`{"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "nope"}}`)}, "error response"},
		{"no tools", [][]byte{[]byte(`{"jsonrpc": "2.0", "id": 1, "result": {}}`)}, `no "tools" array`},
		{"tools not array", [][]byte{[]byte(`{"tools": {}}`)}, "dump 1"},
		{"too big", [][]byte{append([]byte(`{"tools": []}`), bytes.Repeat([]byte(" "), MaxDumpBytes)...)}, "larger than"},
		{"too many tools", [][]byte{[]byte(tooMany.String())}, "more than 500 tools"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := SuggestManifest(c.dumps...)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestLabelHeuristics(t *testing.T) {
	cases := []struct {
		name, desc, schema string
		reads, sinks       []string
	}{
		{"getSecret", "", "", []string{ReadSensitive}, nil},
		{"web_fetch", "Fetch a web page", "", nil, []string{SinkBoundary}},
		{"fetch_metrics", "Fetch metrics", "", nil, nil}, // fetch without a URL-ish object
		{"notify", "", `{"properties": {"webhookUrl": {}}}`, nil, []string{SinkBoundary}},
		{"bash", "", "", nil, []string{SinkExec}},
		{"query_and_email", "Query the DB and email the result", "", []string{ReadSensitive}, []string{SinkBoundary}},
		{"weird_schema", "", `[1, 2]`, nil, nil},
		{"long_desc", strings.Repeat("a ", MaxDescriptionLen) + "shell", "", nil, nil}, // beyond the scanned prefix
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := label(mcpTool{Name: c.name, Description: c.desc, InputSchema: []byte(c.schema)})
			if !slices.Equal(got.tool.Reads, c.reads) || !slices.Equal(got.tool.Sinks, c.sinks) {
				t.Fatalf("reads=%v sinks=%v notes=%v", got.tool.Reads, got.tool.Sinks, got.notes)
			}
		})
	}
	if got := tokens("readFile_fromDB-v2 HTTPPost"); !slices.Equal(got, []string{"read", "file", "from", "db", "v2", "httppost"}) {
		t.Fatalf("tokens = %q", got)
	}
}
