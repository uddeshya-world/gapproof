package models

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

func scanFixtures(t *testing.T) *Result {
	t.Helper()
	root, err := os.OpenRoot(fixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	res, err := Scan(context.Background(), root, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// M1 acceptance: every fixture produces exactly the expected rule IDs.
func TestFixtureFindings(t *testing.T) {
	want := map[string][]string{
		"pickle/benign_state_dict.pt":          nil,
		"pickle/print_payload.pt":              {RulePickleCodeExec},
		"pickle/print_payload.pkl":             {RulePickleCodeExec},
		"pickle/stack_global_os_system.pkl":    {RulePickleCodeExec},
		"pickle/unresolved_global.pkl":         {RulePickleUnresolved},
		"pickle/ext_registry.pkl":              {RulePickleUnresolved},
		"pickle/legacy_torch.pt":               nil,
		"pickle/truncated.pkl":                 {RuleParseFailed},
		"pickle/zip_bomb.pt":                   {RuleParseFailed},
		"pickle/duplicate_member.pt":           {RuleArchiveAnomaly, RulePickleCodeExec},
		"pickle/torchscript.pt":                {RuleTorchScript},
		"pickle/model.joblib":                  {RuleUnscanned},
		"safetensors/hf_ok/model.safetensors":  nil,
		"safetensors/hf_ok/config.json":        nil,
		"safetensors/truncated.safetensors":    {RuleParseFailed},
		"hf/remote_code/config.json":           {RuleRemoteCode},
		"hf/remote_code/tokenizer_config.json": {RuleChatTemplate},
		"gguf/tiny.gguf":                       nil,
		"gguf/ssti.gguf":                       {RuleChatTemplate},
		"gguf/v1.gguf":                         {RuleUnscanned},
		"onnx/escape.onnx":                     {RuleONNXExternalEscape},
		"onnx/weights.data":                    nil,
		"onnx/missing.onnx":                    {RuleONNXExternalMiss},
		"onnx/garbage.onnx":                    {RuleParseFailed},
		"numpy/object.npy":                     {RuleNumpyObject, RulePickleCodeExec},
		"keras/lambda.keras":                   {RuleKerasLambda},
		"keras/module_bypass.keras":            {RuleKerasModule},
		"keras/lambda.h5":                      {RuleKerasLambda},
	}
	res := scanFixtures(t)

	got := map[string][]string{}
	for _, f := range res.Findings {
		if !slices.Contains(got[f.Evidence.Path], f.Rule) {
			got[f.Evidence.Path] = append(got[f.Evidence.Path], f.Rule)
		}
		if f.Evidence.SHA256 == "" || f.Title == "" || f.Explanation == "" || f.Fix == "" || len(f.Controls) == 0 || f.Severity == "" {
			t.Errorf("finding %s on %s is missing evidence fields (rule 5): %+v", f.Rule, f.Evidence.Path, f)
		}
	}
	inventoried := map[string]bool{}
	for _, a := range res.Artifacts {
		inventoried[a.Path] = true
		if a.SHA256 == "" || len(a.SHA256) != 64 {
			t.Errorf("%s: bad sha256 %q", a.Path, a.SHA256)
		}
	}
	for path, rules := range want {
		g := slices.Clone(got[path])
		slices.Sort(g)
		w := slices.Clone(rules)
		slices.Sort(w)
		if !slices.Equal(g, w) {
			t.Errorf("%s: rules %v, want %v", path, g, w)
		}
		if !inventoried[path] {
			t.Errorf("%s: not in the artefact inventory", path)
		}
	}
	for path := range got {
		if _, ok := want[path]; !ok {
			t.Errorf("unexpected findings on %s: %v", path, got[path])
		}
	}
	for _, notModel := range []string{"hf/not_a_model/config.json", "other/firmware.bin", "safetensors/hf_ok/README.md"} {
		if inventoried[notModel] {
			t.Errorf("%s should not be inventoried as a model artefact", notModel)
		}
	}
}

func findArtifact(t *testing.T, res *Result, p string) Artifact {
	t.Helper()
	for _, a := range res.Artifacts {
		if a.Path == p {
			return a
		}
	}
	t.Fatalf("artifact %s not found", p)
	return Artifact{}
}

func findFinding(t *testing.T, res *Result, p, rule string) (out []string) {
	for _, f := range res.Findings {
		if f.Evidence.Path == p && f.Rule == rule {
			off := ""
			if f.Evidence.Offset != nil {
				off = "@" + strings.TrimSpace(json.Number(itoa(*f.Evidence.Offset)).String())
			}
			out = append(out, f.Evidence.Member+"|"+f.Evidence.Detail+off)
		}
	}
	return out
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

func TestFindingDetails(t *testing.T) {
	res := scanFixtures(t)
	cases := []struct {
		path, rule, want string
	}{
		{"pickle/stack_global_os_system.pkl", RulePickleCodeExec, "|STACK_GLOBAL os.system@22"},
		{"pickle/print_payload.pkl", RulePickleCodeExec, "|STACK_GLOBAL builtins.print@21"},
		{"pickle/print_payload.pt", RulePickleCodeExec, "archive/data.pkl|STACK_GLOBAL builtins.print@21"},
		{"pickle/zip_bomb.pt", RuleParseFailed, "archive/data.pkl|limit: possible zip bomb: decompression ratio above 100"},
		{"numpy/object.npy", RulePickleCodeExec, "|STACK_GLOBAL builtins.print@149"},
		{"onnx/escape.onnx", RuleONNXExternalEscape, `|tensor "w2" location=../../../etc/shadow`},
		{"keras/module_bypass.keras", RuleKerasModule, "config.json|module builtins"},
		{"gguf/ssti.gguf", RuleChatTemplate, "|tokenizer.chat_template: __init__"},
	}
	for _, c := range cases {
		got := findFinding(t, res, c.path, c.rule)
		if !slices.Contains(got, c.want) {
			t.Errorf("%s %s: got %v, want %q", c.path, c.rule, got, c.want)
		}
	}

	st := findArtifact(t, res, "safetensors/hf_ok/model.safetensors")
	if st.Tensors != 2 || st.Parameters != 6 || !slices.Equal(st.DTypes, []string{"BF16", "F32"}) || st.License != "apache-2.0" || st.Metadata["format"] != "pt" {
		t.Errorf("safetensors inventory: %+v", st)
	}
	gg := findArtifact(t, res, "gguf/tiny.gguf")
	if gg.Architecture != "llama" || gg.Name != "tiny-test" || gg.License != "apache-2.0" || gg.Tensors != 1 || gg.Parameters != 32 {
		t.Errorf("gguf inventory: %+v", gg)
	}
	if a := findArtifact(t, res, "pickle/torchscript.pt"); a.Format != "torchscript" {
		t.Errorf("torchscript format = %q", a.Format)
	}
	if a := findArtifact(t, res, "onnx/weights.data"); a.Format != "onnx-external-data" {
		t.Errorf("external data format = %q", a.Format)
	}
	if a := findArtifact(t, res, "safetensors/hf_ok/config.json"); a.Architecture != "LlamaForCausalLM" {
		t.Errorf("hf config architecture = %q", a.Architecture)
	}
	benign := findArtifact(t, res, "pickle/benign_state_dict.pt")
	if !slices.Contains(benign.Imports, "torch._utils._rebuild_tensor_v2") {
		t.Errorf("imports not inventoried: %v", benign.Imports)
	}
}

// Rule 6: same input, byte-identical output; plus a reviewed golden file.
func TestScanGoldenAndDeterministic(t *testing.T) {
	a, _ := json.MarshalIndent(scanFixtures(t), "", "  ")
	b, _ := json.MarshalIndent(scanFixtures(t), "", "  ")
	if !bytes.Equal(a, b) {
		t.Fatal("two scans of the same input differ")
	}
	const golden = "testdata/golden/scan.json"
	if *update {
		os.MkdirAll("testdata/golden", 0o755)
		os.WriteFile(golden, append(a, '\n'), 0o644)
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run with -update to create)", err)
	}
	if !bytes.Equal(append(a, '\n'), want) {
		t.Errorf("scan output differs from %s; review the diff and rerun with -update if intended", golden)
	}
}

func TestScanContextCancelled(t *testing.T) {
	root, _ := os.OpenRoot(fixtureDir)
	defer root.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Scan(ctx, root, DefaultOptions()); err == nil {
		t.Fatal("want context error")
	}
}

func TestEmptyRoot(t *testing.T) {
	root, _ := os.OpenRoot(t.TempDir())
	defer root.Close()
	res, err := Scan(context.Background(), root, DefaultOptions())
	if err != nil || res.Artifacts == nil || res.Findings == nil || len(res.Artifacts) != 0 {
		t.Fatalf("empty root: %+v %v (slices must be non-nil for stable JSON)", res, err)
	}
}
