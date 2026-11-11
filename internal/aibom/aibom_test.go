package aibom

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/uddeshya-world/gapproof/internal/evidence"
	"github.com/uddeshya-world/gapproof/internal/models"
)

var update = flag.Bool("update", false, "rewrite golden files")

// sampleScan is the models package's golden scan of its 30 fixtures,
// vendored so this golden doesn't move when those fixtures do.
func sampleScan(t *testing.T) *models.Result {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/samples/models-scan.json")
	if err != nil {
		t.Fatal(err)
	}
	var r models.Result
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return &r
}

func sampleInput(t *testing.T) Input {
	return Input{
		ToolVersion: "v0.2.0-test",
		Subject: Subject{
			Name:         "demo/fixed-rag:1.0",
			ConfigDigest: "sha256:" + strings.Repeat("ab", 32),
			ImageID:      "sha256:" + strings.Repeat("cd", 32),
		},
		Models: sampleScan(t),
	}
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (run with -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from golden (review, then -update)", name)
	}
}

func build(t *testing.T, in Input) []byte {
	t.Helper()
	b, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestGolden(t *testing.T) {
	in := sampleInput(t)
	raw := build(t, in)
	golden(t, "aibom.cdx.json", raw)
	if again := build(t, sampleInput(t)); !bytes.Equal(raw, again) {
		t.Error("not deterministic")
	}

	var b BOM
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(b.SerialNumber) {
		t.Errorf("serialNumber %q", b.SerialNumber)
	}
	if bytes.Contains(raw, []byte(`"timestamp"`)) {
		t.Error("BOM must not carry a timestamp")
	}
	types := map[string]int{}
	for _, c := range b.Components {
		types[c.Type]++
	}
	if types["machine-learning-model"] == 0 || types["data"] == 0 || types["file"] == 0 {
		t.Errorf("component types = %v", types)
	}
	if !AllModelsHashed(&b, in.Models.Artifacts) {
		t.Error("AllModelsHashed = false for a complete BOM")
	}

	// A content change changes the serial number.
	in.Models.Artifacts[0].SHA256 = strings.Repeat("0", 64)
	var b2 BOM
	json.Unmarshal(build(t, in), &b2)
	if b2.SerialNumber == b.SerialNumber {
		t.Error("serialNumber did not change with content")
	}
}

func TestComponentDetails(t *testing.T) {
	res := &models.Result{
		Artifacts: []models.Artifact{
			{Path: "m/b.safetensors", Format: "safetensors", Size: 10, SHA256: strings.Repeat("1", 64), License: "apache-2.0", Tensors: 2, Parameters: 64, DTypes: []string{"F16", "F32"}},
			{Path: "m/a.pt", Format: "pickle", Size: 5, SHA256: strings.Repeat("2", 64), License: "llama3", Imports: []string{"torch._utils._rebuild_tensor_v2"}},
			{Path: "m/tokenizer.json", Format: "hf-tokenizer", Size: 3, SHA256: strings.Repeat("3", 64)},
			{Path: "m/c.joblib", Format: "joblib-compressed", Size: 3, SHA256: strings.Repeat("4", 64)},
		},
		Findings: []evidence.Finding{
			{Rule: models.RuleParseFailed, Evidence: evidence.Evidence{Path: "m/a.pt"}},
			{Rule: models.RuleUnscanned, Evidence: evidence.Evidence{Path: "m/a.pt"}},
			{Rule: models.RuleUnscanned, Evidence: evidence.Evidence{Path: "m/c.joblib"}},
		},
	}
	b, err := Build(Input{Models: res})
	if err != nil {
		t.Fatal(err)
	}
	if b.Metadata.Component.Type != "file" || b.Metadata.Component.Name != "scanned-artifact" || b.Metadata.Component.Hashes != nil {
		t.Errorf("rootfs subject = %+v", b.Metadata.Component)
	}
	got := map[string]Component{}
	for _, c := range b.Components {
		got[c.BOMRef] = c
	}
	prop := func(c Component, n string) string {
		for _, p := range c.Properties {
			if p.Name == n {
				return p.Value
			}
		}
		return ""
	}
	st := got["file:m/b.safetensors"]
	if st.Licenses[0].License.ID != "Apache-2.0" || st.Type != "machine-learning-model" ||
		prop(st, "gapproof:parse_status") != "parsed" || prop(st, "gapproof:dtypes") != "F16,F32" || prop(st, "gapproof:parameters") != "64" {
		t.Errorf("safetensors component = %+v", st)
	}
	pk := got["file:m/a.pt"]
	if pk.Licenses[0].License.Name != "llama3" || prop(pk, "gapproof:parse_status") != "parse-failed" || prop(pk, "gapproof:pickle_imports") == "" {
		t.Errorf("pickle component = %+v", pk)
	}
	if c := got["file:m/c.joblib"]; prop(c, "gapproof:parse_status") != "unscanned-format" {
		t.Errorf("joblib = %+v", c)
	}
	if c := got["file:m/tokenizer.json"]; c.Type != "file" || c.Name != "tokenizer.json" || c.Licenses != nil {
		t.Errorf("tokenizer = %+v", c)
	}
	if b.Components[0].BOMRef != "file:m/a.pt" {
		t.Error("components not in path order")
	}
	if len(b.Dependencies) != 1 || len(b.Dependencies[0].DependsOn) != 4 {
		t.Errorf("dependencies = %+v", b.Dependencies)
	}
	for _, c := range b.Components {
		for i := 1; i < len(c.Properties); i++ {
			if c.Properties[i-1].Name > c.Properties[i].Name {
				t.Errorf("%s: properties not sorted", c.BOMRef)
			}
		}
	}
}

func TestBuildErrors(t *testing.T) {
	if _, err := Build(Input{}); err == nil {
		t.Error("nil models accepted")
	}
	ok := &models.Result{}
	for _, d := range []string{"md5:abc", "sha256:XYZ"} {
		if _, err := Build(Input{Models: ok, Subject: Subject{ConfigDigest: d}}); err == nil {
			t.Errorf("digest %q accepted", d)
		}
	}
	bad := &models.Result{Artifacts: []models.Artifact{{Path: "x.safetensors", Format: "safetensors"}}}
	if _, err := Build(Input{Models: bad}); err == nil {
		t.Error("unhashed artefact accepted")
	}
	b, err := Build(Input{Models: ok})
	if err != nil || len(b.Components) != 0 {
		t.Fatalf("empty scan: %+v %v", b, err)
	}
	raw, _ := Marshal(b)
	if !bytes.Contains(raw, []byte(`"components": []`)) {
		t.Errorf("empty components should be an empty array:\n%s", raw)
	}
}

func TestAllModelsHashed(t *testing.T) {
	arts := []models.Artifact{
		{Path: "a.gguf", Format: "gguf", SHA256: strings.Repeat("a", 64)},
		{Path: "b.onnx", Format: "onnx", SHA256: strings.Repeat("b", 64)},
	}
	b, err := Build(Input{Models: &models.Result{Artifacts: arts}})
	if err != nil {
		t.Fatal(err)
	}
	if !AllModelsHashed(b, arts) || !AllModelsHashed(b, nil) {
		t.Error("complete BOM reported unhashed")
	}
	if AllModelsHashed(nil, arts) {
		t.Error("nil BOM reported hashed")
	}
	extra := append(arts, models.Artifact{Path: "c.pt", SHA256: strings.Repeat("c", 64)})
	if AllModelsHashed(b, extra) {
		t.Error("artefact missing from BOM reported hashed")
	}
	changed := []models.Artifact{arts[0], {Path: "b.onnx", SHA256: strings.Repeat("f", 64)}}
	if AllModelsHashed(b, changed) {
		t.Error("hash mismatch reported hashed")
	}
	b.Components[0].Hashes = nil
	if AllModelsHashed(b, arts) {
		t.Error("component without hash reported hashed")
	}
}

func TestSchemaValid(t *testing.T) {
	raw := build(t, sampleInput(t))
	rootfs := build(t, Input{ToolVersion: "v0", Models: sampleScan(t)})
	validateInContainer(t, "cyclonedx", map[string][]byte{"aibom.cdx.json": raw, "aibom-rootfs.cdx.json": rootfs})
}
