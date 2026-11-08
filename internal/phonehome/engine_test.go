package phonehome

import (
	"context"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/uddeshya-world/gapproof/internal/inventory"
)

const goodRule = `id: PH-TEST
title: t
severity: high
confidence: high
explanation: e
match:
  python_package: x
fix: f
controls: [CM-7]
source: [https://example.org/doc]
`

func TestLoadValidation(t *testing.T) {
	tests := []struct {
		name, file, body, want string
	}{
		{"ok", "PH-TEST.yaml", goodRule, ""},
		{"unknown field", "PH-TEST.yaml", goodRule + "colour: red\n", "field colour not found"},
		{"bad yaml", "PH-TEST.yaml", "id: [", "PH-TEST.yaml"},
		{"bad id", "PH-TEST.yaml", strings.Replace(goodRule, "PH-TEST", "telemetry", 1), "must look like PH-NAME"},
		{"file name", "OTHER.yaml", goodRule, "must live in PH-TEST.yaml"},
		{"no source", "PH-TEST.yaml", strings.Replace(goodRule, "source: [https://example.org/doc]\n", "", 1), "must cite"},
		{"http source", "PH-TEST.yaml", strings.Replace(goodRule, "https://", "http://", 1), "https URL"},
		{"bad severity", "PH-TEST.yaml", strings.Replace(goodRule, "severity: high", "severity: urgent", 1), "bad severity"},
		{"bad confidence", "PH-TEST.yaml", strings.Replace(goodRule, "confidence: high", "confidence: maybe", 1), "confidence must be"},
		{"no controls", "PH-TEST.yaml", strings.Replace(goodRule, "controls: [CM-7]\n", "", 1), "control mapping"},
		{"no fix", "PH-TEST.yaml", strings.Replace(goodRule, "fix: f\n", "", 1), "required"},
		{"no condition", "PH-TEST.yaml", strings.Replace(goodRule, "  python_package: x\n", "  unless_env: {A: [\"1\"]}\n", 1), "at least one of"},
		{"bad regex", "PH-TEST.yaml", strings.Replace(goodRule, "  python_package: x\n", "  source_regex: '('\n", 1), "source_regex"},
		{"bad unless_file", "PH-TEST.yaml", strings.Replace(goodRule, "  python_package: x\n", "  python_package: x\n  unless_file: {path_regex: '(', content_regex: a}\n", 1), "path_regex"},
		{"empty env values", "PH-TEST.yaml", strings.Replace(goodRule, "  python_package: x\n", "  env: {A: []}\n", 1), "at least one value"},
		{"empty unless values", "PH-TEST.yaml", strings.Replace(goodRule, "  python_package: x\n", "  python_package: x\n  unless_env: {A: []}\n", 1), "at least one value"},
		{"package as map", "PH-TEST.yaml", strings.Replace(goodRule, "python_package: x", "python_package: {a: b}", 1), "string or a list"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(fstest.MapFS{tc.file: {Data: []byte(tc.body)}})
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
	_, err := Load(fstest.MapFS{"PH-TEST.yaml": {Data: []byte(goodRule)}, "sub/PH-TEST.yaml": {Data: []byte(goodRule)}})
	if err != nil {
		t.Fatalf("only top-level files are rules: %v", err)
	}
}

func TestDuplicateIDs(t *testing.T) {
	_, err := Load(fstest.MapFS{"PH-TEST.yaml": {Data: []byte(goodRule)}, "PH-TEST2.yaml": {Data: []byte(goodRule)}})
	if err == nil {
		t.Fatal("want an error for a rule in the wrong file")
	}
}

func TestValueMatches(t *testing.T) {
	tests := []struct {
		v    string
		set  bool
		pats []string
		want bool
	}{
		{"1", true, []string{"1", "true"}, true},
		{" TRUE ", true, []string{"true"}, true},
		{"0", true, []string{"1"}, false},
		{"", false, []string{"*"}, false},
		{"", true, []string{"*"}, false},
		{"x", true, []string{"*"}, true},
		{"False", true, []string{"!true"}, true},
		{"True", true, []string{"!true"}, false},
		{"", false, []string{"!true"}, false},
	}
	for _, tc := range tests {
		if got := valueMatches(tc.v, tc.set, tc.pats); got != tc.want {
			t.Errorf("valueMatches(%q, %v, %v) = %v", tc.v, tc.set, tc.pats, got)
		}
	}
}

func TestPublicHost(t *testing.T) {
	tests := map[string]bool{
		"https://key@o1.ingest.sentry.io/2":                true,
		"otlp.example.com:4317":                            true,
		"http://8.8.8.8:4318":                              true,
		"http://[2001:4860::1]:80":                         true,
		"http://otel-collector:4317":                       false,
		"http://localhost:4318":                            false,
		"http://127.0.0.1":                                 false,
		"10.1.2.3:4317":                                    false,
		"http://192.168.1.10":                              false,
		"http://100.64.0.5":                                false,
		"http://[fd00::1]":                                 false,
		"http://sentry.internal:9000":                      false,
		"http://otel.observability.svc.cluster.local:4317": false,
		"http://printer.local":                             false,
		"":                                                 false,
		"http://[bad":                                      true, // unparseable: fail closed
	}
	for in, want := range tests {
		if _, got := PublicHost(in); got != want {
			t.Errorf("PublicHost(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestEnvOnlyEvidenceAnchorsToConfigDigest(t *testing.T) {
	rs, _ := Builtin()
	root, _ := os.OpenRoot(t.TempDir())
	defer root.Close()
	in := Input{Root: root, Inv: &inventory.Inventory{}, Env: []string{"LANGSMITH_TRACING=true"}, ConfigDigest: "sha256:abc"}
	fs, err := Evaluate(context.Background(), rs, in)
	if err != nil || len(fs) != 1 {
		t.Fatalf("want 1 finding, got %v %v", fs, err)
	}
	if fs[0].Evidence.Path != ImageConfigPath || fs[0].Evidence.SHA256 != "abc" || !strings.Contains(fs[0].Evidence.Detail, "LANGSMITH_TRACING=true") {
		t.Errorf("evidence: %+v", fs[0].Evidence)
	}
}

func TestLoadFixtureErrors(t *testing.T) {
	if _, _, err := LoadFixture(context.Background(), t.TempDir()); err == nil || !strings.Contains(err.Error(), "rootfs/") {
		t.Fatalf("got %v", err)
	}
	if ByID(nil, "PH-X") != nil {
		t.Fatal("ByID on empty list")
	}
}

func TestEvaluateCancelled(t *testing.T) {
	rs, _ := Builtin()
	root, _ := os.OpenRoot(t.TempDir())
	defer root.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Evaluate(ctx, rs, Input{Root: root, Inv: &inventory.Inventory{}}); err == nil {
		t.Fatal("want context error")
	}
}
