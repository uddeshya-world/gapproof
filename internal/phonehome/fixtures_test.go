package phonehome

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Every rule ships with a positive and a negative fixture under
// rules/testdata/<ID>/ and a golden expected.json for the positive case.
// The fixtures are generated from this table so they stay reviewable:
//
//	go test ./internal/phonehome -run TestRuleFixtures -update
var update = flag.Bool("update", false, "regenerate rule fixtures and golden files")

const fixtureRoot = "../../rules/testdata"

type fixture struct {
	env   []string
	files map[string]string
}

const site = "usr/local/lib/python3.12/site-packages/"

func dist(name, version string) (string, string) {
	return site + strings.ReplaceAll(name, "-", "_") + "-" + version + ".dist-info/METADATA",
		"Metadata-Version: 2.1\nName: " + name + "\nVersion: " + version + "\n\nLong description, ignored.\nName: not-this\n"
}

func files(kv ...string) map[string]string {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

func withDist(name, version string, extra ...string) map[string]string {
	p, b := dist(name, version)
	return files(append([]string{p, b}, extra...)...)
}

var basePath = "PATH=/usr/local/bin:/usr/bin"

type ruleFixture struct{ pos, neg fixture }

// extraNegatives are further negative cases, written to negative-2, -3, ...
var extraNegatives = map[string][]fixture{
	// MLflow telemetry arrived in 3.2.0; DO_NOT_TRACK is an independent opt-out; mlflow-skinny counts.
	"PH-MLFLOW-TELEMETRY": {
		{nil, withDist("mlflow", "3.1.4")},
		{[]string{"DO_NOT_TRACK=true"}, withDist("mlflow-skinny", "3.18.0")},
	},
	// Opt-out by the documented file, and by DO_NOT_TRACK=1, as well as by VLLM_NO_USAGE_STATS.
	"PH-VLLM-USAGE-STATS": {
		{nil, withDist("vllm", "0.32.0", "root/.config/vllm/do_not_track", "")},
		{[]string{"DO_NOT_TRACK=1"}, withDist("vllm", "0.32.0")},
	},
	"PH-LANGSMITH-TRACING": {
		// The SDK compares to "true" only, so "1" does not enable tracing.
		{[]string{"LANGSMITH_TRACING=1"}, files("app/main.py", "print('rag')\n")},
	},
	// D-036: the version bound and the env opt-out are independent negatives.
	"PH-CHROMA-TELEMETRY": {
		{[]string{"ANONYMIZED_TELEMETRY=False"}, withDist("chromadb", "1.5.2")},
		{nil, withDist("chromadb", "2.0.0")},
	},
}

var ruleFixtures = map[string]ruleFixture{
	"PH-HF-HUB-ONLINE": {
		fixture{[]string{basePath}, withDist("huggingface_hub", "0.26.2")},
		fixture{[]string{basePath, "HF_HUB_OFFLINE=1"}, withDist("huggingface_hub", "0.26.2")},
	},
	"PH-HF-TELEMETRY": {
		fixture{[]string{basePath}, withDist("huggingface_hub", "0.26.2")},
		fixture{[]string{"HF_HUB_DISABLE_TELEMETRY=1"}, withDist("huggingface_hub", "0.26.2")},
	},
	"PH-GRADIO-ANALYTICS": {
		fixture{[]string{"GRADIO_ANALYTICS_ENABLED=True"}, withDist("gradio", "5.4.0")},
		fixture{[]string{"GRADIO_ANALYTICS_ENABLED=False"}, withDist("gradio", "5.4.0")},
	},
	"PH-STREAMLIT-USAGE-STATS": {
		fixture{nil, withDist("streamlit", "1.40.0", "app/.streamlit/config.toml", "[server]\nport = 8501\n")},
		fixture{nil, withDist("streamlit", "1.40.0", "app/.streamlit/config.toml", "[browser]\ngatherUsageStats = false\n")},
	},
	"PH-CHROMA-TELEMETRY": {
		fixture{nil, withDist("chromadb", "1.5.2")},
		// 1.5.4 dropped posthog; its client is a no-op (D-036).
		fixture{nil, withDist("chromadb", "1.5.4")},
	},
	"PH-UNSTRUCTURED-ANALYTICS": {
		fixture{nil, withDist("unstructured", "0.16.5")},
		fixture{[]string{"SCARF_NO_ANALYTICS=true"}, withDist("unstructured", "0.16.5")},
	},
	"PH-LANGSMITH-TRACING": {
		fixture{[]string{"LANGCHAIN_TRACING_V2=true"}, files("app/main.py", "print('rag')\n")},
		fixture{[]string{"LANGSMITH_TRACING=false"}, files("app/main.py", "print('rag')\n")},
	},
	"PH-WANDB-ONLINE": {
		fixture{nil, withDist("wandb", "0.18.7")},
		fixture{[]string{"WANDB_MODE=disabled"}, withDist("wandb", "0.18.7")},
	},
	"PH-MLFLOW-TELEMETRY": {
		fixture{nil, withDist("mlflow", "3.18.0")},
		fixture{[]string{"MLFLOW_DISABLE_TELEMETRY=true"}, withDist("mlflow", "3.18.0")},
	},
	"PH-MLFLOW-REMOTE-TRACKING": {
		fixture{[]string{"MLFLOW_TRACKING_URI=https://mlflow.vendor.example.com"}, files("app/main.py", "")},
		fixture{[]string{"MLFLOW_TRACKING_URI=http://mlflow:5000"}, files("app/main.py", "")},
	},
	"PH-VLLM-USAGE-STATS": {
		fixture{nil, withDist("vllm", "0.32.0")},
		fixture{[]string{"VLLM_NO_USAGE_STATS=1"}, withDist("vllm", "0.32.0")},
	},
	"PH-SENTRY-INIT": {
		fixture{nil, files("app/main.py", "import sentry_sdk\n\nsentry_sdk.init(dsn=\"https://key@o1.ingest.sentry.io/1\")\n")},
		// Library code may call init; only the application's own code counts.
		fixture{nil, files("app/main.py", "print('no sentry here')\n", site+"sentry_sdk/client.py", "sentry_sdk.init(\n")},
	},
	"PH-SENTRY-DSN-ENV": {
		fixture{[]string{"SENTRY_DSN=https://key@o1.ingest.sentry.io/2"}, files("app/main.py", "")},
		fixture{[]string{"SENTRY_DSN=http://key@sentry.internal:9000/2"}, files("app/main.py", "")},
	},
	"PH-TELEMETRY-SDK": {
		fixture{nil, withDist("posthog", "3.7.0")},
		fixture{nil, withDist("requests", "2.32.3")},
	},
	"PH-OTLP-PUBLIC-ENDPOINT": {
		fixture{[]string{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://otlp.observability-vendor.example.com:4318/v1/traces"}, files("app/main.py", "")},
		fixture{[]string{"OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317"}, files("app/main.py", "")},
	},
	"PH-OPENAI-SDK-HOSTED": {
		fixture{nil, withDist("openai", "1.54.4")},
		fixture{[]string{"OPENAI_BASE_URL=http://vllm:8000/v1"}, withDist("openai", "1.54.4")},
	},
	"PH-ANTHROPIC-SDK-HOSTED": {
		fixture{nil, withDist("anthropic", "0.40.0")},
		fixture{[]string{"ANTHROPIC_BASE_URL=http://llm-gateway.internal"}, withDist("anthropic", "0.40.0")},
	},
	"PH-HOSTED-LLM-SDK": {
		fixture{nil, withDist("cohere", "5.11.4")},
		fixture{nil, withDist("torch", "2.5.1")},
	},
	"PH-TRUST-REMOTE-CODE": {
		fixture{nil, files("app/load.py", "from transformers import AutoModel\nm = AutoModel.from_pretrained(p, trust_remote_code=True)\n")},
		fixture{nil, files("app/load.py", "from transformers import AutoModel\nm = AutoModel.from_pretrained(p, trust_remote_code=False)\n")},
	},
}

func writeFixture(t *testing.T, dir string, f fixture) {
	t.Helper()
	for p, body := range f.files {
		full := filepath.Join(dir, "rootfs", filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	os.MkdirAll(filepath.Join(dir, "rootfs"), 0o755)
	if len(f.env) > 0 {
		os.WriteFile(filepath.Join(dir, "env.txt"), []byte("# image environment for this fixture\n"+strings.Join(f.env, "\n")+"\n"), 0o644)
	}
}

func evalFixture(t *testing.T, r *Rule, dir string) []byte {
	t.Helper()
	in, closeFn, err := LoadFixture(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFn()
	fs, err := Evaluate(context.Background(), []*Rule{r}, in)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.MarshalIndent(fs, "", "  ")
	return append(b, '\n')
}

func TestRuleFixtures(t *testing.T) {
	rs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		os.RemoveAll(fixtureRoot)
		for id, fx := range ruleFixtures {
			writeFixture(t, filepath.Join(fixtureRoot, id, "positive"), fx.pos)
			writeFixture(t, filepath.Join(fixtureRoot, id, "negative"), fx.neg)
			for i, n := range extraNegatives[id] {
				writeFixture(t, filepath.Join(fixtureRoot, id, fmt.Sprintf("negative-%d", i+2)), n)
			}
		}
	}

	var ids []string
	for _, r := range rs {
		ids = append(ids, r.ID)
		t.Run(r.ID, func(t *testing.T) {
			if _, ok := ruleFixtures[r.ID]; !ok {
				t.Fatalf("rule %s has no fixtures: add positive and negative cases to ruleFixtures", r.ID)
			}
			posDir := filepath.Join(fixtureRoot, r.ID, "positive")
			pos := evalFixture(t, r, posDir)
			if !bytes.Contains(pos, []byte(`"rule": "`+r.ID+`"`)) {
				t.Errorf("positive fixture produced no %s finding:\n%s", r.ID, pos)
			}
			golden := filepath.Join(posDir, "expected.json")
			if *update {
				os.WriteFile(golden, pos, 0o644)
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%v (run with -update)", err)
			}
			if !bytes.Equal(pos, want) {
				t.Errorf("output differs from %s; review and rerun with -update if intended\n%s", golden, pos)
			}
			if neg := evalFixture(t, r, filepath.Join(fixtureRoot, r.ID, "negative")); string(neg) != "[]\n" {
				t.Errorf("negative fixture matched:\n%s", neg)
			}
			for i := range extraNegatives[r.ID] {
				d := filepath.Join(fixtureRoot, r.ID, fmt.Sprintf("negative-%d", i+2))
				if neg := evalFixture(t, r, d); string(neg) != "[]\n" {
					t.Errorf("%s matched:\n%s", d, neg)
				}
			}
		})
	}
	for id := range ruleFixtures {
		if !slices.Contains(ids, id) {
			t.Errorf("fixtures for %s, but no such rule", id)
		}
	}
	entries, _ := os.ReadDir(fixtureRoot)
	for _, e := range entries {
		if !slices.Contains(ids, e.Name()) {
			t.Errorf("orphan fixture directory %s", e.Name())
		}
	}
}
