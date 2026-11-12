package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

// TestDemoApps is the M4 demo acceptance test (spec §4). Run it with
// `make demo demo-e2e`: `make demo` builds the demo images and scans them into
// evidence/{leaky,fixed}-rag; this test checks those results, then scans each
// image once more and requires a byte-identical evidence.json (rule 6).
// It needs the pinned bin/gapproof, the loaded harness image and both demo
// images, so it only runs when GAPPROOF_DEMO_E2E=1.
func TestDemoApps(t *testing.T) {
	if os.Getenv("GAPPROOF_DEMO_E2E") != "1" {
		t.Skip("set GAPPROOF_DEMO_E2E=1 (make demo-e2e) to run the demo scans")
	}
	root, _ := filepath.Abs("../..")
	bin := filepath.Join(root, "bin", "gapproof")
	observe := envOr("DEMO_OBSERVE", "3m")
	arch := envOr("DEMO_ARCH", "arm64")
	tag := envOr("DEMO_TAG", "dev")

	cases := []struct {
		app   string
		level string
		extra []string
		// Every open-or-waived finding rule, sorted and deduplicated.
		rules []string
		// Rules that must be waived (not open).
		waived []string
	}{
		{
			app:   "leaky-rag",
			level: "AGR-1",
			rules: []string{
				"AGENT-INV01-analyst",
				"CRYPTO-UNKNOWN-MODULE",
				"CRYPTO-UNVALIDATED-MODULE",
				"CRYPTO-WEAK-HASH",
				"EGRESS-ATTEMPT",
				"MODEL-NUMPY-OBJECT-ARRAY",
				"MODEL-PICKLE-CODE-EXEC",
				"MODEL-PICKLE-UNKNOWN-IMPORT",
				"PH-CHROMA-TELEMETRY",
				"PH-HF-HUB-ONLINE",
				"PH-HF-TELEMETRY",
				"PH-OPENAI-SDK-HOSTED",
				"PH-OTLP-PUBLIC-ENDPOINT",
				"PH-SENTRY-DSN-ENV",
				"PH-SENTRY-INIT",
				"PH-TELEMETRY-SDK",
			},
		},
		{
			app:   "fixed-rag",
			level: "AGR-4",
			extra: []string{
				"--scope", filepath.Join(root, "demo/fixed-rag/gapproof.scope.yaml"),
				"--waivers", filepath.Join(root, "demo/fixed-rag/gapproof.waivers."+arch+".yaml"),
			},
			rules:  []string{"AGENT-NEARMISS-analyst", "CRYPTO-UNKNOWN-MODULE", "CRYPTO-UNVALIDATED-MODULE", "PH-TELEMETRY-SDK"},
			waived: []string{"CRYPTO-UNKNOWN-MODULE", "CRYPTO-UNVALIDATED-MODULE"},
		},
	}
	for _, c := range cases {
		t.Run(c.app, func(t *testing.T) {
			first := filepath.Join(root, "evidence", c.app, "evidence.json")
			a, err := os.ReadFile(first)
			if err != nil {
				t.Fatalf("%v (run `make demo` first)", err)
			}
			ev := decodeEvidence(t, a)
			if ev.AGR.Level != c.level {
				t.Errorf("level = %s, want %s (blocking: %s)", ev.AGR.Level, c.level, ev.AGR.Blocking)
			}
			if !ev.Egress.WorkloadPassed {
				t.Error("workload did not pass with egress blocked")
			}
			var rules []string
			for _, f := range ev.Findings {
				rules = append(rules, f.Rule)
				if slices.Contains(c.waived, f.Rule) && f.Status != "waived" {
					t.Errorf("%s %s (%s) is %s, want waived", f.ID, f.Rule, f.Evidence.Path, f.Status)
				}
			}
			slices.Sort(rules)
			rules = slices.Compact(rules)
			if !slices.Equal(rules, c.rules) {
				t.Errorf("finding rules:\n got  %q\n want %q", rules, c.rules)
			}

			// Determinism: scan the same image again with the same inputs.
			out := filepath.Join(t.TempDir(), "ev")
			args := append([]string{"scan", "--image", "gapproof-demo/" + c.app + ":" + tag,
				"--observe", observe,
				"--workload", filepath.Join(root, "demo", c.app, "workload.sh"),
				"--agents", filepath.Join(root, "demo", c.app, "agents.yaml"),
				"--out", out}, c.extra...)
			cmd := exec.Command(bin, args...)
			cmd.Dir = root
			if b, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("rescan: %v\n%s", err, b)
			}
			b, err := os.ReadFile(filepath.Join(out, "evidence.json"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(a, b) {
				t.Errorf("evidence.json differs between two runs (%d vs %d bytes); diff %s %s",
					len(a), len(b), first, filepath.Join(out, "evidence.json"))
				_ = os.WriteFile(first+".rerun", b, 0o644)
			}
		})
	}
}

type demoEvidence struct {
	AGR struct {
		Level    string          `json:"level"`
		Blocking json.RawMessage `json:"blocking"`
	} `json:"agr"`
	Egress struct {
		WorkloadPassed bool `json:"workload_passed"`
	} `json:"egress"`
	Findings []struct {
		ID       string `json:"id"`
		Rule     string `json:"rule"`
		Status   string `json:"status"`
		Evidence struct {
			Path string `json:"path"`
		} `json:"evidence"`
	} `json:"findings"`
}

func decodeEvidence(t *testing.T, b []byte) demoEvidence {
	t.Helper()
	var ev demoEvidence
	if err := json.Unmarshal(b, &ev); err != nil {
		t.Fatal(err)
	}
	return ev
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
