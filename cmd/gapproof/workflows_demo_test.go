package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// demo/tools/check_demo_run.sh is the pass/fail logic of the demo workflow's
// `repeat` loop: it must flag a wrong level, different finding rules and
// non-identical evidence.json, and pass an identical run.
func TestCheckDemoRunScript(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not installed")
	}
	script, _ := filepath.Abs(filepath.Join("..", "..", "demo", "tools", "check_demo_run.sh"))
	write := func(dir, app, level string, rules ...string) {
		t.Helper()
		d := filepath.Join(dir, app)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		var fs []string
		for _, r := range rules {
			fs = append(fs, `{"rule":"`+r+`"}`)
		}
		ev := `{"findings":[` + strings.Join(fs, ",") + `]}`
		sum := `{"agr":{"level":"` + level + `","blocking":[]}}`
		if err := os.WriteFile(filepath.Join(d, "evidence.json"), []byte(ev), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "summary.json"), []byte(sum), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	both := func(dir, fixedLevel string, fixedRules ...string) {
		write(dir, "leaky-rag", "AGR-1", "PH-X", "EGRESS-ATTEMPT")
		write(dir, "fixed-rag", fixedLevel, fixedRules...)
	}
	check := func(ev, base string) (int, string) {
		out, err := exec.Command("sh", script, ev, base).CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return code, string(out)
	}
	tmp := t.TempDir()
	base := filepath.Join(tmp, "base")
	run1 := filepath.Join(tmp, "run1")
	both(run1, "AGR-4", "AGENT-NEARMISS-analyst")
	if code, out := check(run1, base); code != 0 {
		t.Fatalf("baseline run: exit %d\n%s", code, out)
	}
	run2 := filepath.Join(tmp, "run2")
	both(run2, "AGR-4", "AGENT-NEARMISS-analyst")
	if code, out := check(run2, base); code != 0 {
		t.Errorf("identical run: exit %d\n%s", code, out)
	}
	for name, tc := range map[string]struct {
		level string
		rules []string
		want  string
	}{
		"level":    {"AGR-1", []string{"AGENT-NEARMISS-analyst"}, "level AGR-1, want AGR-4"},
		"rules":    {"AGR-4", []string{"AGENT-NEARMISS-analyst", "PH-NEW"}, "finding rules differ"},
		"evidence": {"AGR-4", []string{"AGENT-NEARMISS-analyst", "AGENT-NEARMISS-analyst"}, "sha256"},
	} {
		d := filepath.Join(tmp, "dev-"+name)
		both(d, tc.level, tc.rules...)
		code, out := check(d, base)
		if code != 1 || !strings.Contains(out, tc.want) {
			t.Errorf("%s deviation: exit %d, want 1 with %q\n%s", name, code, tc.want, out)
		}
	}
}
