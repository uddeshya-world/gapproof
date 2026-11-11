package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uddeshya-world/gapproof/internal/evidence"
)

// TestScanRootfsPipeline runs the whole static pipeline on a fixture rootfs
// (no container engine needed), then replay and report on its output.
func TestScanRootfsPipeline(t *testing.T) {
	rootfs := "../../rules/testdata/PH-CHROMA-TELEMETRY/positive/rootfs"
	agentsYAML := "../../internal/agents/testdata/leaky.yaml"
	scan := func(out string) (int, string) {
		var so, se bytes.Buffer
		code := run([]string{"scan", "--rootfs", rootfs, "--skip", "egress", "--agents", agentsYAML, "--out", out}, &so, &se)
		return code, so.String() + se.String()
	}

	out1 := filepath.Join(t.TempDir(), "ev")
	code, txt := scan(out1)
	if code != exitOK {
		t.Fatalf("scan exit %d:\n%s", code, txt)
	}
	for _, want := range []string{"unassessed", "PH-", "AG-", "evidence: " + out1} {
		if !strings.Contains(txt, want) {
			t.Errorf("scan output missing %q:\n%s", want, txt)
		}
	}
	for _, f := range []string{"evidence.json", "summary.json", "aibom.cdx.json", "oscal-ar.json", "report.html", "report.md", "MANIFEST.sha256"} {
		if _, err := os.Stat(filepath.Join(out1, f)); err != nil {
			t.Errorf("missing %s: %v", f, err)
		}
	}
	b, err := evidence.Load(out1)
	if err != nil {
		t.Fatal(err)
	}
	if b.AGR.Level != evidence.LevelUnassessed {
		t.Errorf("rootfs scan level %s, want unassessed (egress can't be observed)", b.AGR.Level)
	}
	if b.ModuleState("agents") != evidence.ModuleRan || b.Agents == nil || b.Agents.Violations == 0 {
		t.Errorf("agents module didn't report the leaky manifest's INV-01 violations: %+v", b.Agents)
	}

	// Determinism (rule 6): a second run gives a byte-identical evidence.json.
	out2 := filepath.Join(t.TempDir(), "ev")
	if code, txt := scan(out2); code != exitOK {
		t.Fatalf("second scan exit %d:\n%s", code, txt)
	}
	e1, _ := os.ReadFile(filepath.Join(out1, "evidence.json"))
	e2, _ := os.ReadFile(filepath.Join(out2, "evidence.json"))
	if !bytes.Equal(e1, e2) {
		t.Error("evidence.json differs between two runs on the same input")
	}

	// --out must be new or empty.
	if code, txt := scan(out1); code != exitUsage || !strings.Contains(txt, "not empty") {
		t.Errorf("reusing --out: exit %d, %s", code, txt)
	}

	// --min-agr gate.
	var so, se bytes.Buffer
	if code := run([]string{"scan", "--rootfs", rootfs, "--skip", "egress", "--min-agr", "1", "--out", filepath.Join(t.TempDir(), "g")}, &so, &se); code != exitBelowThreshold {
		t.Errorf("--min-agr 1 on an unassessed scan: exit %d, want 1\n%s", code, se.String())
	}

	// Replay prints the same summary, headed by the run id.
	so.Reset()
	se.Reset()
	if code := run([]string{"scan", "--replay", out1, "--replay-speed", "1000"}, &so, &se); code != exitOK {
		t.Fatalf("replay exit %d: %s", code, se.String())
	}
	if first, _, _ := strings.Cut(so.String(), "\n"); !strings.HasPrefix(first, "replay of run "+b.Run.ID) {
		t.Errorf("replay first line = %q", first)
	}
	if !strings.Contains(txt, strings.Join(renderTTY(b, nil, false), "\n")) {
		t.Error("live scan output doesn't contain the rendered summary that replay prints")
	}

	// report regenerates both files.
	os.Remove(filepath.Join(out1, "report.md"))
	so.Reset()
	if code := run([]string{"report", "--in", out1, "--format", "md"}, &so, &se); code != exitOK {
		t.Fatalf("report exit %d: %s", code, se.String())
	}
	if _, err := os.Stat(filepath.Join(out1, "report.md")); err != nil {
		t.Error("report --format md didn't write report.md")
	}
}

func TestAgentsImportMCP(t *testing.T) {
	var so, se bytes.Buffer
	if code := run([]string{"agents", "import-mcp", "../../internal/agents/testdata/mcp-files.json"}, &so, &se); code != exitOK {
		t.Fatalf("exit %d: %s", code, se.String())
	}
	if !strings.Contains(so.String(), "agents:") {
		t.Errorf("no manifest printed:\n%s", so.String())
	}
	if code := run([]string{"agents", "import-mcp"}, &so, &se); code != exitUsage {
		t.Errorf("no args: exit %d, want 2", code)
	}
}
