package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uddeshya-world/gapproof/internal/evidence"
	"github.com/uddeshya-world/gapproof/internal/licence"
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

func TestDiffLicenceGate(t *testing.T) {
	rootfs := "../../rules/testdata/PH-CHROMA-TELEMETRY/positive/rootfs"
	a, b := filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")
	var so, se bytes.Buffer
	if c := run([]string{"scan", "--rootfs", rootfs, "--skip", "egress,agents", "--out", a}, &so, &se); c != exitOK {
		t.Fatal(se.String())
	}
	if c := run([]string{"scan", "--rootfs", rootfs, "--skip", "egress", "--agents", "../../internal/agents/testdata/leaky.yaml", "--out", b}, &so, &se); c != exitOK {
		t.Fatal(se.String())
	}

	// Free: counts only, and the regression gate still works.
	so.Reset()
	if c := run([]string{"diff", a, b, "--exit-code"}, &so, &se); c != exitBelowThreshold {
		t.Errorf("new open findings with --exit-code: exit %d, want 1", c)
	}
	if !strings.Contains(so.String(), "+1 new") || !strings.Contains(so.String(), "Pro feature") || strings.Contains(so.String(), "AG-0001") {
		t.Errorf("free diff output:\n%s", so.String())
	}

	// Pro: a valid licence itemises it.
	dir := t.TempDir()
	if c := run([]string{"keygen", "--out", filepath.Join(dir, "lk")}, &so, &se); c != exitOK {
		t.Fatal(se.String())
	}
	pub, _ := os.ReadFile(filepath.Join(dir, "lk.pub"))
	lines := strings.Split(strings.TrimSpace(string(pub)), "\n")
	old := licence.PublicKey
	licence.PublicKey = lines[len(lines)-1]
	t.Cleanup(func() { licence.PublicKey = old })
	so.Reset()
	if c := run([]string{"licence", "issue", "--key", filepath.Join(dir, "lk.key"), "--org", "Test Org", "--expires", "2099-12-31"}, &so, &se); c != exitOK {
		t.Fatal(se.String())
	}
	lic := filepath.Join(dir, "lic")
	os.WriteFile(lic, so.Bytes(), 0o600)
	so.Reset()
	if c := run([]string{"licence", "--licence", lic}, &so, &se); c != exitOK || !strings.Contains(so.String(), "Pro licence: Test Org") {
		t.Errorf("licence status: %s %s", so.String(), se.String())
	}
	so.Reset()
	if c := run([]string{"diff", a, b, "--licence", lic}, &so, &se); c != exitOK {
		t.Errorf("diff without --exit-code: exit %d", c)
	}
	if !strings.Contains(so.String(), "+ AG-0001") || len(strings.Split(so.String(), "\n")) > 30 {
		t.Errorf("pro diff output (want itemised, under 30 lines):\n%s", so.String())
	}
}

func TestTTYNeutralisesControlChars(t *testing.T) {
	b := &evidence.Bundle{
		Modules:  []evidence.ModuleStatus{{Name: "egress", Status: evidence.ModuleRan}},
		Egress:   &evidence.EgressSection{Attempts: []evidence.EgressAttempt{{Kind: "dns", Name: "evil\x1b[2J.example"}}},
		Findings: []evidence.Finding{{ID: "EG-0001", Rule: evidence.RuleEgressAttempt, Severity: evidence.High, Status: "open", Title: "x\x1b]0;pwned\x07"}},
	}
	for _, l := range renderTTY(b, nil, false) {
		if strings.ContainsAny(l, "\x1b\x07") {
			t.Fatalf("control character reached the terminal: %q", l)
		}
	}
}

func TestScanValidatesInputsBeforeWriting(t *testing.T) {
	rootfs := "../../rules/testdata/PH-CHROMA-TELEMETRY/positive/rootfs"
	out := filepath.Join(t.TempDir(), "ev")
	var so, se bytes.Buffer
	for _, args := range [][]string{
		{"--models", "/nonexistent"},
		{"--skip", "egress,agents", "--agents", "x.yaml"},
		{"--agents", "../../internal/agents/testdata/mcp-files.json"}, // fails after --out is created
	} {
		a := append([]string{"scan", "--rootfs", rootfs, "--skip", "egress", "--out", out}, args...)
		if c := run(a, &so, &se); c != exitUsage {
			t.Errorf("%v: exit %d, want 2: %s", args, c, se.String())
		}
		if _, err := os.Stat(out); err == nil {
			t.Errorf("%v: left %s behind", args, out)
		}
	}
	// Same inputs spelled differently give the same evidence (rule 6).
	o1, o2 := filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")
	run([]string{"scan", "--rootfs", rootfs, "--skip", "egress", "--agents", "../../internal/agents/testdata/leaky.yaml", "--out", o1}, &so, &se)
	run([]string{"scan", "--rootfs", "./" + rootfs + "/", "--skip", "egress", "--agents", "./../../internal/agents/testdata/leaky.yaml", "--out", o2}, &so, &se)
	e1, _ := os.ReadFile(filepath.Join(o1, "evidence.json"))
	e2, _ := os.ReadFile(filepath.Join(o2, "evidence.json"))
	if len(e1) == 0 || !bytes.Equal(e1, e2) {
		t.Error("evidence.json depends on how the input paths are spelled")
	}
}

func TestParseMinAGR(t *testing.T) {
	for in, want := range map[string]int{"": -1, "0": 0, "2": 2, "4": 4, "AGR-2": 2, "agr-3": 3, "Agr-4": 4, " AGR-1 ": 1} {
		if got, err := parseMinAGR(in); err != nil || got != want {
			t.Errorf("parseMinAGR(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"5", "-1", "AGR-5", "AGR-", "AGR", "AGR--1", "AGR-+1", "two", "AGR-2x", "1.5"} {
		if _, err := parseMinAGR(in); err == nil {
			t.Errorf("parseMinAGR(%q) accepted", in)
		}
	}
}

// --min-agr on --replay gates the saved level instead of being ignored.
func TestReplayMinAGR(t *testing.T) {
	rootfs := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootfs, "x"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "e")
	var so, se bytes.Buffer
	if code := run([]string{"scan", "--rootfs", rootfs, "--skip", "egress", "--out", out}, &so, &se); code != exitOK {
		t.Fatalf("scan exit %d: %s", code, se.String())
	}
	// A static-only run is unassessed: below every threshold, in either spelling.
	for _, v := range []string{"1", "AGR-1", "agr-4"} {
		so.Reset()
		se.Reset()
		if code := run([]string{"scan", "--replay", out, "--replay-speed", "1000", "--min-agr", v}, &so, &se); code != exitBelowThreshold {
			t.Errorf("replay --min-agr %s: exit %d, want %d (%s)", v, code, exitBelowThreshold, se.String())
		}
	}
	so.Reset()
	se.Reset()
	if code := run([]string{"scan", "--replay", out, "--replay-speed", "1000"}, &so, &se); code != exitOK {
		t.Errorf("replay without --min-agr: exit %d", code)
	}
	if code := run([]string{"scan", "--replay", out, "--min-agr", "9"}, &so, &se); code != exitUsage {
		t.Errorf("replay --min-agr 9: exit %d, want usage", code)
	}
}
