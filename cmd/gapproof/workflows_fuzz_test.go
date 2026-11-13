package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Every package with a Fuzz* target must be in fuzz.yml's matrix, or a new
// target would silently never run in CI.
func TestFuzzWorkflowCoversEveryFuzzPackage(t *testing.T) {
	wf, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "fuzz.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var inMatrix []string
	for _, m := range regexp.MustCompile(`(?m)^\s+- ([a-z0-9]+)\s*$`).FindAllStringSubmatch(string(wf), -1) {
		inMatrix = append(inMatrix, m[1])
	}
	out, err := exec.Command("grep", "-rlE", `^func Fuzz[A-Za-z0-9_]*\(`, "--include=*_test.go", filepath.Join("..", "..", "internal")).Output()
	if err != nil {
		t.Fatalf("grep: %v", err)
	}
	have := map[string]bool{}
	for _, f := range strings.Fields(string(out)) {
		have[filepath.Base(filepath.Dir(f))] = true
	}
	var want []string
	for p := range have {
		want = append(want, p)
	}
	sort.Strings(want)
	for _, p := range want {
		found := false
		for _, m := range inMatrix {
			found = found || m == p
		}
		if !found {
			t.Errorf("internal/%s has Fuzz targets but is not in .github/workflows/fuzz.yml", p)
		}
	}
	for _, m := range inMatrix {
		if !have[m] {
			t.Errorf("fuzz.yml lists internal/%s, which has no Fuzz targets", m)
		}
	}
}
