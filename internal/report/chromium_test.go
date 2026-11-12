package report

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestReportZeroNetworkInChromium is the M4 acceptance check: the golden
// report.html, opened in headless Chromium with the network disabled,
// attempts no request at all. The net-log records every request Chromium
// tries, blocked or not, and a page with a planted <img> and stylesheet is
// the positive control that proves the check can fail.
func TestReportZeroNetworkInChromium(t *testing.T) {
	if testing.Short() {
		t.Skip("container test skipped in -short mode")
	}
	engine := ""
	for _, e := range []string{"docker", "podman"} {
		if _, err := exec.LookPath(e); err == nil && exec.Command(e, "info").Run() == nil {
			engine = e
			break
		}
	}
	if engine == "" {
		if os.Getenv("GAPPROOF_REQUIRE_CONTAINER") == "1" {
			t.Fatal("GAPPROOF_REQUIRE_CONTAINER=1 but no container engine")
		}
		t.Skip("no container engine")
	}
	const img = "gapproof-chromium:test" // test infra only; built from a pinned base
	build := exec.Command(engine, "build", "-q", "-t", img, "-")
	build.Stdin = strings.NewReader("FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc\nRUN apk add --no-cache chromium\n")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build chromium image: %v\n%s", err, out)
	}

	dir := t.TempDir()
	golden, err := os.ReadFile("testdata/golden/report.html")
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "report.html"), golden, 0o644)
	os.WriteFile(filepath.Join(dir, "leak.html"), []byte(`<html><body><img src="http://leak.example/x.png"><link rel=stylesheet href="https://fonts.example/a.css"></body></html>`), 0o644)

	urls := func(page string) []string {
		script := "chromium-browser --headless=new --no-sandbox --disable-gpu --no-first-run " +
			"--disable-background-networking --disable-component-update --disable-sync --disable-default-apps " +
			"--disable-features=OptimizationGuideModelDownloading,OptimizationHintsFetching,OptimizationTargetPrediction,OptimizationHints " +
			"--log-net-log=/tmp/n.json --virtual-time-budget=5000 --dump-dom file:///r/" + page + " >/dev/null 2>&1; cat /tmp/n.json"
		out, err := exec.Command(engine, "run", "--rm", "--network", "none", "-v", dir+":/r:ro", img, "sh", "-c", script).Output()
		if err != nil || len(out) == 0 {
			t.Fatalf("chromium on %s: %v (net-log %d bytes)", page, err, len(out))
		}
		var u []string
		for _, m := range regexp.MustCompile(`"url":"([^"]*)"`).FindAllStringSubmatch(string(out), -1) {
			if !strings.HasPrefix(m[1], "file://") && !strings.HasPrefix(m[1], "data:") && !slices.Contains(u, m[1]) {
				u = append(u, m[1])
			}
		}
		return u
	}

	if got := urls("leak.html"); !slices.Contains(got, "http://leak.example/x.png") {
		t.Fatalf("positive control: the net-log didn't record the planted request; got %v", got)
	}
	if got := urls("report.html"); len(got) > 0 {
		t.Errorf("report.html attempted network requests: %v", got)
	}
}
