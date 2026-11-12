package harness

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeEngine writes a shell script standing in for docker: it logs every
// call and answers `image inspect` from canned output.
func fakeEngine(t *testing.T, harnessPresent bool, targetConfig string) *Engine {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	hp := "exit 1"
	if harnessPresent {
		hp = "echo '[]'; exit 0"
	}
	script := `#!/bin/sh
echo "$*" >> ` + log + `
case "$*" in
  "image inspect --format {{json .RootFS.Layers}} "*) ` + hp + ` ;;
  "image inspect --format {{json .Config}} "*) echo '` + targetConfig + `'; exit 0 ;;
  "ps "*|"network ls "*) exit 0 ;;
  *) echo "unexpected: $*" >&2; exit 99 ;;
esac
`
	bin := filepath.Join(dir, "docker")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return &Engine{Bin: bin}
}

func TestMissingHarnessImageNeverPulls(t *testing.T) {
	e := fakeEngine(t, false, `{}`)
	_, err := Run(context.Background(), e, Config{Target: "x", Observe: time.Second, OutDir: t.TempDir()})
	if !errors.Is(err, ErrHarnessMissing) {
		t.Fatalf("err = %v, want ErrHarnessMissing", err)
	}
	if !strings.Contains(err.Error(), "gapproof harness load") || !strings.Contains(err.Error(), "never pulled") {
		t.Errorf("error should tell the user how to load the image: %v", err)
	}
	for _, c := range e.Calls() {
		if strings.Contains(strings.Join(c, " "), "pull") {
			t.Errorf("pull attempted: %v", c)
		}
	}
}

func TestNetAdminTargetRefused(t *testing.T) {
	PinnedConfigDigest, PinnedLayers = "", ""
	e := fakeEngine(t, true, `{"Labels":{"io.example.capabilities":"NET_ADMIN,SYS_TIME"}}`)
	res, err := Run(context.Background(), e, Config{Target: "x", Observe: time.Second, OutDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Refused) != 1 || res.TargetStarted || res.Passed() {
		t.Fatalf("NET_ADMIN target must be refused, not run: %+v", res)
	}
	for _, c := range e.Calls() {
		if c[1] == "run" {
			t.Errorf("container started for a refused target: %v", c)
		}
	}
}

func TestRequestedNetCaps(t *testing.T) {
	for labels, want := range map[string]int{
		"cap_add=NET_RAW":         1,
		"x=cap_net_admin":         1,
		"desc=uses network admin": 0,
		"net_administrator=1":     0,
	} {
		k, v, _ := strings.Cut(labels, "=")
		if got := len(RequestedNetCaps(map[string]string{k: v})); got != want {
			t.Errorf("%s: %d hits, want %d", labels, got, want)
		}
	}
}

func TestLoadedRef(t *testing.T) {
	for out, want := range map[string]string{
		"Loaded image: gapproof-harness:build\n":        "gapproof-harness:build",
		"Loaded image ID: sha256:abc\n":                 "sha256:abc",
		"noise\nLoaded image: a:b\nLoaded image: c:d\n": "c:d",
		"nothing": "",
	} {
		if got := loadedRef(out); got != want {
			t.Errorf("loadedRef(%q) = %q, want %q", out, got, want)
		}
	}
}

func TestResultPassed(t *testing.T) {
	cases := []struct {
		r    Result
		want bool
	}{
		{Result{}, false},
		{Result{TargetStarted: true, TargetRunning: true}, true},
		{Result{TargetStarted: true, TargetRunning: true, TargetHealth: "unhealthy"}, false},
		{Result{TargetStarted: true, TargetRunning: false}, false},
		{Result{TargetStarted: true, TargetRunning: true, WorkloadRan: true, WorkloadPassed: true}, true},
		// A crashed or unhealthy target with a passing workload is not AGR-1.
		{Result{TargetStarted: true, WorkloadRan: true, WorkloadPassed: true}, false},
		{Result{TargetStarted: true, TargetRunning: true, TargetHealth: "unhealthy", WorkloadRan: true, WorkloadPassed: true}, false},
		{Result{TargetStarted: true, TargetRunning: true, WorkloadRan: true}, false},
	}
	for i, c := range cases {
		if got := c.r.Passed(); got != c.want {
			t.Errorf("case %d: Passed() = %v, want %v", i, got, c.want)
		}
	}
}
