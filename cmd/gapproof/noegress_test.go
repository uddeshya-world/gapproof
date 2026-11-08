package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestNoEgress runs the real static Linux binary inside a container with
// no network at all (--network none, read-only, all capabilities dropped)
// and asserts every command behaves normally. "We sell this property, so
// we must have it" (CLAUDE.md rule 1).
//
// Needs Docker or Podman. Skipped when neither is available, unless
// GAPPROOF_REQUIRE_CONTAINER=1 (set in CI), which turns the skip into a failure.
//
// M0 can only exercise version/help and the stubs. As modules land, add a
// full `scan --rootfs testdata/... --skip egress` case here (review P1 #6).
func TestNoEgress(t *testing.T) {
	if testing.Short() {
		t.Skip("container test skipped in -short mode")
	}
	engine := containerEngine()
	if engine == "" {
		if os.Getenv("GAPPROOF_REQUIRE_CONTAINER") == "1" {
			t.Fatal("GAPPROOF_REQUIRE_CONTAINER=1 but neither docker nor podman is usable")
		}
		t.Skip("no container engine available (install OrbStack/Docker, or set GAPPROOF_REQUIRE_CONTAINER=1 to fail instead)")
	}

	bin := filepath.Join(t.TempDir(), "gapproof")
	build := exec.Command("go", "build", "-trimpath", "-o", bin, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("static linux build failed: %v\n%s", err, out)
	}

	image := os.Getenv("GAPPROOF_NOEGRESS_IMAGE")
	if image == "" {
		image = "gcr.io/distroless/static-debian12:nonroot" // no shell, no libc: proves the binary is static
	}

	cases := []struct {
		args []string
		want int
	}{
		{[]string{"version"}, exitOK},
		{[]string{"--help"}, exitOK},
		{[]string{"scan", "--help"}, exitOK},
		{[]string{"verify", "--help"}, exitOK},
		{[]string{"report", "--help"}, exitOK},
		{[]string{"rules", "list", "--help"}, exitOK},
		{[]string{"scan", "--out", "/tmp/o"}, exitUsage},                                         // usage path works offline
		{[]string{"scan", "--rootfs", "/", "--skip", "egress", "--out", "/tmp/o"}, exitInternal}, // stub until M1
	}
	for _, tc := range cases {
		args := append([]string{
			"run", "--rm",
			"--network", "none",
			"--read-only",
			"--cap-drop", "ALL",
			"--security-opt", "no-new-privileges",
			"-v", bin + ":/gapproof:ro",
			image, "/gapproof",
		}, tc.args...)
		out, err := exec.Command(engine, args...).CombinedOutput()
		got := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			got = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("%v: %v", tc.args, err)
		}
		if got != tc.want {
			t.Errorf("%v under --network none: exit %d, want %d\n%s", tc.args, got, tc.want, out)
		}
	}
}

func containerEngine() string {
	for _, e := range []string{"docker", "podman"} {
		if _, err := exec.LookPath(e); err != nil {
			continue
		}
		if exec.Command(e, "info").Run() == nil {
			return e
		}
	}
	return ""
}
