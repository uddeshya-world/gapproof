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

	// A signed bundle plus matching and non-matching images, mounted
	// read-only at /work, so verify runs end to end with no network.
	work := t.TempDir()
	img, digest := testImage(t, "v1")
	other, _ := testImage(t, "v2")
	for src, dst := range map[string]string{img: "img.tar", other: "other.tar"} {
		raw, _ := os.ReadFile(src)
		os.WriteFile(filepath.Join(work, dst), raw, 0o644)
	}
	ev := filepath.Join(t.TempDir(), "ev")
	os.Mkdir(ev, 0o755)
	os.WriteFile(filepath.Join(ev, "summary.json"), []byte(`{"agr":{"level":"AGR-2"}}`), 0o644)
	if c, out := runCLI(t, "keygen", "--out", filepath.Join(work, "k")); c != exitOK {
		t.Fatal(out)
	}
	if c, out := runCLI(t, "sign", "--in", ev, "--key", filepath.Join(work, "k.key"), "--artifact-digest", digest, "--bundle", filepath.Join(work, "b.tar")); c != exitOK {
		t.Fatal(out)
	}

	cases := []struct {
		args []string
		want int
	}{
		{[]string{"keygen", "--help"}, exitOK},
		{[]string{"sign", "--help"}, exitOK},
		{[]string{"verify", "/work/b.tar", "--pub", "/work/k.pub", "--artifact", "/work/img.tar"}, exitOK},
		{[]string{"verify", "/work/b.tar", "--pub", "/work/k.pub", "--artifact", "/work/other.tar"}, exitBelowThreshold},
		{[]string{"version"}, exitOK},
		{[]string{"--help"}, exitOK},
		{[]string{"scan", "--help"}, exitOK},
		{[]string{"verify", "--help"}, exitOK},
		{[]string{"report", "--help"}, exitOK},
		{[]string{"rules", "list", "--help"}, exitOK},
		{[]string{"rules", "list"}, exitOK},                                                      // embedded rule pack + CMVP snapshot, no network
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
			"--tmpfs", "/tmp", // verify --artifact extracts the image to a temp dir
			"-v", bin + ":/gapproof:ro",
			"-v", work + ":/work:ro",
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
