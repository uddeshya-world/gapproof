package fsscan

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestRealDockerSave extracts a real `docker save` archive, so the format
// handling is checked against what Docker/Podman actually produce. Skipped
// without a container engine unless GAPPROOF_REQUIRE_CONTAINER=1.
func TestRealDockerSave(t *testing.T) {
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
			t.Fatal("GAPPROOF_REQUIRE_CONTAINER=1 but no container engine is usable")
		}
		t.Skip("no container engine available")
	}
	image := os.Getenv("GAPPROOF_NOEGRESS_IMAGE")
	if image == "" {
		image = "gcr.io/distroless/static-debian12:nonroot"
	}
	if exec.Command(engine, "image", "inspect", image).Run() != nil {
		if out, err := exec.Command(engine, "pull", "-q", image).CombinedOutput(); err != nil {
			t.Fatalf("pull %s: %v\n%s", image, err, out)
		}
	}
	tarPath := filepath.Join(t.TempDir(), "img.tar")
	if out, err := exec.Command(engine, "save", "-o", tarPath, image).CombinedOutput(); err != nil {
		t.Fatalf("save: %v\n%s", err, out)
	}
	im, err := ExtractImage(context.Background(), tarPath, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer im.Close()
	if _, err := im.Root.Stat("etc/os-release"); err != nil {
		t.Errorf("etc/os-release missing from extracted rootfs: %v", err)
	}
	id, err := exec.Command(engine, "image", "inspect", "--format", "{{.Id}}", image).Output()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("config %s, image ID %s, %d layers, stats %+v", im.ConfigDigest, im.ImageID, len(im.Layers), im.Stats)
	// Classic store: engine ID = config digest. containerd store: engine ID =
	// the index/manifest digest that index.json points at.
	// Podman prints the ID without the "sha256:" prefix.
	got := strings.TrimSpace(string(id))
	if !strings.HasPrefix(got, "sha256:") {
		got = "sha256:" + got
	}
	if got != im.ConfigDigest && !slices.Contains(im.AltImageIDs, got) {
		t.Errorf("engine image ID %s matches neither config digest %s nor image ID %s", got, im.ConfigDigest, im.ImageID)
	}
}

// TestRealDockerSaveAttested: buildx provenance attestations (on by default)
// and a rebuild of the same tag make `docker save` write an index.json the
// harness used to reject ("refusing to observe a different image"). The ID
// Docker reports after loading must be one of AltImageIDs.
func TestRealDockerSaveAttested(t *testing.T) {
	if testing.Short() {
		t.Skip("container test skipped in -short mode")
	}
	// Podman (also reachable as `docker`) has no buildx attestations.
	if out, err := exec.Command("docker", "--version").Output(); err != nil || !strings.HasPrefix(string(out), "Docker version") {
		t.Skip("not Docker: provenance attestations are Docker-only")
	}
	if exec.Command("docker", "buildx", "version").Run() != nil {
		t.Skip("no docker buildx: provenance attestations are Docker-only")
	}
	const base = "gcr.io/distroless/static-debian12:nonroot"
	if exec.Command("docker", "image", "inspect", base).Run() != nil {
		if out, err := exec.Command("docker", "pull", "-q", base).CombinedOutput(); err != nil {
			t.Fatalf("pull: %v\n%s", err, out)
		}
	}
	const tag = "gapproof-test/attested:latest"
	t.Cleanup(func() { exec.Command("docker", "rmi", "-f", tag).Run() })
	for _, v := range []string{"1", "2"} { // the rebuild leaves the old attestation behind
		b := exec.Command("docker", "buildx", "build", "--provenance=true", "--load", "-t", tag, "-")
		b.Stdin = strings.NewReader("FROM " + base + "\nLABEL gapproof.test=" + v + "\n")
		if out, err := b.CombinedOutput(); err != nil {
			t.Fatalf("build: %v\n%s", err, out)
		}
	}
	tarPath := filepath.Join(t.TempDir(), "img.tar")
	if out, err := exec.Command("docker", "save", "-o", tarPath, tag).CombinedOutput(); err != nil {
		t.Fatalf("save: %v\n%s", err, out)
	}
	im, err := ExtractImage(context.Background(), tarPath, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer im.Close()
	out, err := exec.Command("docker", "load", "-i", tarPath).CombinedOutput()
	if err != nil {
		t.Fatalf("load: %v\n%s", err, out)
	}
	id, err := exec.Command("docker", "image", "inspect", "--format", "{{.Id}}", tag).Output()
	if err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(string(id))
	t.Logf("engine %s, config %s, alt %v", got, im.ConfigDigest, im.AltImageIDs)
	if got != im.ConfigDigest && !slices.Contains(im.AltImageIDs, got) {
		t.Errorf("engine ID %s not among config %s / alt %v", got, im.ConfigDigest, im.AltImageIDs)
	}
}
