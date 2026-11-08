package fsscan

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
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
	if got := string(id[:len(id)-1]); got != im.ConfigDigest && got != im.ImageID {
		t.Errorf("engine image ID %s matches neither config digest %s nor image ID %s", got, im.ConfigDigest, im.ImageID)
	}
}
