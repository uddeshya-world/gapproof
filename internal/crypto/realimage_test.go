package crypto

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uddeshya-world/gapproof/internal/fsscan"
	"github.com/uddeshya-world/gapproof/internal/inventory"
)

// TestRealCryptographyWheel is the M2 acceptance test: build python:3.12-slim
// + `pip install cryptography`, save it, extract it with fsscan, and check
// the crypto scan reports the wheel's bundled OpenSSL as unvalidated.
// Needs a container engine and network for the build (test infrastructure,
// not Gapproof); skipped without one unless GAPPROOF_REQUIRE_CONTAINER=1.
func TestRealCryptographyWheel(t *testing.T) {
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
	const tag = "gapproof-test/py-cryptography:m2"
	if out, err := exec.Command(engine, "build", "-q", "-t", tag, "testdata/py-cryptography").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	tarPath := filepath.Join(t.TempDir(), "img.tar")
	if out, err := exec.Command(engine, "save", "-o", tarPath, tag).CombinedOutput(); err != nil {
		t.Fatalf("save: %v\n%s", err, out)
	}
	im, err := fsscan.ExtractImage(context.Background(), tarPath, fsscan.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer im.Close()
	inv, err := inventory.Build(context.Background(), im.Root, inventory.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	snap, _ := BuiltinSnapshot()
	res, err := Scan(context.Background(), im.Root, inv, snap, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range res.Modules {
		t.Logf("%-14s %-10s %-13s %-26s %s", m.Library, m.Version, m.Origin, m.Status, m.Path)
	}
	var wheel *Module
	for i, m := range res.Modules {
		if strings.HasSuffix(m.Path, "cryptography/hazmat/bindings/_rust.abi3.so") {
			wheel = &res.Modules[i]
		}
	}
	if wheel == nil {
		t.Fatal("the OpenSSL bundled inside the cryptography wheel was not found")
	}
	if wheel.Library != "openssl" || wheel.Version == "" || wheel.Status != StatusUnvalidated || wheel.Package != "cryptography" || wheel.Origin != "python-wheel" {
		t.Errorf("bundled OpenSSL: %+v", *wheel)
	}
	found := false
	for _, f := range res.Findings {
		if f.Rule == RuleUnvalidated && f.Evidence.Path == wheel.Path && strings.Contains(f.Evidence.Detail, "CMVP snapshot "+snap.SnapshotDate) {
			found = true
		}
	}
	if !found {
		t.Error("no CRYPTO-UNVALIDATED-MODULE finding stating the snapshot date for the wheel's OpenSSL")
	}
	if pkgs := inv.Package("cryptography"); len(pkgs) != 1 || len(pkgs[0].WheelTags) == 0 {
		t.Errorf("cryptography should be inventoried as a wheel install: %+v", pkgs)
	}
}
