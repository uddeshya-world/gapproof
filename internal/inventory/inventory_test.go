package inventory

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, dir, p, body string) {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(p))
	os.MkdirAll(filepath.Dir(full), 0o755)
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestBuild(t *testing.T) {
	d := t.TempDir()
	sp := "usr/local/lib/python3.12/site-packages/"
	write(t, d, sp+"Foo_Bar-1.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: Foo_Bar\nVersion: 1.0\n\nName: decoy\n")
	write(t, d, sp+"Foo_Bar-1.0.dist-info/WHEEL", "Wheel-Version: 1.0\nTag: cp312-cp312-manylinux_2_28_x86_64\nTag: cp312-abi3-linux_x86_64\n")
	write(t, d, sp+"old.egg-info/PKG-INFO", "Name: oldpkg\nVersion: 0.1\n")
	write(t, d, sp+"broken.dist-info/METADATA", "Version: 9\n")
	write(t, d, sp+"foo/lib.py", "x = 1\n")
	write(t, d, "usr/lib/python3.12/os.py", "x\n")
	write(t, d, "app/main.py", "print()\n")
	write(t, d, "app/web/index.js", "x\n")
	write(t, d, "app/node_modules/m/index.js", "x\n")
	write(t, d, "app/big.py", string(make([]byte, 100)))
	write(t, d, "usr/share/doc/x.py", "x\n")

	root, _ := os.OpenRoot(d)
	defer root.Close()
	lim := DefaultLimits()
	lim.MaxSourceSize = 50
	inv, err := Build(context.Background(), root, lim)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Python) != 2 || inv.Python[0].Name != "foo-bar" || inv.Python[0].Version != "1.0" || len(inv.Python[0].WheelTags) != 2 {
		t.Errorf("python: %+v", inv.Python)
	}
	if got := inv.Package("FOO.bar"); len(got) != 1 {
		t.Errorf("Package lookup by unnormalised name: %v", got)
	}
	if inv.Python[1].Name != "oldpkg" || inv.Python[1].WheelTags != nil {
		t.Errorf("egg-info: %+v", inv.Python[1])
	}
	want := []string{"app/main.py", "app/web/index.js"}
	if len(inv.Sources) != 2 || inv.Sources[0] != want[0] || inv.Sources[1] != want[1] {
		t.Errorf("sources = %v, want %v", inv.Sources, want)
	}

	lim.MaxSources = 1
	inv, _ = Build(context.Background(), root, lim)
	if len(inv.Sources) != 1 || inv.Skipped != 1 {
		t.Errorf("source cap: %v skipped=%d", inv.Sources, inv.Skipped)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Build(ctx, root, lim); err == nil {
		t.Error("want context error")
	}
}

func TestNormalizeAndEnv(t *testing.T) {
	if Normalize("Huggingface_Hub") != "huggingface-hub" || Normalize("a.b--c") != "a-b-c" {
		t.Error("PEP 503 normalisation")
	}
	m := EnvMap([]string{"A=1", "B=x=y", "A=2", "=bad", "NOEQ"})
	if m["A"] != "2" || m["B"] != "x=y" || len(m) != 2 {
		t.Errorf("EnvMap = %v", m)
	}
	if !IsLibraryPath("opt/venv/lib/python3.11/site-packages/x.py") || IsLibraryPath("app/python/x.py") || !IsLibraryPath("usr/lib/python3/dist-packages/y.py") {
		t.Error("IsLibraryPath")
	}
}
