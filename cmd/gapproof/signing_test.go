package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runCLI(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String() + stderr.String()
}

func writeTar(t *testing.T, p string, files ...[2]string) {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range files {
		tw.WriteHeader(&tar.Header{Name: f[0], Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(f[1]))})
		tw.Write([]byte(f[1]))
	}
	tw.Close()
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func digestOf(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// testImage writes a one-layer docker-save tar and returns (path, config digest).
func testImage(t *testing.T, content string) (string, string) {
	t.Helper()
	var lb bytes.Buffer
	tw := tar.NewWriter(&lb)
	tw.WriteHeader(&tar.Header{Name: "app/v", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(content))})
	tw.Write([]byte(content))
	tw.Close()
	layer := lb.Bytes()
	cfg, _ := json.Marshal(map[string]any{"os": "linux", "architecture": "amd64",
		"rootfs": map[string]any{"type": "layers", "diff_ids": []string{digestOf(layer)}}})
	cfgName := "blobs/sha256/" + strings.TrimPrefix(digestOf(cfg), "sha256:")
	layerName := "blobs/sha256/" + strings.TrimPrefix(digestOf(layer), "sha256:")
	man, _ := json.Marshal([]any{map[string]any{"Config": cfgName, "Layers": []string{layerName}}})
	p := filepath.Join(t.TempDir(), "img.tar")
	writeTar(t, p, [2]string{layerName, string(layer)}, [2]string{cfgName, string(cfg)}, [2]string{"manifest.json", string(man)})
	return p, digestOf(cfg)
}

func TestKeygenSignVerify(t *testing.T) {
	tmp := t.TempDir()
	prefix := filepath.Join(tmp, "vendor")
	code, out := runCLI(t, "keygen", "--out", prefix)
	if code != exitOK || !strings.Contains(out, "fingerprint: ed25519:") {
		t.Fatalf("keygen: %d\n%s", code, out)
	}
	if code, out := runCLI(t, "keygen", "--out", prefix); code != exitUsage || !strings.Contains(out, "refusing to overwrite") {
		t.Fatalf("keygen overwrite: %d\n%s", code, out)
	}
	fp := strings.TrimSpace(out[strings.Index(out, "ed25519:"):])

	img, digest := testImage(t, "v1")
	other, _ := testImage(t, "v2")
	ev := filepath.Join(tmp, "evidence")
	os.Mkdir(ev, 0o755)
	os.WriteFile(filepath.Join(ev, "summary.json"), []byte(`{"agr":{"level":"AGR-3"}}`), 0o644)
	os.WriteFile(filepath.Join(ev, "report.md"), []byte("# r\n"), 0o644)

	if code, out := runCLI(t, "sign", "--in", ev, "--key", prefix+".pub"); code != exitUsage || !strings.Contains(out, "--key:") {
		t.Fatalf("sign with public key: %d\n%s", code, out)
	}
	if code, out := runCLI(t, "sign", "--in", ev, "--key", prefix+".key", "--artifact-digest", "sha256:nope"); code != exitUsage {
		t.Fatalf("sign bad digest: %d\n%s", code, out)
	}
	code, out = runCLI(t, "sign", "--in", ev, "--key", prefix+".key", "--artifact-digest", digest)
	if code != exitOK || !strings.Contains(out, "signed "+ev+" (2 files) with "+fp) || !strings.Contains(out, "artifact: "+digest) {
		t.Fatalf("sign: %d\n%s", code, out)
	}
	b := ev + ".bundle.tar"

	code, out = runCLI(t, "verify", b, "--pub", prefix+".pub", "--artifact", img)
	if want := "AGR-3 · signed by " + fp + " · artifact digest matches\n"; code != exitOK || out != want {
		t.Fatalf("verify: %d\n%q\nwant %q", code, out, want)
	}
	code, out = runCLI(t, "verify", b, "--pub", prefix+".pub", "--artifact", other)
	if code != exitBelowThreshold || !strings.Contains(out, "artifact digest MISMATCH") {
		t.Fatalf("verify swapped image: %d\n%s", code, out)
	}
	if code, out := runCLI(t, "verify", b, "--pub", prefix+".pub", "--artifact", filepath.Join(tmp, "nope.tar")); code != exitUsage {
		t.Fatalf("verify missing artifact: %d\n%s", code, out)
	}
	if code, out := runCLI(t, "verify", filepath.Join(tmp, "nope.tar"), "--pub", prefix+".pub"); code != exitUsage {
		t.Fatalf("verify missing bundle: %d\n%s", code, out)
	}
	if code, out := runCLI(t, "verify", b, "--pub", prefix+".key"); code != exitUsage {
		t.Fatalf("verify with private key as pub: %d\n%s", code, out)
	}
	if code, out := runCLI(t, "verify", tmp, "--pub", prefix+".pub"); code != exitUsage {
		t.Fatalf("verify a directory: %d\n%s", code, out)
	}

	// Wrong key.
	runCLI(t, "keygen", "--out", filepath.Join(tmp, "other"))
	if code, out := runCLI(t, "verify", b, "--pub", filepath.Join(tmp, "other.pub")); code != exitBelowThreshold || !strings.Contains(out, "verify FAILED") {
		t.Fatalf("verify wrong key: %d\n%s", code, out)
	}

	// Editing evidence after the manifest: sign refuses, --rehash accepts,
	// and the conflicting digest flag is rejected.
	os.WriteFile(filepath.Join(ev, "report.md"), []byte("# edited\n"), 0o644)
	if code, out := runCLI(t, "sign", "--in", ev, "--key", prefix+".key"); code != exitUsage || !strings.Contains(out, "stale") {
		t.Fatalf("sign stale: %d\n%s", code, out)
	}
	if code, out := runCLI(t, "sign", "--in", ev, "--key", prefix+".key", "--artifact-digest", "sha256:"+strings.Repeat("0", 64)); code != exitUsage || !strings.Contains(out, "differs") {
		t.Fatalf("sign conflicting digest: %d\n%s", code, out)
	}
	// The old bundle no longer matches what's on disk, but still verifies itself.
	if code, _ := runCLI(t, "verify", b, "--pub", prefix+".pub"); code != exitOK {
		t.Fatal("old bundle stopped verifying")
	}
	alt := filepath.Join(tmp, "alt.tar")
	if code, out := runCLI(t, "sign", "--in", ev, "--key", prefix+".key", "--rehash", "--bundle", alt); code != exitOK {
		t.Fatalf("sign --rehash: %d\n%s", code, out)
	}
	if code, out := runCLI(t, "verify", alt, "--pub", prefix+".pub", "--artifact", img); code != exitOK {
		t.Fatalf("verify rehashed: %d\n%s", code, out)
	}
	if code, out := runCLI(t, "sign", "--in", ev, "--key", prefix+".key", "--bundle", filepath.Join(ev, "in.tar")); code != exitUsage || !strings.Contains(out, "must not be inside") {
		t.Fatalf("bundle inside dir: %d\n%s", code, out)
	}

	// Tampered bundle (a byte flipped in report.md's content).
	raw, _ := os.ReadFile(alt)
	i := bytes.Index(raw, []byte("# edited"))
	raw[i+2] = 'E'
	bad := filepath.Join(tmp, "bad.tar")
	os.WriteFile(bad, raw, 0o644)
	if code, out := runCLI(t, "verify", bad, "--pub", prefix+".pub"); code != exitBelowThreshold || !strings.Contains(out, "report.md was modified") {
		t.Fatalf("verify tampered: %d\n%s", code, out)
	}
}

func TestSignWithoutDigestWarns(t *testing.T) {
	tmp := t.TempDir()
	runCLI(t, "keygen", "--out", filepath.Join(tmp, "k"))
	ev := filepath.Join(tmp, "ev")
	os.Mkdir(ev, 0o755)
	os.WriteFile(filepath.Join(ev, "evidence.json"), []byte("{}"), 0o644)
	code, out := runCLI(t, "sign", "--in", ev, "--key", filepath.Join(tmp, "k.key"))
	if code != exitOK || !strings.Contains(out, "warning: no artifact digest") {
		t.Fatalf("%d\n%s", code, out)
	}
	code, out = runCLI(t, "verify", ev+".bundle.tar", "--pub", filepath.Join(tmp, "k.pub"))
	if code != exitOK || !strings.HasPrefix(out, "AGR level not recorded · signed by ed25519:") {
		t.Fatalf("%d\n%s", code, out)
	}
	os.WriteFile(filepath.Join(ev, "MANIFEST.sha256"), []byte("garbage"), 0o644)
	if code, out := runCLI(t, "sign", "--in", ev, "--key", filepath.Join(tmp, "k.key")); code != exitUsage {
		t.Fatalf("garbage manifest: %d\n%s", code, out)
	}
}

func TestSignSymlinkedInAndEmptyDir(t *testing.T) {
	tmp := t.TempDir()
	runCLI(t, "keygen", "--out", filepath.Join(tmp, "k"))
	ev := filepath.Join(tmp, "ev")
	os.Mkdir(ev, 0o755)
	os.WriteFile(filepath.Join(ev, "summary.json"), []byte(`{"agr":{"level":"AGR-2"}}`), 0o644)
	os.WriteFile(filepath.Join(ev, "report.md"), []byte("# r\n"), 0o644)
	link := filepath.Join(tmp, "evlink")
	if err := os.Symlink(ev, link); err != nil {
		t.Skip("no symlinks:", err)
	}
	code, out := runCLI(t, "sign", "--in", link, "--key", filepath.Join(tmp, "k.key"))
	if code != exitOK || !strings.Contains(out, "signed "+link+" (2 files)") {
		t.Fatalf("sign via symlink: %d\n%s", code, out)
	}
	code, out = runCLI(t, "verify", link+".bundle.tar", "--pub", filepath.Join(tmp, "k.pub"))
	if code != exitOK || !strings.HasPrefix(out, "AGR-2 · signed by") {
		t.Fatalf("verify: %d\n%s", code, out)
	}

	empty := filepath.Join(tmp, "empty")
	os.Mkdir(empty, 0o755)
	if code, out := runCLI(t, "sign", "--in", empty, "--key", filepath.Join(tmp, "k.key")); code != exitUsage || !strings.Contains(out, "covers no files") {
		t.Fatalf("sign empty dir: %d\n%s", code, out)
	}

	// A group/other-readable private key still signs, with a warning.
	os.Chmod(filepath.Join(tmp, "k.key"), 0o644)
	code, out = runCLI(t, "sign", "--in", ev, "--key", filepath.Join(tmp, "k.key"), "--bundle", filepath.Join(tmp, "b2.tar"))
	if code != exitOK || !strings.Contains(out, "warning: private key") {
		t.Fatalf("lax key perms: %d\n%s", code, out)
	}
}
