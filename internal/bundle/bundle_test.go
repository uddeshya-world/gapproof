package bundle

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- fixtures ----

type member struct {
	name string
	body string
	typ  byte
}

func tarBytes(t *testing.T, ms ...member) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, m := range ms {
		typ := m.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Name: m.name, Typeflag: typ, Mode: 0o644}
		if typ == tar.TypeReg {
			h.Size = int64(len(m.body))
		}
		if typ == tar.TypeSymlink {
			h.Linkname = m.body
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			tw.Write([]byte(m.body))
		}
	}
	tw.Close()
	return buf.Bytes()
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// imageTar writes a minimal docker-save archive (legacy manifest.json
// layout) with one layer holding app/version.txt = content, and returns its
// path and config digest.
func imageTar(t *testing.T, content string) (string, string) {
	t.Helper()
	layer := tarBytes(t, member{name: "app/version.txt", body: content})
	layerName := "blobs/sha256/" + strings.TrimPrefix(sha(layer), "sha256:")
	cfg, _ := json.Marshal(map[string]any{
		"os": "linux", "architecture": "amd64",
		"config": map[string]any{"Cmd": []string{"/app"}},
		"rootfs": map[string]any{"type": "layers", "diff_ids": []string{sha(layer)}},
	})
	cfgName := "blobs/sha256/" + strings.TrimPrefix(sha(cfg), "sha256:")
	man, _ := json.Marshal([]any{map[string]any{"Config": cfgName, "RepoTags": []string{"demo:1"}, "Layers": []string{layerName}}})
	p := filepath.Join(t.TempDir(), "image.tar")
	if err := os.WriteFile(p, tarBytes(t,
		member{name: layerName, body: string(layer)},
		member{name: cfgName, body: string(cfg)},
		member{name: "manifest.json", body: string(man)},
	), 0o644); err != nil {
		t.Fatal(err)
	}
	return p, sha(cfg)
}

// evidenceDir builds a small evidence directory, including scope and
// waivers copies and a nested file.
func evidenceDir(t *testing.T, level string) string {
	t.Helper()
	d := t.TempDir()
	files := map[string]string{
		"summary.json":          `{"agr":{"level":"` + level + `","spec_version":"0.2-draft"}}` + "\n",
		"evidence.json":         `{"findings":[]}` + "\n",
		"report.md":             "# Report\n",
		"gapproof.scope.yaml":   "scope_version: 1\ninternal_names: [db]\n",
		"gapproof.waivers.yaml": "waivers_version: 1\nwaivers: []\n",
		"extra/notes.txt":       "nested\n",
	}
	for p, body := range files {
		full := filepath.Join(d, filepath.FromSlash(p))
		os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func keypair(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey, string) {
	t.Helper()
	prefix := filepath.Join(t.TempDir(), "signer")
	if _, err := Keygen(prefix); err != nil {
		t.Fatal(err)
	}
	priv, err := LoadPrivateKey(prefix + ".key")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := LoadPublicKey(prefix + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub, prefix
}

// signedBundle runs the full producer flow and returns the bundle path.
func signedBundle(t *testing.T, dir, digest string, priv ed25519.PrivateKey) string {
	t.Helper()
	if _, err := WriteManifest(dir, digest); err != nil {
		t.Fatal(err)
	}
	if _, err := Sign(dir, priv); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "bundle.tar")
	if err := Pack(dir, out); err != nil {
		t.Fatal(err)
	}
	return out
}

// ---- tests ----

func TestRoundTripWithArtifact(t *testing.T) {
	priv, pub, _ := keypair(t)
	img, digest := imageTar(t, "v1")
	b := signedBundle(t, evidenceDir(t, "AGR-4"), digest, priv)

	res, err := Verify(context.Background(), b, pub, img)
	if err != nil {
		t.Fatal(err)
	}
	want := "AGR-4 · signed by " + Fingerprint(pub) + " · artifact digest matches"
	if res.String() != want {
		t.Errorf("verdict = %q, want %q", res.String(), want)
	}
	if res.Files != 6 || res.RecordedArtifact != digest || res.ArtifactDigest != digest {
		t.Errorf("result = %+v", res)
	}

	res, err = Verify(context.Background(), b, pub, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(res.String(), "artifact digest not checked") {
		t.Errorf("verdict = %q", res.String())
	}
}

func TestSwappedImageFailsArtifact(t *testing.T) {
	priv, pub, _ := keypair(t)
	_, digest := imageTar(t, "v1")
	other, otherDigest := imageTar(t, "v2-swapped")
	b := signedBundle(t, evidenceDir(t, "AGR-3"), digest, priv)

	res, err := Verify(context.Background(), b, pub, other)
	if !errors.Is(err, ErrArtifactMismatch) || !errors.Is(err, ErrVerification) {
		t.Fatalf("err = %v, want artifact mismatch", err)
	}
	if res.Artifact != ArtifactMismatch || res.ArtifactDigest != otherDigest {
		t.Errorf("result = %+v", res)
	}
	if !strings.Contains(res.String(), "AGR-3 · signed by ed25519:") || !strings.HasSuffix(res.String(), "artifact digest MISMATCH") {
		t.Errorf("verdict = %q", res.String())
	}

	// Not an image at all.
	junk := filepath.Join(t.TempDir(), "junk.tar")
	os.WriteFile(junk, tarBytes(t, member{name: "x", body: "y"}), 0o644)
	if _, err := Verify(context.Background(), b, pub, junk); !errors.Is(err, ErrArtifactMismatch) {
		t.Errorf("junk artifact: err = %v", err)
	}
	// Missing file is an operational error, not a verdict.
	if _, err := Verify(context.Background(), b, pub, filepath.Join(t.TempDir(), "nope.tar")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing artifact: err = %v", err)
	}
}

func TestNoRecordedArtifact(t *testing.T) {
	priv, pub, _ := keypair(t)
	img, _ := imageTar(t, "v1")
	b := signedBundle(t, evidenceDir(t, "unassessed"), "", priv)
	res, err := Verify(context.Background(), b, pub, "")
	if err != nil || res.Level != "unassessed" || res.RecordedArtifact != "" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if _, err := Verify(context.Background(), b, pub, img); !errors.Is(err, ErrArtifactMismatch) {
		t.Errorf("err = %v, want mismatch (nothing recorded)", err)
	}
}

// rebuild repacks a bundle after mutating its members, keeping the
// original signature: the attacker's view.
func rebuild(t *testing.T, bundlePath string, mutate func(map[string]string) []member) string {
	t.Helper()
	raw, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(bytes.NewReader(raw))
	files := map[string]string{}
	var order []string
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		var b bytes.Buffer
		b.ReadFrom(tr)
		files[h.Name] = b.String()
		order = append(order, h.Name)
	}
	extra := mutate(files)
	var ms []member
	for _, n := range order {
		if body, ok := files[n]; ok {
			ms = append(ms, member{name: n, body: body})
		}
	}
	ms = append(ms, extra...)
	p := filepath.Join(t.TempDir(), "tampered.tar")
	os.WriteFile(p, tarBytes(t, ms...), 0o644)
	return p
}

func TestTamperingFails(t *testing.T) {
	priv, pub, _ := keypair(t)
	_, digest := imageTar(t, "v1")
	b := signedBundle(t, evidenceDir(t, "AGR-4"), digest, priv)

	tests := []struct {
		name   string
		mutate func(map[string]string) []member
		want   string
	}{
		{"tampered report", func(f map[string]string) []member { f["report.md"] = "# Report (edited)\n"; return nil }, "report.md was modified"},
		{"changed scope", func(f map[string]string) []member {
			f["gapproof.scope.yaml"] += "internal_cidrs: [10.0.0.0/8]\n"
			return nil
		}, "gapproof.scope.yaml was modified"},
		{"changed waivers", func(f map[string]string) []member {
			f["gapproof.waivers.yaml"] = "waivers_version: 1\nwaivers: [{rule: X}]\n"
			return nil
		}, "gapproof.waivers.yaml was modified"},
		{"raised level", func(f map[string]string) []member {
			f["summary.json"] = strings.Replace(f["summary.json"], "AGR-4", "AGR-4 ", 1)
			return nil
		}, "summary.json was modified"},
		{"deleted waivers", func(f map[string]string) []member { delete(f, "gapproof.waivers.yaml"); return nil }, "gapproof.waivers.yaml is listed in the manifest but missing"},
		{"extra file", func(map[string]string) []member { return []member{{name: "payload.sh", body: "echo hi\n"}} }, "payload.sh is present but not listed"},
		{"edited manifest", func(f map[string]string) []member {
			c := "0"
			if f[ManifestName][0] == '0' {
				c = "1"
			}
			f[ManifestName] = c + f[ManifestName][1:]
			return nil
		}, "signature does not verify"},
		{"no signature", func(f map[string]string) []member { delete(f, SignatureName); return nil }, "unsigned"},
		{"no manifest", func(f map[string]string) []member { delete(f, ManifestName); return nil }, "no MANIFEST.sha256"},
		{"garbled signature", func(f map[string]string) []member { f[SignatureName] = "nope\n"; return nil }, "not a gapproof-ed25519-signature-v1"},
		{"duplicate entry", func(f map[string]string) []member { return []member{{name: "report.md", body: "# Report\n"}} }, "more than once"},
		{"traversal", func(map[string]string) []member { return []member{{name: "../evil", body: "x"}} }, "unsafe path"},
		{"absolute", func(map[string]string) []member { return []member{{name: "/etc/passwd", body: "x"}} }, "unsafe path"},
		{"symlink", func(map[string]string) []member {
			return []member{{name: "link", body: "/etc/passwd", typ: tar.TypeSymlink}}
		}, "not a regular file"},
		{"directory entry", func(map[string]string) []member { return []member{{name: "d/", typ: tar.TypeDir}} }, "not a regular file"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := rebuild(t, b, tc.mutate)
			_, err := Verify(context.Background(), p, pub, "")
			if !errors.Is(err, ErrVerification) {
				t.Fatalf("err = %v, want ErrVerification", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestWrongKeyFails(t *testing.T) {
	priv, _, _ := keypair(t)
	_, other, _ := keypair(t)
	b := signedBundle(t, evidenceDir(t, "AGR-2"), "", priv)
	_, err := Verify(context.Background(), b, other, "")
	if !errors.Is(err, ErrVerification) || !strings.Contains(err.Error(), "but --pub is "+Fingerprint(other)) {
		t.Fatalf("err = %v", err)
	}
	if _, err := Verify(context.Background(), b, ed25519.PublicKey{1, 2}, ""); !errors.Is(err, ErrKey) {
		t.Errorf("short key: err = %v", err)
	}
}

func TestHostileTarLimits(t *testing.T) {
	priv, pub, _ := keypair(t)
	b := signedBundle(t, evidenceDir(t, "AGR-1"), "", priv)
	ctx := context.Background()
	cases := []struct {
		name string
		lim  limits
		want string
	}{
		{"entries", limits{maxEntries: 3, maxFileSize: 1 << 20, maxTotal: 1 << 20, maxSmall: 1 << 20}, "more than 3 entries"},
		{"file size", limits{maxEntries: 100, maxFileSize: 10, maxTotal: 1 << 20, maxSmall: 1 << 20}, "limit 10"},
		{"total", limits{maxEntries: 100, maxFileSize: 1 << 20, maxTotal: 100, maxSmall: 1 << 20}, "larger than 100 bytes"},
		{"small", limits{maxEntries: 100, maxFileSize: 1 << 20, maxTotal: 1 << 20, maxSmall: 20}, "limit 20"},
	}
	for _, tc := range cases {
		_, _, err := verify(ctx, b, pub, "", nil, tc.lim)
		if !errors.Is(err, ErrVerification) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v", tc.name, err)
		}
	}

	// Not a tar / truncated tar.
	raw, _ := os.ReadFile(b)
	trunc := filepath.Join(t.TempDir(), "trunc.tar")
	os.WriteFile(trunc, raw[:700], 0o644)
	if _, err := Verify(ctx, trunc, pub, ""); !errors.Is(err, ErrVerification) {
		t.Errorf("truncated: err = %v", err)
	}
	if _, err := Verify(ctx, filepath.Join(t.TempDir(), "missing.tar"), pub, ""); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing: err = %v", err)
	}
	if _, err := Verify(ctx, t.TempDir(), pub, ""); err == nil || errors.Is(err, ErrVerification) {
		t.Errorf("directory: err = %v", err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := Verify(cctx, b, pub, ""); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: err = %v", err)
	}
}

func TestLevelHandling(t *testing.T) {
	priv, pub, _ := keypair(t)
	for level, want := range map[string]string{
		"AGR-0":                 "AGR-0",
		"AGR-9":                 "unrecognised AGR level",
		`AGR-1\u001b[31m`:       "unrecognised AGR level",
		"AGR-1\x1b[31m":         "AGR level not recorded", // raw control char: invalid JSON
		"":                      "AGR level not recorded",
		"unassessed":            "unassessed",
		"AGR-4 · artifact okay": "unrecognised AGR level",
	} {
		d := evidenceDir(t, level)
		b := signedBundle(t, d, "", priv)
		res, err := Verify(context.Background(), b, pub, "")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(res.String(), want+" · ") {
			t.Errorf("level %q: verdict %q", level, res.String())
		}
	}
	// No summary.json at all.
	d := evidenceDir(t, "AGR-1")
	os.Remove(filepath.Join(d, "summary.json"))
	res, err := Verify(context.Background(), signedBundle(t, d, "", priv), pub, "")
	if err != nil || res.Level != "" {
		t.Errorf("res=%+v err=%v", res, err)
	}
}

func TestPackDeterministic(t *testing.T) {
	priv, _, _ := keypair(t)
	d := evidenceDir(t, "AGR-4")
	a := signedBundle(t, d, "", priv)
	b := filepath.Join(t.TempDir(), "again.tar")
	if err := Pack(d, b); err != nil {
		t.Fatal(err)
	}
	ra, _ := os.ReadFile(a)
	rb, _ := os.ReadFile(b)
	if !bytes.Equal(ra, rb) {
		t.Fatal("Pack is not byte-deterministic")
	}
	tr := tar.NewReader(bytes.NewReader(ra))
	var names []string
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		if h.Mode != 0o644 || h.Uid != 0 || h.Gid != 0 || !h.ModTime.Equal(h.ModTime.Truncate(0)) || h.ModTime.Unix() != 0 {
			t.Errorf("%s: header not normalised: %+v", h.Name, h)
		}
		names = append(names, h.Name)
	}
	want := "MANIFEST.sha256 MANIFEST.sig evidence.json extra/notes.txt gapproof.scope.yaml gapproof.waivers.yaml report.md summary.json"
	if got := strings.Join(names, " "); got != want {
		t.Errorf("members = %s\nwant      %s", got, want)
	}
	if err := Pack(d, filepath.Join(d, "inside.tar")); err == nil || !strings.Contains(err.Error(), "must not be inside") {
		t.Errorf("pack into dir: %v", err)
	}
	if err := Pack(d, filepath.Join(t.TempDir(), "nodir", "x.tar")); err == nil {
		t.Error("pack into missing dir should fail")
	}
}

func TestManifestFormat(t *testing.T) {
	d := evidenceDir(t, "AGR-4")
	digest := "sha256:" + strings.Repeat("ab", 32)
	m, err := WriteManifest(d, digest)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(d, ManifestName))
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != 7 || lines[6] != "artifact "+digest || !strings.HasSuffix(lines[0], "  evidence.json") {
		t.Errorf("manifest:\n%s", raw)
	}
	back, err := ReadManifest(d)
	if err != nil || back.Artifact != digest || len(back.Files) != len(m.Files) {
		t.Fatalf("read back: %+v %v", back, err)
	}
	if !bytes.Equal(back.Marshal(), raw) {
		t.Error("marshal/parse not canonical")
	}

	if _, err := WriteManifest(d, "sha256:XYZ"); err == nil {
		t.Error("bad digest accepted")
	}
	if _, err := ReadManifest(t.TempDir()); err == nil {
		t.Error("missing manifest accepted")
	}

	h := strings.Repeat("0", 64)
	bad := map[string]string{
		"no newline":    "artifact none",
		"no artifact":   h + "  a\n",
		"bad artifact":  "artifact md5:x\n",
		"bad line":      h + " a\nartifact none\n",
		"bad hash":      "XYZ  a\nartifact none\n",
		"traversal":     h + "  ../a\nartifact none\n",
		"unsorted":      h + "  b\n" + h + "  a\nartifact none\n",
		"duplicate":     h + "  a\n" + h + "  a\nartifact none\n",
		"reserved":      h + "  MANIFEST.sig\nartifact none\n",
		"control char":  h + "  a\tb\nartifact none\n",
		"backslash":     h + `  a\b` + "\nartifact none\n",
		"not utf8":      h + "  \xff\nartifact none\n",
		"empty name":    h + "  \nartifact none\n",
		"leading slash": h + "  /a\nartifact none\n",
	}
	for name, s := range bad {
		if _, err := ParseManifest([]byte(s)); err == nil {
			t.Errorf("%s: accepted %q", name, s)
		}
	}
	if m, err := ParseManifest([]byte("artifact none\n")); err != nil || len(m.Files) != 0 || m.Artifact != "" {
		t.Errorf("empty manifest: %+v %v", m, err)
	}
}

func TestTreeRefusesSymlinks(t *testing.T) {
	d := evidenceDir(t, "AGR-1")
	if err := os.Symlink("/etc/passwd", filepath.Join(d, "link")); err != nil {
		t.Skip("symlinks unsupported:", err)
	}
	if _, err := WriteManifest(d, ""); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("err = %v", err)
	}
	if err := Pack(d, filepath.Join(t.TempDir(), "b.tar")); err == nil {
		t.Error("pack followed a symlink")
	}
	if _, err := WriteManifest(filepath.Join(d, "nope"), ""); err == nil {
		t.Error("missing dir accepted")
	}
}

func TestSignRefusesStaleManifest(t *testing.T) {
	priv, _, _ := keypair(t)
	d := evidenceDir(t, "AGR-4")
	if _, err := Sign(d, priv); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("no manifest: %v", err)
	}
	WriteManifest(d, "")
	os.WriteFile(filepath.Join(d, "report.md"), []byte("changed after hashing\n"), 0o644)
	if _, err := Sign(d, priv); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Errorf("stale manifest signed: %v", err)
	}
	os.WriteFile(filepath.Join(d, ManifestName), []byte("garbage"), 0o644)
	if _, err := Sign(d, priv); err == nil {
		t.Error("garbage manifest signed")
	}
	WriteManifest(d, "")
	os.Symlink("/etc/passwd", filepath.Join(d, "late-link"))
	if _, err := Sign(d, priv); err == nil {
		t.Error("symlink in dir signed")
	}
}

func TestKeygen(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "k")
	fp, err := Keygen(prefix)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(prefix + ".key")
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("private key mode = %v, %v", fi.Mode(), err)
	}
	pub, err := LoadPublicKey(prefix + ".pub")
	if err != nil || Fingerprint(pub) != fp || len(fp) != len("ed25519:")+16 {
		t.Errorf("fingerprint %q, pub err %v", fp, err)
	}
	priv, err := LoadPrivateKey(prefix + ".key")
	if err != nil || !priv.Public().(ed25519.PublicKey).Equal(pub) {
		t.Errorf("private key doesn't match public: %v", err)
	}

	// Refuses to overwrite, and writes neither file when one exists.
	before, _ := os.ReadFile(prefix + ".key")
	if _, err := Keygen(prefix); !errors.Is(err, ErrKeyExists) {
		t.Errorf("overwrite: %v", err)
	}
	after, _ := os.ReadFile(prefix + ".key")
	if !bytes.Equal(before, after) {
		t.Error("existing key was modified")
	}
	p2 := filepath.Join(t.TempDir(), "k2")
	os.WriteFile(p2+".pub", []byte("x"), 0o644)
	if _, err := Keygen(p2); err == nil {
		t.Error("overwrote existing .pub")
	}
	if _, err := os.Stat(p2 + ".key"); err == nil {
		t.Error("wrote .key although .pub existed")
	}
	if _, err := Keygen(filepath.Join(t.TempDir(), "missing", "k")); err == nil {
		t.Error("keygen into missing dir succeeded")
	}
}

func TestKeyFileErrors(t *testing.T) {
	_, _, prefix := keypair(t)
	if _, err := LoadPublicKey(prefix + ".key"); !errors.Is(err, ErrKey) || !strings.Contains(err.Error(), "is a private key, but a public key is needed") {
		t.Errorf("private as public: %v", err)
	}
	if _, err := LoadPrivateKey(prefix + ".pub"); !errors.Is(err, ErrKey) {
		t.Errorf("public as private: %v", err)
	}
	d := t.TempDir()
	cases := map[string]string{
		"garbage":   "hello\n",
		"bad b64":   publicHeader + "\n!!!\n",
		"wrong len": publicHeader + "\nAAAA\n",
		"3 lines":   publicHeader + "\nAAAA\nAAAA\n",
		"huge":      strings.Repeat("A", maxKeyFile+10),
	}
	for name, body := range cases {
		p := filepath.Join(d, strings.ReplaceAll(name, " ", "_"))
		os.WriteFile(p, []byte(body), 0o644)
		if _, err := LoadPublicKey(p); !errors.Is(err, ErrKey) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := LoadPublicKey(filepath.Join(d, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing: %v", err)
	}
	if _, err := LoadPrivateKey(filepath.Join(d, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing: %v", err)
	}
}
