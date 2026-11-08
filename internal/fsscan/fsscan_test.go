package fsscan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
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

// ---- archive builders (all in memory; nothing here is ever executed) ----

type ent struct {
	name string
	typ  byte
	body string
	link string
	mode int64
}

func file(name, body string) ent       { return ent{name: name, typ: tar.TypeReg, body: body, mode: 0o644} }
func dir(name string) ent              { return ent{name: name, typ: tar.TypeDir, mode: 0o755} }
func symlink(name, target string) ent  { return ent{name: name, typ: tar.TypeSymlink, link: target} }
func hardlink(name, target string) ent { return ent{name: name, typ: tar.TypeLink, link: target} }

func tarOf(t *testing.T, ents ...ent) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range ents {
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Linkname: e.link, Mode: e.mode, Size: int64(len(e.body)), Format: tar.FormatPAX}
		if e.typ != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gz(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(b)
	zw.Close()
	return buf.Bytes()
}

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

type layer struct {
	blob []byte // as stored (maybe compressed)
	tar  []byte // uncompressed, for the diff_id
}

func plain(t *testing.T, ents ...ent) layer {
	b := tarOf(t, ents...)
	return layer{b, b}
}

func gzipped(t *testing.T, ents ...ent) layer {
	b := tarOf(t, ents...)
	return layer{gz(t, b), b}
}

type archiveOpts struct {
	oci          bool                 // OCI layout (index.json) instead of manifest.json
	images       int                  // manifest.json entries (default 1)
	badDiffID    bool                 // corrupt the config's first diff_id
	badBlobName  bool                 // store layer 0 under the wrong digest name
	configMutate func(map[string]any) // edit the config
}

// writeArchive builds a docker-save style tar and returns its path.
func writeArchive(t *testing.T, layers []layer, o archiveOpts) string {
	t.Helper()
	var members []ent
	var diffIDs, layerNames []string
	var ociLayers []map[string]any
	for i, l := range layers {
		d := digest(l.blob)
		name := "blobs/sha256/" + strings.TrimPrefix(d, "sha256:")
		if o.badBlobName && i == 0 {
			name = "blobs/sha256/" + strings.Repeat("0", 64)
			d = "sha256:" + strings.Repeat("0", 64)
		}
		members = append(members, file(name, string(l.blob)))
		layerNames = append(layerNames, name)
		diffIDs = append(diffIDs, digest(l.tar))
		ociLayers = append(ociLayers, map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": d, "size": len(l.blob)})
	}
	if o.badDiffID && len(diffIDs) > 0 {
		diffIDs[0] = "sha256:" + strings.Repeat("f", 64)
	}
	cfg := map[string]any{
		"os": "linux", "architecture": "amd64",
		"config": map[string]any{"Env": []string{"PATH=/usr/bin", "HF_HUB_OFFLINE=1"}, "User": "app", "Cmd": []string{"python", "app.py"}},
		"rootfs": map[string]any{"type": "layers", "diff_ids": diffIDs},
	}
	if o.configMutate != nil {
		o.configMutate(cfg)
	}
	cfgRaw, _ := json.Marshal(cfg)
	cfgName := "blobs/sha256/" + strings.TrimPrefix(digest(cfgRaw), "sha256:")
	members = append(members, file(cfgName, string(cfgRaw)))

	if o.oci {
		man, _ := json.Marshal(map[string]any{
			"schemaVersion": 2,
			"config":        map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": digest(cfgRaw)},
			"layers":        ociLayers,
		})
		members = append(members, file("blobs/sha256/"+strings.TrimPrefix(digest(man), "sha256:"), string(man)))
		idx, _ := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": []any{map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": digest(man)}}})
		members = append(members, file("index.json", string(idx)), file("oci-layout", `{"imageLayoutVersion":"1.0.0"}`))
	} else {
		n := max(o.images, 1)
		var ms []any
		for range n {
			ms = append(ms, map[string]any{"Config": cfgName, "RepoTags": []string{"demo:latest"}, "Layers": layerNames})
		}
		raw, _ := json.Marshal(ms)
		members = append(members, file("manifest.json", string(raw)))
	}
	p := filepath.Join(t.TempDir(), "image.tar")
	if err := os.WriteFile(p, tarOf(t, members...), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func extract(t *testing.T, p string, lim Limits) (*Image, error) {
	t.Helper()
	im, err := ExtractImage(context.Background(), p, lim)
	if im != nil {
		t.Cleanup(func() { im.Close() })
	}
	return im, err
}

func readIn(t *testing.T, im *Image, p string) string {
	t.Helper()
	b, err := im.Root.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return string(b)
}

func exists(im *Image, p string) bool {
	_, err := im.Root.Lstat(p)
	return err == nil
}

// ---- tests ----

func TestExtractLayersWhiteoutsAndLinks(t *testing.T) {
	l1 := plain(t,
		dir("etc/"), file("etc/passwd", "root:x:0:0\n"),
		dir("usr/"), dir("usr/lib/"), symlink("lib", "usr/lib"),
		file("opt/keep/a", "a"), file("opt/gone/b", "b"),
		file("var/data/old", "old"), file("var/data/sub/deep", "deep"),
		ent{name: "dev/null", typ: tar.TypeChar},
		ent{name: "bin/suid", typ: tar.TypeReg, body: "x", mode: 0o4755},
	)
	l2 := gzipped(t,
		file("opt/.wh.gone", ""),          // whiteout a lower dir
		file("var/data/.wh..wh..opq", ""), // opaque: hide lower content of var/data
		file("var/data/new", "new"),       // ...but keep this layer's own
		file("lib/libfoo.so", "ELF"),      // written through the lib -> usr/lib symlink
		hardlink("bin/pw", "etc/passwd"),
		file("tmp/same", "same"), file("tmp/.wh.same", ""), // same-layer whiteout must not apply
	)
	im, err := extract(t, writeArchive(t, []layer{l1, l2}, archiveOpts{}), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	checks := []struct {
		path string
		want bool
	}{
		{"etc/passwd", true},
		{"opt/keep/a", true},
		{"opt/gone", false},
		{"var/data/old", false},
		{"var/data/sub", false},
		{"var/data/new", true},
		{"usr/lib/libfoo.so", true},
		{"bin/pw", true},
		{"tmp/same", true},
		{"dev/null", false},
	}
	for _, c := range checks {
		if got := exists(im, c.path); got != c.want {
			t.Errorf("exists(%s) = %v, want %v", c.path, got, c.want)
		}
	}
	if got := readIn(t, im, "bin/pw"); got != "root:x:0:0\n" {
		t.Errorf("hardlink content = %q", got)
	}
	if fi, _ := im.Root.Lstat("bin/suid"); fi.Mode()&(fs.ModeSetuid|fs.ModeSetgid) != 0 {
		t.Errorf("setuid bit kept: %v", fi.Mode())
	}
	st := im.Stats
	if st.SkippedDevices != 1 || st.Whiteouts != 3 || st.Hardlinks != 1 || st.Symlinks != 1 {
		t.Errorf("stats = %+v", st)
	}
	if im.ConfigDigest == "" || len(im.Layers) != 2 || im.Layers[1].Digest == "" {
		t.Errorf("identity not recorded: %+v", im)
	}
	if im.User != "app" || len(im.Env) != 2 || im.RepoTags[0] != "demo:latest" {
		t.Errorf("config not parsed: user=%q env=%v tags=%v", im.User, im.Env, im.RepoTags)
	}
}

func TestPathTraversalRejected(t *testing.T) {
	for _, name := range []string{"../../etc/passwd", "/../etc/passwd", "a/../../x"} {
		t.Run(name, func(t *testing.T) {
			_, err := extract(t, writeArchive(t, []layer{plain(t, file(name, "pwned"))}, archiveOpts{}), DefaultLimits())
			var ue *UnsafePathError
			if !errors.As(err, &ue) {
				t.Fatalf("want UnsafePathError, got %v", err)
			}
			if !strings.Contains(err.Error(), "rejected") {
				t.Errorf("error should be clear, got %q", err)
			}
		})
	}
}

// Symlinks are resolved inside the root (chroot semantics): writing through
// an absolute or climbing symlink lands inside the image, never on the host.
func TestSymlinkEscapeStaysInRoot(t *testing.T) {
	sentinel := filepath.Join(t.TempDir(), "host-file")
	l := plain(t,
		symlink("abs", "/etc"),
		file("abs/passwd", "img"),
		symlink("climb", "../../../../../../../../"+strings.TrimPrefix(filepath.Dir(sentinel), "/")),
		file("climb/host-file", "img"),
		symlink("loop1", "loop2"), symlink("loop2", "loop1"),
	)
	im, err := extract(t, writeArchive(t, []layer{l}, archiveOpts{}), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if got := readIn(t, im, "etc/passwd"); got != "img" {
		t.Errorf("abs symlink write landed elsewhere: %q", got)
	}
	if _, err := os.Stat(sentinel); err == nil {
		t.Fatal("write through a climbing symlink escaped the root")
	}
	inRoot := strings.TrimPrefix(filepath.Dir(sentinel), "/") + "/host-file"
	if got := readIn(t, im, inRoot); got != "img" {
		t.Errorf("climbing symlink write not clamped into root")
	}

	// A write through a symlink loop is refused, not followed forever.
	_, err = extract(t, writeArchive(t, []layer{plain(t, symlink("l1", "l2"), symlink("l2", "l1"), file("l1/x", "x"))}, archiveOpts{}), DefaultLimits())
	var ue *UnsafePathError
	if !errors.As(err, &ue) || !strings.Contains(err.Error(), "symbolic links") {
		t.Fatalf("symlink loop: want UnsafePathError, got %v", err)
	}
}

func TestDecompressionBombRejected(t *testing.T) {
	zeros := strings.Repeat("\x00", 8<<20) // 8 MiB of zeros gzips to ~8 KiB
	lim := DefaultLimits()
	lim.RatioFloor = 1 << 20
	lim.MaxRatio = 100
	_, err := extract(t, writeArchive(t, []layer{gzipped(t, file("bomb", zeros))}, archiveOpts{}), lim)
	var le *LimitError
	if !errors.As(err, &le) || !strings.Contains(err.Error(), "decompression bomb") {
		t.Fatalf("want decompression-ratio LimitError, got %v", err)
	}
}

func TestLimits(t *testing.T) {
	t.Run("file size", func(t *testing.T) {
		lim := DefaultLimits()
		lim.MaxFileSize = 4
		_, err := extract(t, writeArchive(t, []layer{plain(t, file("big", "12345"))}, archiveOpts{}), lim)
		var le *LimitError
		if !errors.As(err, &le) || le.Limit != "max file size" {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("entries", func(t *testing.T) {
		lim := DefaultLimits()
		lim.MaxEntries = 2
		_, err := extract(t, writeArchive(t, []layer{plain(t, file("a", ""), file("b", ""), file("c", ""))}, archiveOpts{}), lim)
		var le *LimitError
		if !errors.As(err, &le) || le.Limit != "max entries" {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("total size", func(t *testing.T) {
		lim := DefaultLimits()
		lim.MaxTotalSize = 5
		_, err := extract(t, writeArchive(t, []layer{plain(t, file("a", "1234"), file("b", "1234"))}, archiveOpts{}), lim)
		var le *LimitError
		if !errors.As(err, &le) || le.Limit != "max total size" {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("metadata size", func(t *testing.T) {
		lim := DefaultLimits()
		lim.MaxMetadataSize = 10
		_, err := extract(t, writeArchive(t, []layer{plain(t, file("a", ""))}, archiveOpts{}), lim)
		var le *LimitError
		if !errors.As(err, &le) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestIntegrity(t *testing.T) {
	l := plain(t, file("a", "a"))
	t.Run("diff_id mismatch", func(t *testing.T) {
		_, err := extract(t, writeArchive(t, []layer{l}, archiveOpts{badDiffID: true}), DefaultLimits())
		var ie *IntegrityError
		if !errors.As(err, &ie) || !strings.Contains(err.Error(), "diff_id") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("blob digest mismatch", func(t *testing.T) {
		_, err := extract(t, writeArchive(t, []layer{l}, archiveOpts{badBlobName: true}), DefaultLimits())
		var ie *IntegrityError
		if !errors.As(err, &ie) || !strings.Contains(err.Error(), "blob") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("layer count", func(t *testing.T) {
		p := writeArchive(t, []layer{l}, archiveOpts{configMutate: func(c map[string]any) {
			c["rootfs"] = map[string]any{"diff_ids": []string{}}
		}})
		_, err := extract(t, p, DefaultLimits())
		var ie *IntegrityError
		if !errors.As(err, &ie) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestOCILayout(t *testing.T) {
	im, err := extract(t, writeArchive(t, []layer{gzipped(t, file("app/main.py", "print()"))}, archiveOpts{oci: true}), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if im.ImageID == "" || im.ImageID == im.ConfigDigest {
		t.Errorf("OCI image ID should be the manifest digest, got %q", im.ImageID)
	}
	if readIn(t, im, "app/main.py") != "print()" || im.Layers[0].Digest == "" {
		t.Errorf("OCI layout not applied: %+v", im.Layers)
	}
}

func TestArchiveErrors(t *testing.T) {
	notTar := filepath.Join(t.TempDir(), "x.tar")
	os.WriteFile(notTar, []byte("definitely not a tar archive, just text padding padding padding"), 0o644)
	zstd := layer{blob: []byte{0x28, 0xb5, 0x2f, 0xfd, 0, 0}, tar: []byte{}}

	tests := []struct {
		name string
		path string
		want string
	}{
		{"not a tar", notTar, "not a readable tar"},
		{"two images", writeArchive(t, []layer{plain(t, file("a", ""))}, archiveOpts{images: 2}), "exactly one image"},
		{"zstd layer", writeArchive(t, []layer{zstd}, archiveOpts{}), "zstd"},
		{"missing file", filepath.Join(t.TempDir(), "nope.tar"), "no such file"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := extract(t, tc.path, DefaultLimits())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestCloseRemovesTempDir(t *testing.T) {
	im, err := ExtractImage(context.Background(), writeArchive(t, []layer{plain(t, file("a", "a"))}, archiveOpts{}), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	dir := im.Dir
	if err := im.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("temp dir %s still exists after Close", dir)
	}
	if err := im.Close(); err != nil {
		t.Fatal("second Close should be a no-op")
	}
}

func TestOpenRootFSDoesNotDelete(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "keep"), []byte("k"), 0o644)
	im, err := OpenRootFS(d)
	if err != nil {
		t.Fatal(err)
	}
	im.Close()
	if _, err := os.Stat(filepath.Join(d, "keep")); err != nil {
		t.Fatal("OpenRootFS.Close deleted user files")
	}
	if _, err := OpenRootFS(filepath.Join(d, "keep")); err == nil {
		t.Fatal("a file is not a rootfs")
	}
}

func TestCleanEntryName(t *testing.T) {
	ok := map[string]string{"./a/b": "a/b", "/abs/x": "abs/x", "a//b/../c": "a/c", "./": ".", "": "."}
	for in, want := range ok {
		if got, err := cleanEntryName(in); err != nil || got != want {
			t.Errorf("cleanEntryName(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	// tar writers refuse NUL in names, but a hostile archive can still carry one.
	var ue *UnsafePathError
	if _, err := cleanEntryName("ok/\x00bad"); !errors.As(err, &ue) {
		t.Errorf("NUL byte in name: want UnsafePathError, got %v", err)
	}
}

func TestContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ExtractImage(ctx, writeArchive(t, []layer{plain(t, file("a", ""))}, archiveOpts{}), DefaultLimits())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

// A later layer writing a file where a lower layer left a symlink must
// replace the link, never write through it.
func TestOverwriteNeverWritesThroughSymlink(t *testing.T) {
	l1 := plain(t, file("real/target", "original"), symlink("etc/shadow", "/real/target"), dir("d/"), file("d/x", "x"), file("f", "f"))
	l2 := plain(t,
		file("etc/shadow", "new"),                       // replaces the symlink
		file("d", "now a file"),                         // file replaces dir
		dir("f/"),                                       // dir replaces file
		file("p/q", "q"), file("p/q/r", "under a file"), // parent is not a dir
		hardlink("h", "missing/target"),
	)
	im, err := extract(t, writeArchive(t, []layer{l1, l2}, archiveOpts{}), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if got := readIn(t, im, "real/target"); got != "original" {
		t.Fatalf("write went through a symlink: real/target = %q", got)
	}
	if fi, _ := im.Root.Lstat("etc/shadow"); fi.Mode()&fs.ModeSymlink != 0 || readIn(t, im, "etc/shadow") != "new" {
		t.Error("symlink not replaced by regular file")
	}
	if fi, _ := im.Root.Lstat("d"); fi.IsDir() {
		t.Error("dir not replaced by file")
	}
	if fi, _ := im.Root.Lstat("f"); !fi.IsDir() {
		t.Error("file not replaced by dir")
	}
	if im.Stats.SkippedOther != 2 || len(im.Warnings) != 2 {
		t.Errorf("want 2 skipped entries with warnings, got %d: %v", im.Stats.SkippedOther, im.Warnings)
	}
}

func TestCaseCollisionReported(t *testing.T) {
	im, err := extract(t, writeArchive(t, []layer{plain(t, file("README", "a"), file("readme", "b"))}, archiveOpts{}), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !caseInsensitive(t.TempDir()) {
		if im.Stats.CaseCollisions != 0 {
			t.Error("collision reported on a case-sensitive filesystem")
		}
		return
	}
	if im.Stats.CaseCollisions != 1 || !strings.Contains(strings.Join(im.Warnings, "\n"), "case collision") {
		t.Errorf("case collision not reported: %+v %v", im.Stats, im.Warnings)
	}
}

func TestBlobDigest(t *testing.T) {
	h := strings.Repeat("a", 64)
	cases := map[string]string{
		"blobs/sha256/" + h: "sha256:" + h,
		h + ".json":         "sha256:" + h,
		"abc/layer.tar":     "",
		"blobs/sha256/xyz":  "",
	}
	for in, want := range cases {
		if got := blobDigest(in); got != want {
			t.Errorf("blobDigest(%q) = %q, want %q", in, got, want)
		}
	}
}
