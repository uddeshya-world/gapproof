package fsscan

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Regression (M8): a bad index.json next to manifest.json made ExtractImage
// fail after creating its temp root, leaking it.
func TestFailedExtractionLeavesNoTempDir(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	l := plain(t, file("a", "a"))
	good := writeArchive(t, []layer{l}, archiveOpts{})
	raw, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}
	// Append an index.json naming a blob whose content doesn't match.
	var members []ent
	tr := readTar(t, raw)
	for name, body := range tr {
		members = append(members, file(name, body))
	}
	bad := "sha256:" + strings.Repeat("a", 64)
	members = append(members,
		file("blobs/sha256/"+strings.Repeat("a", 64), "not the blob"),
		file("index.json", `{"manifests":[{"digest":"`+bad+`"}]}`))
	p := t.TempDir() + "/image.tar"
	if err := os.WriteFile(p, tarOf(t, members...), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = ExtractImage(context.Background(), p, DefaultLimits())
	var ie *IntegrityError
	if !errors.As(err, &ie) {
		t.Fatalf("want IntegrityError, got %v", err)
	}
	ents, _ := os.ReadDir(tmp)
	if len(ents) != 0 {
		t.Fatalf("temp dir leaked: %v", ents)
	}
}

// Regression (M8): each opaque whiteout re-listed the whole tree below it,
// so a layer of N opaque whiteouts over N files cost O(N²) directory reads.
func TestRepeatedOpaqueWhiteoutsAreLinear(t *testing.T) {
	const n = 500
	var lower, upper []ent
	for i := range n {
		lower = append(lower, file(fmt.Sprintf("d/old%d", i), "x"))
	}
	for i := range n {
		upper = append(upper, file(fmt.Sprintf("d/sub/new%d", i), "y"), file("d/.wh..wh..opq", ""), file("d/sub/.wh..wh..opq", ""))
	}
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var st Stats
	x := newExtractor(context.Background(), root, DefaultLimits(), &st, nil)
	for _, l := range [][]ent{lower, upper} {
		if _, err := x.applyLayer(bytes.NewReader(tarOf(t, l...))); err != nil {
			t.Fatal(err)
		}
	}
	if x.pruneReads > 4 {
		t.Fatalf("%d directory reads for %d opaque whiteouts; want a constant", x.pruneReads, 2*n)
	}
	ents, err := fs.ReadDir(root.FS(), "d")
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Name() != "sub" {
		t.Fatalf("lower files not hidden: %d entries in d", len(ents))
	}
	subs, _ := fs.ReadDir(root.FS(), "d/sub")
	if len(subs) != n {
		t.Fatalf("want %d new files kept, got %d", n, len(subs))
	}
}

// readTar returns the regular members of a tar as name -> body.
func readTar(t *testing.T, b []byte) map[string]string {
	t.Helper()
	out := map[string]string{}
	tr := tar.NewReader(bytes.NewReader(b))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		out[h.Name] = string(body)
	}
}

// Regression (M8): a PAX GNU sparse 1.0 member expands on read; extraction
// must reject it rather than write (or silently skip) it.
func TestSparseMemberRejected(t *testing.T) {
	rec := func(k, v string) string {
		body := " " + k + "=" + v + "\n"
		n := len(body) + 1
		for len(fmt.Sprint(n))+len(body) != n {
			n++
		}
		return fmt.Sprint(n) + body
	}
	const realSize = 64 << 20
	pax := rec("GNU.sparse.major", "1") + rec("GNU.sparse.minor", "0") +
		rec("GNU.sparse.name", "big") + rec("GNU.sparse.realsize", fmt.Sprint(realSize))
	data := []byte(fmt.Sprintf("1\n%d\n0\n", realSize))
	data = append(data, make([]byte, 512-len(data))...)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Name: "PaxHeaders/big", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(pax)), Format: tar.FormatUSTAR})
	tw.Write([]byte(pax))
	tw.WriteHeader(&tar.Header{Name: "GNUSparseFile.0/big", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(data)), Format: tar.FormatUSTAR})
	tw.Write(data)
	tw.Close()
	raw := buf.Bytes()
	raw[156] = tar.TypeXHeader // retype the first block as a PAX header
	copy(raw[148:156], "        ")
	sum := 0
	for _, c := range raw[:512] {
		sum += int(c)
	}
	copy(raw[148:156], fmt.Sprintf("%06o\x00 ", sum))

	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var st Stats
	x := newExtractor(context.Background(), root, DefaultLimits(), &st, nil)
	_, err = x.applyLayer(bytes.NewReader(raw))
	var up *UnsafePathError
	if !errors.As(err, &up) || !strings.Contains(err.Error(), "sparse") {
		t.Fatalf("err = %v, want sparse rejection", err)
	}
	if _, err := root.Stat("big"); err == nil {
		t.Fatal("sparse member was written to disk")
	}
}

// Regression (demo): Docker's index.json can list several entries
// (attestation manifests, older builds of the same tag). Every entry pinned
// to the scanned config is an acceptable engine ID; an entry for another
// config never is, even when it is the only one.
func TestIndexEntriesPinnedToConfig(t *testing.T) {
	good := writeArchive(t, []layer{plain(t, file("a", "a"))}, archiveOpts{})
	raw, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}
	tr := readTar(t, raw)
	var cfgDigest string
	for name, body := range tr {
		if strings.HasPrefix(name, "blobs/sha256/") && strings.Contains(body, `"rootfs"`) {
			cfgDigest = digest([]byte(body))
		}
	}
	blob := func(m map[string]any) (string, ent) {
		b, _ := json.Marshal(m)
		d := digest(b)
		return d, file("blobs/sha256/"+strings.TrimPrefix(d, "sha256:"), string(b))
	}
	other := "sha256:" + strings.Repeat("b", 64)
	manD, manE := blob(map[string]any{"config": map[string]any{"digest": cfgDigest}})
	attD, attE := blob(map[string]any{"config": map[string]any{"digest": other}})
	idxD, idxE := blob(map[string]any{"manifests": []any{map[string]any{"digest": manD}, map[string]any{"digest": attD}}})
	strayD, strayE := blob(map[string]any{"config": map[string]any{"digest": other}})

	build := func(index ...string) *Image {
		t.Helper()
		var members []ent
		for name, body := range tr {
			members = append(members, file(name, body))
		}
		var ms []any
		for _, d := range index {
			ms = append(ms, map[string]any{"digest": d})
		}
		ij, _ := json.Marshal(map[string]any{"manifests": ms})
		members = append(members, manE, attE, idxE, strayE, file("index.json", string(ij)))
		p := filepath.Join(t.TempDir(), "image.tar")
		if err := os.WriteFile(p, tarOf(t, members...), 0o644); err != nil {
			t.Fatal(err)
		}
		im, err := extract(t, p, DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		return im
	}

	im := build(strayD, idxD, manD)
	if im.ImageID != idxD || !slices.Equal(im.AltImageIDs, []string{idxD, manD}) {
		t.Errorf("ImageID=%s alt=%v; want %s then %s, never the stray entry", im.ImageID, im.AltImageIDs, idxD, manD)
	}
	if im := build(strayD); im.ImageID != "" || len(im.AltImageIDs) != 0 {
		t.Errorf("single entry for another config accepted: %s %v", im.ImageID, im.AltImageIDs)
	}
}
