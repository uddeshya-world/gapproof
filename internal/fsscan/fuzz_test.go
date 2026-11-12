package fsscan

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// FuzzExtractImage feeds fuzzed layers through ExtractImage (M8). Each input
// is two layer blobs wrapped in a valid docker-save archive whose config
// carries their real diff_ids, so both layers are applied and cross-layer
// whiteouts, links and overwrites get exercised. With raw set, the first
// blob is the whole outer archive instead.
//
// Invariants: no panic; no hang (watchdog); bounded allocation; nothing is
// ever created outside the extraction root (the whole fuzz sandbox is walked
// after every input); no device files; and the temp root is gone after
// Close, or after a failed extraction.
func FuzzExtractImage(f *testing.F) {
	t := f
	seeds := [][2][]byte{
		{tarOf(t, dir("app"), file("app/a.txt", "a"), symlink("app/l", "/etc/passwd"), hardlink("app/h", "app/a.txt")),
			tarOf(t, file("app/.wh.a.txt", ""), file("app/.wh..wh..opq", ""), file("app/b", "b"))},
		{tarOf(t, file("../../etc/passwd", "x")), tarOf(t, symlink("esc", "../../.."), file("esc/out", "x"))},
		{tarOf(t, symlink("d", "/"), file("d/tmp/x", "x")), gz(t, tarOf(t, file("big", strings.Repeat("0", 4096))))},
		{tarOf(t, ent{name: "dev", typ: tar.TypeChar}, ent{name: "fifo", typ: tar.TypeFifo}), nil},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1], false)
	}
	f.Add([]byte("not a tar"), []byte(nil), true)

	sandbox := f.TempDir()
	base := filepath.Join(sandbox, "a", "b")
	tmp := filepath.Join(base, "tmp")
	in := filepath.Join(base, "in")
	for _, d := range []string{tmp, in} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			f.Fatal(err)
		}
	}
	f.Setenv("TMPDIR", tmp)
	expected := []string{"a", "a/b", "a/b/in", "a/b/in/image.tar", "a/b/tmp"}

	lim := DefaultLimits()
	lim.MaxEntries = 2000
	lim.MaxFileSize = 1 << 20
	lim.MaxTotalSize = 4 << 20
	lim.RatioFloor = 256 << 10
	lim.MaxMetadataSize = 1 << 20
	lim.MaxOuterMembers = 100

	f.Fuzz(func(t *testing.T, l1, l2 []byte, raw bool) {
		archive := l1
		if !raw {
			archive = dockerSave(t, l1, l2)
		}
		p := filepath.Join(in, "image.tar")
		if err := os.WriteFile(p, archive, 0o644); err != nil {
			t.Fatal(err)
		}

		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		watchdog := time.AfterFunc(20*time.Second, func() {
			panic(fmt.Sprintf("hang: extracting a %d-byte archive took longer than 20s", len(archive)))
		})
		im, err := ExtractImage(context.Background(), p, lim)
		watchdog.Stop()
		runtime.ReadMemStats(&after)
		if got, budget := after.TotalAlloc-before.TotalAlloc, uint64(64<<20+64*len(archive)); got > budget {
			t.Errorf("extracting a %d-byte archive allocated %d bytes (budget %d)", len(archive), got, budget)
		}

		if err == nil {
			if !strings.HasPrefix(im.Dir, tmp+string(filepath.Separator)) {
				t.Errorf("root %s is not under TMPDIR", im.Dir)
			}
			// No device files, and every entry is inside the root.
			werr := filepath.WalkDir(im.Dir, func(q string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.Type()&(fs.ModeDevice|fs.ModeCharDevice|fs.ModeNamedPipe|fs.ModeSocket) != 0 {
					t.Errorf("special file extracted: %s (%v)", q, d.Type())
				}
				return nil
			})
			if werr != nil {
				t.Errorf("walking the root: %v", werr)
			}
			// Nothing landed beside the root.
			sandboxEntries(t, sandbox, im.Dir, expected)
			if err := im.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		}
		// After success+Close or after an error: the sandbox is exactly as it
		// was, including an empty TMPDIR (no leaked temp root).
		sandboxEntries(t, sandbox, "", expected)
	})
}

// sandboxEntries asserts that sandbox holds exactly want (slash paths),
// ignoring everything under skip.
func sandboxEntries(t *testing.T, sandbox, skip string, want []string) {
	t.Helper()
	var got []string
	err := filepath.WalkDir(sandbox, func(q string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if q == sandbox {
			return nil
		}
		if skip != "" && q == skip {
			return filepath.SkipDir
		}
		rel, _ := filepath.Rel(sandbox, q)
		got = append(got, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatalf("walking the sandbox: %v", err)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("sandbox changed: got %v, want %v", got, want)
	}
}

// dockerSave wraps two layer blobs in a legacy docker-save archive whose
// config lists their real diff_ids.
func dockerSave(t *testing.T, layers ...[]byte) []byte {
	var members []ent
	var names, diffIDs []string
	for i, l := range layers {
		name := fmt.Sprintf("l%d/layer.tar", i)
		members = append(members, file(name, string(l)))
		names = append(names, name)
		diffIDs = append(diffIDs, fuzzDiffID(l))
	}
	cfg, _ := json.Marshal(map[string]any{"os": "linux", "rootfs": map[string]any{"type": "layers", "diff_ids": diffIDs}})
	man, _ := json.Marshal([]any{map[string]any{"Config": "config.json", "Layers": names}})
	members = append(members, file("config.json", string(cfg)), file("manifest.json", string(man)))
	return tarOf(t, members...)
}

// fuzzDiffID hashes what applyLayer would hash: the whole decompressed
// stream. Undecodable blobs get whatever prefix decoded; extraction fails on
// them anyway.
func fuzzDiffID(blob []byte) string {
	br := bufio.NewReader(bytes.NewReader(blob))
	magic, _ := br.Peek(6)
	var r io.Reader = br
	switch {
	case bytes.HasPrefix(magic, []byte{0x1f, 0x8b}):
		gz, err := gzip.NewReader(br)
		if err != nil {
			return "sha256:" + strings.Repeat("0", 64)
		}
		r = gz
	case bytes.HasPrefix(magic, []byte("BZh")):
		r = bzip2.NewReader(br)
	}
	h := sha256.New()
	io.Copy(h, io.LimitReader(r, 8<<20))
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
