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
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
)

// Stats describe what extraction did. They go into the run metadata.
type Stats struct {
	Entries        int   `json:"entries"`
	Files          int   `json:"files"`
	Dirs           int   `json:"dirs"`
	Symlinks       int   `json:"symlinks"`
	Hardlinks      int   `json:"hardlinks"`
	Whiteouts      int   `json:"whiteouts"`
	BytesWritten   int64 `json:"bytes_written"`
	SkippedDevices int   `json:"skipped_devices"`
	SkippedOther   int   `json:"skipped_other"`
	CaseCollisions int   `json:"case_collisions"`
}

const maxSymlinkHops = 40
const maxWarnings = 100

// extractor applies layers, in order, into one root.
type extractor struct {
	ctx   context.Context
	root  *os.Root
	lim   Limits
	stats *Stats
	warn  func(string)

	// Paths created by the layer being applied, and their ancestors. OCI:
	// whiteouts only hide content from lower layers.
	current   map[string]bool
	ancestors map[string]bool
	// Directories already pruned of lower-layer content in this layer.
	// After a prune only current-layer entries remain below, so pruning the
	// same tree again is a no-op; skipping it keeps a layer of many opaque
	// whiteouts linear instead of quadratic.
	pruned     map[string]bool
	pruneReads int // directories listed while pruning (for tests)

	caseInsensitive bool
	caseSeen        map[string]string // lower(path) -> path, on case-insensitive filesystems
}

func newExtractor(ctx context.Context, root *os.Root, lim Limits, st *Stats, warn func(string)) *extractor {
	return &extractor{ctx: ctx, root: root, lim: lim, stats: st, warn: warn, caseSeen: map[string]string{}}
}

// applyLayer streams one layer blob (tar, tar+gzip or tar+bzip2) into the
// root and returns the sha256 of the uncompressed tar stream (the diff_id).
func (x *extractor) applyLayer(raw io.Reader) (diffID string, err error) {
	compressed := &countReader{r: raw}
	br := bufio.NewReaderSize(compressed, 64<<10)
	magic, _ := br.Peek(6)

	var dr io.Reader = br
	isCompressed := true
	switch {
	case bytes.HasPrefix(magic, []byte{0x1f, 0x8b}):
		gz, err := gzip.NewReader(br)
		if err != nil {
			return "", fmt.Errorf("layer: bad gzip stream: %w", err)
		}
		defer gz.Close()
		dr = gz
	case bytes.HasPrefix(magic, []byte("BZh")):
		dr = bzip2.NewReader(br)
	case bytes.HasPrefix(magic, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		return "", errors.New("layer: zstd-compressed layers are not supported yet (re-save the image with gzip or uncompressed layers)")
	case bytes.HasPrefix(magic, []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}):
		return "", errors.New("layer: xz-compressed layers are not supported yet")
	default:
		isCompressed = false
	}

	diff := sha256.New()
	ur := &ratioReader{r: dr, compressed: compressed, check: isCompressed, lim: x.lim}
	tee := io.TeeReader(ur, diff)
	tr := tar.NewReader(tee)

	x.current = map[string]bool{}
	x.ancestors = map[string]bool{}
	x.pruned = map[string]bool{}
	for {
		if err := x.ctx.Err(); err != nil {
			return "", err
		}
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			var le *LimitError
			if errors.As(err, &le) {
				return "", le
			}
			return "", fmt.Errorf("layer: reading tar: %w", err)
		}
		x.stats.Entries++
		if x.stats.Entries > x.lim.MaxEntries {
			return "", &LimitError{"max entries", fmt.Sprintf("more than %d archive entries", x.lim.MaxEntries)}
		}
		if err := x.entry(hdr, tr); err != nil {
			return "", err
		}
	}
	// Hash the trailing zero blocks too, so the digest covers the whole stream.
	if _, err := io.Copy(io.Discard, tee); err != nil {
		return "", fmt.Errorf("layer: reading trailer: %w", err)
	}
	return "sha256:" + hex.EncodeToString(diff.Sum(nil)), nil
}

// entry applies one tar header.
func (x *extractor) entry(hdr *tar.Header, r io.Reader) error {
	name, err := cleanEntryName(hdr.Name)
	if err != nil {
		return err
	}
	if name == "." {
		return nil // the root itself
	}
	dir, base := path.Split(name)
	dir = strings.TrimSuffix(dir, "/")

	// OCI whiteouts.
	if base == ".wh..wh..opq" {
		d, err := x.resolve(dir, true)
		if err != nil {
			return err
		}
		x.stats.Whiteouts++
		return x.pruneOnce(d)
	}
	if victim, ok := strings.CutPrefix(base, ".wh."); ok {
		if victim == "" || victim == "." || victim == ".." {
			return &UnsafePathError{hdr.Name, "malformed whiteout"}
		}
		d, err := x.resolve(dir, true)
		if err != nil {
			return err
		}
		x.stats.Whiteouts++
		return x.whiteout(join(d, victim))
	}

	parent, err := x.resolve(dir, true)
	if err != nil {
		return err
	}
	if parent != "" {
		if fi, err := x.root.Lstat(parent); err == nil && !fi.IsDir() {
			x.warnf("skipped %q: parent %q is not a directory in the image", name, parent)
			x.stats.SkippedOther++
			return nil
		}
		if err := x.root.MkdirAll(parent, 0o755); err != nil {
			return fmt.Errorf("creating %q: %w", parent, err)
		}
	}
	target := join(parent, base)

	switch hdr.Typeflag {
	case tar.TypeDir:
		if fi, err := x.root.Lstat(target); err == nil && !fi.IsDir() {
			if err := x.root.RemoveAll(target); err != nil {
				return err
			}
		}
		if err := x.root.MkdirAll(target, dirPerm(hdr.Mode)); err != nil {
			return fmt.Errorf("creating dir %q: %w", target, err)
		}
		x.stats.Dirs++

	case tar.TypeReg:
		if hdr.Size > x.lim.MaxFileSize {
			return &LimitError{"max file size", fmt.Sprintf("%q is %d bytes (limit %d)", name, hdr.Size, x.lim.MaxFileSize)}
		}
		if err := x.clear(target); err != nil {
			return err
		}
		// O_EXCL: never write through a symlink or into an existing file.
		f, err := x.root.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, filePerm(hdr.Mode))
		if err != nil {
			return fmt.Errorf("creating %q: %w", target, err)
		}
		n, err := io.Copy(f, io.LimitReader(r, hdr.Size))
		cerr := f.Close()
		if err != nil {
			var le *LimitError
			if errors.As(err, &le) {
				return le
			}
			return fmt.Errorf("writing %q: %w", target, err)
		}
		if cerr != nil {
			return cerr
		}
		x.stats.BytesWritten += n
		if x.stats.BytesWritten > x.lim.MaxTotalSize {
			return &LimitError{"max total size", fmt.Sprintf("more than %d bytes extracted", x.lim.MaxTotalSize)}
		}
		x.stats.Files++

	case tar.TypeSymlink:
		if err := x.clear(target); err != nil {
			return err
		}
		// The link text is stored as-is; it is never followed outside x.resolve.
		if err := x.root.Symlink(hdr.Linkname, target); err != nil {
			return fmt.Errorf("symlink %q: %w", target, err)
		}
		x.stats.Symlinks++

	case tar.TypeLink:
		ln, err := cleanEntryName(hdr.Linkname)
		if err != nil {
			return err
		}
		ld, lb := path.Split(ln)
		lp, err := x.resolve(strings.TrimSuffix(ld, "/"), true)
		if err != nil {
			return err
		}
		src := join(lp, lb)
		fi, err := x.root.Lstat(src)
		if err != nil || fi.IsDir() {
			x.warnf("skipped hardlink %q -> %q: target missing or a directory", name, hdr.Linkname)
			x.stats.SkippedOther++
			return nil
		}
		if err := x.clear(target); err != nil {
			return err
		}
		if err := x.root.Link(src, target); err != nil {
			return fmt.Errorf("hardlink %q: %w", target, err)
		}
		x.stats.Hardlinks++

	case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
		x.stats.SkippedDevices++ // rule 3: never create device files
		return nil

	case tar.TypeXGlobalHeader:
		return nil

	default:
		x.stats.SkippedOther++
		return nil
	}

	x.markCurrent(target)
	x.checkCase(target)
	return nil
}

// resolve maps an in-image path to a symlink-free path under the root,
// following symlinks with chroot semantics: absolute targets restart at the
// image root, and ".." never climbs above it. Components that don't exist
// yet are kept as-is. "" means the root.
func (x *extractor) resolve(rel string, followLast bool) (string, error) {
	parts := splitPath(rel)
	var cur []string
	hops := 0
	for len(parts) > 0 {
		p := parts[0]
		parts = parts[1:]
		switch p {
		case "", ".":
			continue
		case "..":
			if len(cur) > 0 {
				cur = cur[:len(cur)-1]
			}
			continue
		}
		next := strings.Join(append(cur[:len(cur):len(cur)], p), "/")
		if len(parts) == 0 && !followLast {
			cur = append(cur, p)
			break
		}
		fi, err := x.root.Lstat(next)
		if errors.Is(err, fs.ErrNotExist) {
			cur = append(cur, p)
			continue
		}
		if err != nil {
			return "", fmt.Errorf("resolving %q: %w", rel, err)
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			cur = append(cur, p)
			continue
		}
		hops++
		if hops > maxSymlinkHops {
			return "", &UnsafePathError{rel, "too many levels of symbolic links"}
		}
		target, err := x.root.Readlink(next)
		if err != nil {
			return "", err
		}
		if path.IsAbs(target) {
			cur = cur[:0]
		}
		parts = append(splitPath(target), parts...)
	}
	return strings.Join(cur, "/"), nil
}

// whiteout removes p as seen from lower layers.
func (x *extractor) whiteout(p string) error {
	if x.current[p] && !x.ancestors[p] {
		return nil // created in this same layer: a whiteout doesn't apply to it
	}
	if x.ancestors[p] {
		return x.pruneOnce(p)
	}
	if err := x.root.RemoveAll(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("whiteout %q: %w", p, err)
	}
	return nil
}

// pruneOnce prunes dir unless it, or a directory above it, was already
// pruned in this layer.
func (x *extractor) pruneOnce(dir string) error {
	for p := dir; ; p = path.Dir(p) {
		if p == "." {
			p = ""
		}
		if x.pruned[p] {
			return nil
		}
		if p == "" {
			break
		}
	}
	if err := x.pruneLower(dir); err != nil {
		return err
	}
	x.pruned[dir] = true
	return nil
}

// pruneLower removes everything under dir that the current layer didn't create.
func (x *extractor) pruneLower(dir string) error {
	d := dir
	if d == "" {
		d = "."
	}
	x.pruneReads++
	f, err := x.root.Open(d)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	ents, err := f.ReadDir(-1)
	f.Close()
	if err != nil {
		return nil // not a directory: nothing to prune
	}
	for _, e := range ents {
		cp := join(dir, e.Name())
		switch {
		case e.IsDir() && (x.current[cp] || x.ancestors[cp]):
			if err := x.pruneLower(cp); err != nil {
				return err
			}
		case x.current[cp]:
			// keep
		default:
			if err := x.root.RemoveAll(cp); err != nil {
				return err
			}
		}
	}
	return nil
}

// clear removes whatever is at p (file, symlink or directory) before a write.
func (x *extractor) clear(p string) error {
	fi, err := x.root.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return x.root.RemoveAll(p)
	}
	return x.root.Remove(p)
}

func (x *extractor) markCurrent(p string) {
	x.current[p] = true
	for d := path.Dir(p); d != "." && d != "/" && d != ""; d = path.Dir(d) {
		x.ancestors[d] = true
	}
}

// checkCase records paths that collide on a case-insensitive host filesystem
// (macOS default). Linux images can contain both "A" and "a".
func (x *extractor) checkCase(p string) {
	if !x.caseInsensitive {
		return
	}
	k := strings.ToLower(p)
	if prev, ok := x.caseSeen[k]; ok && prev != p {
		x.stats.CaseCollisions++
		x.warnf("case collision on this host filesystem: %q and %q (extract on a case-sensitive filesystem for a complete scan)", prev, p)
	}
	x.caseSeen[k] = p
}

func (x *extractor) warnf(format string, a ...any) {
	if x.warn != nil {
		x.warn(fmt.Sprintf(format, a...))
	}
}

// cleanEntryName normalises a tar entry name to a clean relative path and
// rejects anything that would climb out of the root. Absolute names are
// treated as rooted in the image, as Docker does.
func cleanEntryName(name string) (string, error) {
	if strings.ContainsRune(name, 0) {
		return "", &UnsafePathError{name, "NUL byte in name"}
	}
	n := strings.TrimLeft(name, "/")
	c := path.Clean(n)
	if c == ".." || strings.HasPrefix(c, "../") {
		return "", &UnsafePathError{name, "path traversal outside the image root"}
	}
	if c == "" {
		c = "."
	}
	return c, nil
}

func splitPath(p string) []string {
	var out []string
	for s := range strings.SplitSeq(p, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func join(dir, base string) string {
	if dir == "" || dir == "." {
		return base
	}
	return dir + "/" + base
}

func filePerm(mode int64) fs.FileMode { return fs.FileMode(mode)&0o777 | 0o600 }
func dirPerm(mode int64) fs.FileMode  { return fs.FileMode(mode)&0o777 | 0o700 }

// countReader counts bytes read through it.
type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// ratioReader aborts a decompression bomb: once more than RatioFloor bytes
// have been decompressed, decompressed/compressed may not exceed MaxRatio.
type ratioReader struct {
	r          io.Reader
	compressed *countReader
	check      bool
	lim        Limits
	n          int64
}

func (r *ratioReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.n += int64(n)
	if r.check && r.n > r.lim.RatioFloor && r.compressed.n > 0 {
		if ratio := float64(r.n) / float64(r.compressed.n); ratio > r.lim.MaxRatio {
			return n, &LimitError{"max decompression ratio", fmt.Sprintf(
				"layer decompressed to %d bytes from %d (ratio %.0f > %.0f): possible decompression bomb",
				r.n, r.compressed.n, ratio, r.lim.MaxRatio)}
		}
	}
	return n, err
}
