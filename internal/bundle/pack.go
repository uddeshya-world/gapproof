package bundle

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Pack writes every file of dir (including MANIFEST.sha256 and MANIFEST.sig)
// into a deterministic tar at out: regular files only, sorted by path, no
// directory entries, mode 0644, owner 0:0, mtime 1970-01-01. The same
// directory always gives byte-identical tar bytes. out must not be inside
// dir. The tar is written to a temp file and renamed into place.
func Pack(dir, out string) error {
	if inside, err := within(dir, out); err != nil {
		return err
	} else if inside {
		return fmt.Errorf("bundle %s must not be inside the evidence directory %s", out, dir)
	}
	files, err := hashTree(dir) // also refuses symlinks and special files
	if err != nil {
		return err
	}
	names := make([]string, 0, len(files)+2)
	for p := range files {
		names = append(names, p)
	}
	for _, r := range []string{ManifestName, SignatureName} {
		if _, err := os.Lstat(filepath.Join(dir, r)); err == nil {
			names = append(names, r)
		}
	}
	slices.Sort(names)

	tmp, err := os.CreateTemp(filepath.Dir(out), ".gapproof-bundle-*.tar")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	tw := tar.NewWriter(tmp)
	for _, n := range names {
		if err := addFile(tw, filepath.Join(dir, filepath.FromSlash(n)), n); err != nil {
			tmp.Close()
			return err
		}
	}
	if err := tw.Close(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), out)
}

func addFile(tw *tar.Writer, src, name string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", name)
	}
	hdr := &tar.Header{
		Typeflag: tar.TypeReg,
		Name:     name,
		Size:     fi.Size(),
		Mode:     0o644,
		ModTime:  time.Unix(0, 0).UTC(),
		Format:   tar.FormatPAX, // long names are representable; no atime/ctime are written
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	n, err := io.Copy(tw, f)
	if err != nil {
		return err
	}
	if n != fi.Size() {
		return fmt.Errorf("%s changed size while packing", name)
	}
	return nil
}

// within reports whether p is dir itself or below it.
func within(dir, p string) (bool, error) {
	ad, err := filepath.Abs(dir)
	if err != nil {
		return false, err
	}
	ap, err := filepath.Abs(p)
	if err != nil {
		return false, err
	}
	rel, err := filepath.Rel(ad, ap)
	if err != nil {
		return false, nil
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))), nil
}
