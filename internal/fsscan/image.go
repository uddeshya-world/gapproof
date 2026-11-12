package fsscan

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
)

// Image is an extracted image (or an opened rootfs) ready for scanning.
type Image struct {
	// Root confines every read to the filesystem. Scanners must open files
	// through it and must not follow symlinks themselves.
	Root *os.Root `json:"-"`
	Dir  string   `json:"-"` // on-disk location of the root

	// Identity. ConfigDigest is the image ID: sha256 of the config JSON,
	// which in turn pins every layer's diff_id (review P1 #8).
	ConfigDigest string `json:"config_digest,omitempty"`
	// ImageID is what the container engine reports as the image ID when the
	// archive is in OCI layout (Docker 25+/containerd store): the top-level
	// index or manifest digest, i.e. the registry digest. Verified against
	// its blob. Empty for legacy archives, where the engine ID is ConfigDigest.
	ImageID      string   `json:"image_id,omitempty"`
	RepoTags     []string `json:"repo_tags,omitempty"`
	OS           string   `json:"os,omitempty"`
	Architecture string   `json:"architecture,omitempty"`

	// Runtime config, for the phone-home rules.
	Env        []string          `json:"env,omitempty"`
	User       string            `json:"user,omitempty"`
	Entrypoint []string          `json:"entrypoint,omitempty"`
	Cmd        []string          `json:"cmd,omitempty"`
	WorkingDir string            `json:"working_dir,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`

	Layers   []Layer  `json:"layers,omitempty"`
	Stats    Stats    `json:"stats"`
	Warnings []string `json:"warnings,omitempty"`

	owned bool // Dir is our temp dir and is removed by Close
}

// Layer is one applied layer.
type Layer struct {
	DiffID string `json:"diff_id"`          // sha256 of the uncompressed tar, verified
	Digest string `json:"digest,omitempty"` // sha256 of the blob as stored, verified when the archive names it
	Size   int64  `json:"size"`
}

// Close releases the root and, for extracted images, deletes the temp dir.
// It is safe to call more than once.
func (im *Image) Close() error {
	if im == nil {
		return nil
	}
	var err error
	if im.Root != nil {
		err = im.Root.Close()
		im.Root = nil
	}
	if im.owned && im.Dir != "" {
		if rerr := os.RemoveAll(im.Dir); rerr != nil && err == nil {
			err = rerr
		}
		im.Dir = ""
	}
	return err
}

// OpenRootFS opens an already-unpacked filesystem. Nothing is copied or
// deleted; reads are still confined to dir.
func OpenRootFS(dir string) (*Image, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &Image{Root: r, Dir: dir}, nil
}

// ExtractImage extracts a `docker save` / `podman save` tarball (Docker or
// OCI layout) into a fresh temp directory, applying layers in order with
// OCI whiteout semantics and verifying the archive's own digests.
// The caller must Close the returned Image.
func ExtractImage(ctx context.Context, archive string, lim Limits) (_ *Image, err error) {
	f, err := os.Open(archive)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	members, err := indexTar(f, lim)
	if err != nil {
		return nil, err
	}
	a := &outer{f: f, members: members, lim: lim}

	refs, err := a.imageRefs()
	if err != nil {
		return nil, err
	}

	cfgRaw, err := a.read(refs.config, lim.MaxMetadataSize)
	if err != nil {
		return nil, fmt.Errorf("image config: %w", err)
	}
	sum := sha256.Sum256(cfgRaw)
	cfgDigest := "sha256:" + hex.EncodeToString(sum[:])
	if want := refs.configDigest; want != "" && want != cfgDigest {
		return nil, &IntegrityError{"image config " + refs.config, want, cfgDigest}
	}
	var cfg imageConfig
	if err := json.Unmarshal(cfgRaw, &cfg); err != nil {
		return nil, fmt.Errorf("image config: %w", err)
	}
	if len(cfg.RootFS.DiffIDs) != len(refs.layers) {
		return nil, &IntegrityError{"layer count", fmt.Sprintf("%d diff_ids in config", len(cfg.RootFS.DiffIDs)), fmt.Sprintf("%d layers in manifest", len(refs.layers))}
	}

	// Everything that can fail before extraction runs before the temp dir
	// exists, so an early error never leaks it (rule 3: remove it on exit).
	imageID, err := a.topDigest()
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "gapproof-rootfs-*")
	if err != nil {
		return nil, err
	}
	im := &Image{
		ImageID:      imageID,
		Dir:          dir,
		owned:        true,
		ConfigDigest: cfgDigest,
		RepoTags:     refs.tags,
		OS:           cfg.OS,
		Architecture: cfg.Architecture,
		Env:          cfg.Config.Env,
		User:         cfg.Config.User,
		Entrypoint:   cfg.Config.Entrypoint,
		Cmd:          cfg.Config.Cmd,
		WorkingDir:   cfg.Config.WorkingDir,
		Labels:       cfg.Config.Labels,
	}
	defer func() {
		if err != nil {
			im.Close()
		}
	}()
	if im.Root, err = os.OpenRoot(dir); err != nil {
		return nil, err
	}

	x := newExtractor(ctx, im.Root, lim, &im.Stats, func(w string) {
		if len(im.Warnings) < maxWarnings {
			im.Warnings = append(im.Warnings, w)
		}
	})
	x.caseInsensitive = caseInsensitive(dir)

	for i, l := range refs.layers {
		m, err := a.member(l.name)
		if err != nil {
			return nil, fmt.Errorf("layer %d: %w", i, err)
		}
		blob := sha256.New()
		sec := io.TeeReader(io.NewSectionReader(f, m.off, m.size), blob)
		diffID, err := x.applyLayer(sec)
		if err != nil {
			return nil, fmt.Errorf("layer %d (%s): %w", i, l.name, err)
		}
		if _, err := io.Copy(io.Discard, sec); err != nil {
			return nil, err
		}
		if want := cfg.RootFS.DiffIDs[i]; want != diffID {
			return nil, &IntegrityError{fmt.Sprintf("layer %d diff_id", i), want, diffID}
		}
		layer := Layer{DiffID: diffID, Size: m.size}
		if l.digest != "" {
			got := "sha256:" + hex.EncodeToString(blob.Sum(nil))
			if got != l.digest {
				return nil, &IntegrityError{fmt.Sprintf("layer %d blob", i), l.digest, got}
			}
			layer.Digest = got
		}
		im.Layers = append(im.Layers, layer)
	}
	return im, nil
}

type imageConfig struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Config       struct {
		Env        []string          `json:"Env"`
		User       string            `json:"User"`
		Entrypoint []string          `json:"Entrypoint"`
		Cmd        []string          `json:"Cmd"`
		WorkingDir string            `json:"WorkingDir"`
		Labels     map[string]string `json:"Labels"`
	} `json:"config"`
	RootFS struct {
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
}

type member struct {
	off, size int64
	link      string // for symlink members (legacy docker save dedupes layers this way)
}

// indexTar records where each member of the outer tar starts, without
// reading member data (tar.Reader seeks over it).
func indexTar(f *os.File, lim Limits) (map[string]member, error) {
	tr := tar.NewReader(f)
	m := map[string]member{}
	for n := 0; ; n++ {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("not a readable tar archive (expected `docker save` output; compressed archives aren't supported): %w", err)
		}
		if n >= lim.MaxOuterMembers {
			return nil, &LimitError{"max archive members", fmt.Sprintf("more than %d members", lim.MaxOuterMembers)}
		}
		name := path.Clean(strings.TrimLeft(hdr.Name, "/"))
		if isSparse(hdr) {
			// Members are read by raw offset; a sparse member's declared size
			// is its expanded size, not what is stored. docker save never
			// writes them.
			return nil, &UnsafePathError{name, "sparse members are not allowed in an image archive"}
		}
		switch hdr.Typeflag {
		case tar.TypeReg:
			off, err := f.Seek(0, io.SeekCurrent)
			if err != nil {
				return nil, err
			}
			m[name] = member{off: off, size: hdr.Size}
		case tar.TypeSymlink:
			m[name] = member{link: path.Join(path.Dir(name), hdr.Linkname)}
		}
	}
	if len(m) == 0 {
		return nil, errors.New("empty archive")
	}
	return m, nil
}

type outer struct {
	f       *os.File
	members map[string]member
	lim     Limits
}

func (a *outer) member(name string) (member, error) {
	name = path.Clean(name)
	for range 8 {
		m, ok := a.members[name]
		if !ok {
			return member{}, fmt.Errorf("archive has no member %q", name)
		}
		if m.link == "" {
			return m, nil
		}
		name = path.Clean(m.link)
	}
	return member{}, fmt.Errorf("member %q: too many symlinks", name)
}

func (a *outer) read(name string, max int64) ([]byte, error) {
	m, err := a.member(name)
	if err != nil {
		return nil, err
	}
	if m.size > max {
		return nil, &LimitError{"max metadata size", fmt.Sprintf("%q is %d bytes (limit %d)", name, m.size, max)}
	}
	return io.ReadAll(io.NewSectionReader(a.f, m.off, m.size))
}

type layerRef struct{ name, digest string }

type imageRefs struct {
	config, configDigest string
	tags                 []string
	layers               []layerRef
}

var digestRe = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// blobDigest returns the digest a member name commits to, if any:
// "blobs/sha256/<hex>" (OCI / Docker 25+) or "<hex>.json" (legacy config).
func blobDigest(name string) string {
	if h, ok := strings.CutPrefix(name, "blobs/sha256/"); ok && digestRe.MatchString("sha256:"+h) {
		return "sha256:" + h
	}
	if h, ok := strings.CutSuffix(path.Base(name), ".json"); ok && digestRe.MatchString("sha256:"+h) {
		return "sha256:" + h
	}
	return ""
}

// imageRefs reads manifest.json (Docker layout), falling back to index.json
// (OCI layout). The archive must hold exactly one image.
func (a *outer) imageRefs() (imageRefs, error) {
	if _, err := a.member("manifest.json"); err == nil {
		raw, err := a.read("manifest.json", a.lim.MaxMetadataSize)
		if err != nil {
			return imageRefs{}, err
		}
		var ms []struct {
			Config   string
			RepoTags []string
			Layers   []string
		}
		if err := json.Unmarshal(raw, &ms); err != nil {
			return imageRefs{}, fmt.Errorf("manifest.json: %w", err)
		}
		if len(ms) != 1 {
			return imageRefs{}, fmt.Errorf("archive contains %d images; save exactly one image per scan", len(ms))
		}
		r := imageRefs{config: ms[0].Config, configDigest: blobDigest(ms[0].Config), tags: ms[0].RepoTags}
		for _, l := range ms[0].Layers {
			d := ""
			if strings.HasPrefix(l, "blobs/") {
				d = blobDigest(l)
			}
			r.layers = append(r.layers, layerRef{name: l, digest: d})
		}
		return r, nil
	}
	return a.ociRefs()
}

type ociDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
}

func (a *outer) blob(d string) ([]byte, error) {
	if !digestRe.MatchString(d) {
		return nil, fmt.Errorf("unsupported digest %q", d)
	}
	raw, err := a.read("blobs/sha256/"+strings.TrimPrefix(d, "sha256:"), a.lim.MaxMetadataSize)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	if got := "sha256:" + hex.EncodeToString(sum[:]); got != d {
		return nil, &IntegrityError{"blob", d, got}
	}
	return raw, nil
}

func (a *outer) ociRefs() (imageRefs, error) {
	raw, err := a.read("index.json", a.lim.MaxMetadataSize)
	if err != nil {
		return imageRefs{}, fmt.Errorf("neither manifest.json nor index.json found (expected `docker save` output): %w", err)
	}
	for range 4 { // follow nested indexes a few levels
		var idx struct{ Manifests []ociDescriptor }
		if err := json.Unmarshal(raw, &idx); err != nil {
			return imageRefs{}, fmt.Errorf("OCI index: %w", err)
		}
		if len(idx.Manifests) != 1 {
			return imageRefs{}, fmt.Errorf("OCI index lists %d manifests; save exactly one single-platform image per scan", len(idx.Manifests))
		}
		body, err := a.blob(idx.Manifests[0].Digest)
		if err != nil {
			return imageRefs{}, err
		}
		var man struct {
			Manifests []ociDescriptor
			Config    ociDescriptor
			Layers    []ociDescriptor
		}
		if err := json.Unmarshal(body, &man); err != nil {
			return imageRefs{}, fmt.Errorf("OCI manifest: %w", err)
		}
		if man.Manifests != nil { // a nested index
			raw = body
			continue
		}
		if !digestRe.MatchString(man.Config.Digest) {
			return imageRefs{}, fmt.Errorf("OCI manifest: bad config digest %q", man.Config.Digest)
		}
		r := imageRefs{config: "blobs/sha256/" + strings.TrimPrefix(man.Config.Digest, "sha256:"), configDigest: man.Config.Digest}
		for _, l := range man.Layers {
			if !digestRe.MatchString(l.Digest) {
				return imageRefs{}, fmt.Errorf("OCI manifest: bad layer digest %q", l.Digest)
			}
			r.layers = append(r.layers, layerRef{name: "blobs/sha256/" + strings.TrimPrefix(l.Digest, "sha256:"), digest: l.Digest})
		}
		return r, nil
	}
	return imageRefs{}, errors.New("OCI index nested too deeply")
}

// topDigest returns the digest index.json points at, verified against its
// blob, or "" when the archive has no (single-entry) index.json.
func (a *outer) topDigest() (string, error) {
	if _, err := a.member("index.json"); err != nil {
		return "", nil
	}
	raw, err := a.read("index.json", a.lim.MaxMetadataSize)
	if err != nil {
		return "", err
	}
	var idx struct{ Manifests []ociDescriptor }
	if err := json.Unmarshal(raw, &idx); err != nil {
		return "", fmt.Errorf("index.json: %w", err)
	}
	if len(idx.Manifests) != 1 {
		return "", nil
	}
	d := idx.Manifests[0].Digest
	if _, err := a.member("blobs/sha256/" + strings.TrimPrefix(d, "sha256:")); err != nil {
		return "", nil // referenced but not shipped: nothing to verify against
	}
	if _, err := a.blob(d); err != nil {
		return "", err
	}
	return d, nil
}

// caseInsensitive reports whether dir lives on a case-insensitive filesystem.
func caseInsensitive(dir string) bool {
	p := path.Join(dir, ".gapproof-CaseProbe")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		return false
	}
	defer os.Remove(p)
	_, err := os.Stat(path.Join(dir, ".gapproof-caseprobe"))
	return err == nil
}

// isSparse reports whether hdr is a GNU sparse member (old GNU type 'S', or
// any PAX GNU.sparse.* record).
func isSparse(hdr *tar.Header) bool {
	if hdr.Typeflag == tar.TypeGNUSparse {
		return true
	}
	for k := range hdr.PAXRecords {
		if strings.HasPrefix(k, "GNU.sparse.") {
			return true
		}
	}
	return false
}
