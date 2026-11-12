package fsscan

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// ErrConfigMismatch is returned by VerifyImageIdentity when the archive's
// config digest is not the expected one. No layer has been read.
var ErrConfigMismatch = errors.New("image config digest mismatch")

// VerifyImageIdentity checks that an image archive is the image whose config
// digest is want, without extracting anything to disk. It returns the
// archive's config digest.
//
// The config digest is computed and compared first: on a mismatch it returns
// ErrConfigMismatch before any layer is touched. Otherwise every layer is
// decompressed (gzip, bzip2, or none) and only hashed, as a stream, to check
// its diff_id against the config (and its blob digest where the archive
// names one), so a layer swapped under an unchanged config is caught. Layer
// contents (sparse members, huge files) never reach the filesystem; the
// decompression ratio limit still applies to compressed layers. If want is
// "", the layers are checked against whatever config the archive carries.
func VerifyImageIdentity(ctx context.Context, archive, want string, lim Limits) (string, error) {
	f, err := os.Open(archive)
	if err != nil {
		return "", err
	}
	defer f.Close()

	members, err := indexTar(f, lim)
	if err != nil {
		return "", err
	}
	a := &outer{f: f, members: members, lim: lim}
	refs, err := a.imageRefs()
	if err != nil {
		return "", err
	}
	cfgRaw, err := a.read(refs.config, lim.MaxMetadataSize)
	if err != nil {
		return "", fmt.Errorf("image config: %w", err)
	}
	sum := sha256.Sum256(cfgRaw)
	cfgDigest := "sha256:" + hex.EncodeToString(sum[:])
	if r := refs.configDigest; r != "" && r != cfgDigest {
		return "", &IntegrityError{"image config " + refs.config, r, cfgDigest}
	}
	if want != "" && cfgDigest != want {
		return cfgDigest, fmt.Errorf("%w: want %s, archive has %s", ErrConfigMismatch, want, cfgDigest)
	}

	var cfg imageConfig
	if err := json.Unmarshal(cfgRaw, &cfg); err != nil {
		return "", fmt.Errorf("image config: %w", err)
	}
	if len(cfg.RootFS.DiffIDs) != len(refs.layers) {
		return "", &IntegrityError{"layer count", fmt.Sprintf("%d diff_ids in config", len(cfg.RootFS.DiffIDs)), fmt.Sprintf("%d layers in manifest", len(refs.layers))}
	}
	for i, l := range refs.layers {
		m, err := a.member(l.name)
		if err != nil {
			return "", fmt.Errorf("layer %d: %w", i, err)
		}
		blob := sha256.New()
		sec := io.TeeReader(&ctxReader{ctx: ctx, r: io.NewSectionReader(f, m.off, m.size)}, blob)
		diffID, err := hashLayer(sec, lim)
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return "", cerr
			}
			return "", fmt.Errorf("layer %d (%s): %w", i, l.name, err)
		}
		if _, err := io.Copy(io.Discard, sec); err != nil {
			return "", err
		}
		if w := cfg.RootFS.DiffIDs[i]; w != diffID {
			return "", &IntegrityError{fmt.Sprintf("layer %d diff_id", i), w, diffID}
		}
		if l.digest != "" {
			if got := "sha256:" + hex.EncodeToString(blob.Sum(nil)); got != l.digest {
				return "", &IntegrityError{fmt.Sprintf("layer %d blob", i), l.digest, got}
			}
		}
	}
	return cfgDigest, nil
}

// hashLayer returns the diff_id (sha256 of the uncompressed stream) of one
// layer blob. The tar inside is never parsed.
func hashLayer(raw io.Reader, lim Limits) (string, error) {
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
	h := sha256.New()
	if _, err := io.Copy(h, &ratioReader{r: dr, compressed: compressed, check: isCompressed, lim: lim}); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// ctxReader stops a long stream when ctx is cancelled.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}
