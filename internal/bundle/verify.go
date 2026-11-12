package bundle

import (
	"archive/tar"
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"

	"github.com/uddeshya-world/gapproof/internal/fsscan"
)

// ErrVerification wraps every reason a bundle fails to verify (tampering,
// a wrong key, a malformed or hostile tar, an artifact mismatch). Other
// errors (an unreadable bundle path, say) are operational, not a verdict.
var ErrVerification = errors.New("verification failed")

// ErrArtifactMismatch is returned (wrapped in ErrVerification) when the
// bundle verifies but --artifact is not the image that was scanned.
var ErrArtifactMismatch = errors.New("artifact digest mismatch")

// ArtifactStatus is the outcome of the --artifact check.
type ArtifactStatus string

const (
	ArtifactNotChecked ArtifactStatus = "not-checked"
	ArtifactMatch      ArtifactStatus = "match"
	ArtifactMismatch   ArtifactStatus = "mismatch"
)

// Result describes a verified bundle. The level comes from summary.json,
// which the signature covers; the signer comes from the --pub key that
// verified the signature (never from the bundle's own claim).
type Result struct {
	Level            string         // e.g. "AGR-4" or "unassessed"; "" if the bundle has no summary.json level
	Signer           string         // fingerprint of the verifying public key
	Files            int            // files covered by the manifest
	RecordedArtifact string         // config digest in the manifest, "" if none
	Artifact         ArtifactStatus // outcome of the --artifact check
	ArtifactDigest   string         // config digest computed from --artifact, if checked
}

// String is the one-line verdict, e.g.
// "AGR-4 · signed by ed25519:3f9a0c1d2e3f4a5b · artifact digest matches".
func (r Result) String() string {
	level := r.Level
	if level == "" {
		level = "AGR level not recorded"
	}
	art := "artifact digest not checked"
	switch r.Artifact {
	case ArtifactMatch:
		art = "artifact digest matches"
	case ArtifactMismatch:
		art = "artifact digest MISMATCH"
	}
	return level + " · signed by " + r.Signer + " · " + art
}

// limits bound what a hostile bundle can make Verify do. Nothing is ever
// written to disk: every member is hashed while it streams past.
type limits struct {
	maxEntries  int
	maxFileSize int64
	maxTotal    int64
	maxSmall    int64 // manifest, signature, summary.json are kept in memory
}

var defaultLimits = limits{
	maxEntries:  100_000,
	maxFileSize: 64 << 30,
	maxTotal:    256 << 30,
	maxSmall:    64 << 20,
}

var levelRe = regexp.MustCompile(`^(unassessed|AGR-[0-4])$`)

func failf(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrVerification, fmt.Sprintf(format, a...))
}

// Verify checks a bundle tar fully offline: safe tar reading, the Ed25519
// signature over MANIFEST.sha256 against pub, every file's SHA-256, no
// missing and no unlisted files, and, if artifactTar is not empty, that the
// image tar's config digest equals the one the manifest records.
//
// On ErrArtifactMismatch the returned Result is complete (the bundle itself
// verified), so callers can still print the verdict line.
func Verify(ctx context.Context, bundlePath string, pub ed25519.PublicKey, artifactTar string) (Result, error) {
	return verify(ctx, bundlePath, pub, artifactTar, defaultLimits)
}

func verify(ctx context.Context, bundlePath string, pub ed25519.PublicKey, artifactTar string, lim limits) (Result, error) {
	res := Result{Artifact: ArtifactNotChecked}
	if len(pub) != ed25519.PublicKeySize {
		return res, fmt.Errorf("%w: public key has the wrong size", ErrKey)
	}
	if err := checkPublicKey(pub); err != nil {
		return res, err
	}
	f, err := os.Open(bundlePath)
	if err != nil {
		return res, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return res, err
	}
	if !fi.Mode().IsRegular() {
		return res, fmt.Errorf("%s is not a regular file", bundlePath)
	}

	b, err := readBundle(ctx, f, fi.Size(), pub, lim)
	if err != nil {
		return res, err
	}
	m := b.manifest
	res.Signer = Fingerprint(pub)
	res.Files = len(m.Files)
	res.RecordedArtifact = m.Artifact

	if b.summary != nil {
		var s struct {
			AGR struct {
				Level string `json:"level"`
			} `json:"agr"`
		}
		if json.Unmarshal(b.summary, &s) == nil && s.AGR.Level != "" {
			res.Level = s.AGR.Level
			if !levelRe.MatchString(res.Level) {
				res.Level = "unrecognised AGR level"
			}
		}
	}

	if artifactTar == "" {
		return res, nil
	}
	if m.Artifact == "" {
		res.Artifact = ArtifactMismatch
		return res, fmt.Errorf("%w: %w: the bundle records no artifact digest (the scan had no image)", ErrVerification, ErrArtifactMismatch)
	}
	// The config digest is compared before any layer is read, and layers are
	// only hashed as they stream: nothing from --artifact is written to disk.
	got, err := fsscan.VerifyImageIdentity(ctx, artifactTar, m.Artifact, fsscan.DefaultLimits())
	switch {
	case errors.Is(err, fsscan.ErrConfigMismatch):
		res.Artifact = ArtifactMismatch
		res.ArtifactDigest = got
		return res, fmt.Errorf("%w: %w: bundle records %s, %s is %s", ErrVerification, ErrArtifactMismatch, m.Artifact, artifactTar, got)
	case err != nil:
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, context.Canceled) {
			return res, err
		}
		res.Artifact = ArtifactMismatch
		return res, fmt.Errorf("%w: %w: %s is not a valid image archive: %v", ErrVerification, ErrArtifactMismatch, artifactTar, err)
	}
	res.ArtifactDigest = got
	res.Artifact = ArtifactMatch
	return res, nil
}

// bundleContents is what readBundle hands back once everything verified.
type bundleContents struct {
	manifest *Manifest
	summary  []byte // summary.json, nil if the bundle has none
}

// countingReader counts the bytes read from the bundle file.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// readBundle streams the tar once, never writing anything to disk, and
// enforces the D-024/D-034 layout:
//
//   - MANIFEST.sha256 is the first member and MANIFEST.sig the second; the
//     signature is verified against pub before any other member is hashed.
//   - Every other member is a clean relative name listed in the signed
//     manifest, appears once, in strictly increasing order, and is hashed
//     and compared as it streams.
//   - Every header is a regular file, mode 0644, uid/gid 0, with no PAX
//     records other than path and size (no GNU.sparse.*, no xattrs), and a
//     declared size that fits in what is left of the file.
//   - After the end-of-archive marker there is nothing but zero bytes.
func readBundle(ctx context.Context, f io.Reader, fileSize int64, pub ed25519.PublicKey, lim limits) (*bundleContents, error) {
	cr := &countingReader{r: f}
	br := bufio.NewReaderSize(cr, 1<<20)
	tr := tar.NewReader(br)
	var (
		n     int
		total int64
	)
	// next returns the next header after every per-header check, or nil at
	// the end of the archive.
	next := func() (*tar.Header, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil, nil
		}
		if err != nil {
			return nil, failf("bundle is not a valid tar: %v", err)
		}
		if n >= lim.maxEntries {
			return nil, failf("bundle has more than %d entries", lim.maxEntries)
		}
		n++
		name := hdr.Name
		if hdr.Typeflag != tar.TypeReg {
			return nil, failf("bundle entry %q is not a regular file (type %q)", name, hdr.Typeflag)
		}
		for k := range hdr.PAXRecords {
			if k != "path" && k != "size" {
				return nil, failf("bundle entry %q has a disallowed PAX record %q", name, k)
			}
		}
		if hdr.Mode != 0o644 || hdr.Uid != 0 || hdr.Gid != 0 {
			return nil, failf("bundle entry %q is not mode 0644 owned by 0:0 (mode %o, owner %d:%d)", name, hdr.Mode, hdr.Uid, hdr.Gid)
		}
		if hdr.Size < 0 || hdr.Size > lim.maxFileSize {
			return nil, failf("bundle entry %q is %d bytes (limit %d)", name, hdr.Size, lim.maxFileSize)
		}
		if total += hdr.Size; total > lim.maxTotal {
			return nil, failf("bundle is larger than %d bytes", lim.maxTotal)
		}
		if left := fileSize - (cr.n - int64(br.Buffered())); hdr.Size > left {
			return nil, failf("bundle entry %q declares %d bytes but only %d remain in the file", name, hdr.Size, left)
		}
		return hdr, nil
	}
	readSmall := func(hdr *tar.Header) ([]byte, error) {
		if hdr.Size > lim.maxSmall {
			return nil, failf("bundle entry %q is %d bytes (limit %d)", hdr.Name, hdr.Size, lim.maxSmall)
		}
		buf := make([]byte, hdr.Size)
		if _, err := io.ReadFull(tr, buf); err != nil {
			return nil, failf("bundle entry %q is truncated", hdr.Name)
		}
		return buf, nil
	}

	// 1. The manifest, then the signature, then verify before anything else.
	hdr, err := next()
	if err != nil {
		return nil, err
	}
	if hdr == nil || hdr.Name != ManifestName {
		return nil, failf("bundle has no %s as its first entry", ManifestName)
	}
	rawManifest, err := readSmall(hdr)
	if err != nil {
		return nil, err
	}
	if hdr, err = next(); err != nil {
		return nil, err
	}
	if hdr == nil || hdr.Name != SignatureName {
		return nil, failf("bundle has no %s as its second entry (unsigned; run `gapproof sign`)", SignatureName)
	}
	rawSig, err := readSmall(hdr)
	if err != nil {
		return nil, err
	}
	claimed, sig, err := parseSignature(rawSig)
	if err != nil {
		return nil, failf("%v", err)
	}
	if !ed25519.Verify(pub, rawManifest, sig) {
		if fp := Fingerprint(pub); claimed != fp {
			return nil, failf("signature does not verify: the bundle says it was signed by %s, but --pub is %s", claimed, fp)
		}
		return nil, failf("signature does not verify against %s (%s was altered)", Fingerprint(pub), ManifestName)
	}
	m, err := ParseManifest(rawManifest)
	if err != nil {
		return nil, failf("%v", err) // signed but malformed: still not acceptable
	}

	// 2. The listed files, hashed as they stream.
	out := &bundleContents{manifest: m}
	seen := map[string]bool{}
	prev := ""
	for {
		hdr, err := next()
		if err != nil {
			return nil, err
		}
		if hdr == nil {
			break
		}
		name := hdr.Name
		if err := checkName(name); err != nil {
			if name == ManifestName || name == SignatureName {
				return nil, failf("bundle entry %q appears more than once", name)
			}
			return nil, failf("bundle entry: %v", err)
		}
		want, listed := m.Files[name]
		switch {
		case !listed:
			return nil, failf("%s is present but not listed in the manifest", name)
		case seen[name]:
			return nil, failf("bundle entry %q appears more than once", name)
		case name < prev:
			return nil, failf("bundle entry %q is out of order (after %q)", name, prev)
		}
		seen[name] = true
		prev = name
		h := sha256.New()
		if name == "summary.json" {
			raw, err := readSmall(hdr)
			if err != nil {
				return nil, err
			}
			h.Write(raw)
			out.summary = raw
		} else if c, err := io.CopyN(h, tr, hdr.Size); err != nil || c != hdr.Size {
			if cerr := ctx.Err(); cerr != nil {
				return nil, cerr
			}
			return nil, failf("bundle entry %q is truncated", name)
		}
		if got := hex.EncodeToString(h.Sum(nil)); got != want {
			return nil, failf("%s was modified (manifest sha256 %s, actual %s)", name, want, got)
		}
	}
	if len(seen) != len(m.Files) {
		var missing []string
		for p := range m.Files {
			if !seen[p] {
				missing = append(missing, p)
			}
		}
		slices.Sort(missing)
		return nil, failf("%s is listed in the manifest but missing", missing[0])
	}

	// 3. Only zero padding after the end-of-archive marker.
	var pad [32 << 10]byte
	for {
		k, err := br.Read(pad[:])
		for _, c := range pad[:k] {
			if c != 0 {
				return nil, failf("bundle has data after the end of the archive")
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
