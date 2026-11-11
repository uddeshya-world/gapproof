package bundle

import (
	"archive/tar"
	"bufio"
	"bytes"
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
	f, err := os.Open(bundlePath)
	if err != nil {
		return res, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil {
		return res, err
	} else if !fi.Mode().IsRegular() {
		return res, fmt.Errorf("%s is not a regular file", bundlePath)
	}

	got, small, err := readBundle(ctx, f, lim)
	if err != nil {
		return res, err
	}
	rawManifest, ok := small[ManifestName]
	if !ok {
		return res, failf("bundle has no %s", ManifestName)
	}
	rawSig, ok := small[SignatureName]
	if !ok {
		return res, failf("bundle has no %s (unsigned; run `gapproof sign`)", SignatureName)
	}
	claimed, sig, err := parseSignature(rawSig)
	if err != nil {
		return res, failf("%v", err)
	}
	if !ed25519.Verify(pub, rawManifest, sig) {
		if fp := Fingerprint(pub); claimed != fp {
			return res, failf("signature does not verify: the bundle says it was signed by %s, but --pub is %s", claimed, fp)
		}
		return res, failf("signature does not verify against %s (%s was altered)", Fingerprint(pub), ManifestName)
	}
	res.Signer = Fingerprint(pub)

	m, err := ParseManifest(rawManifest)
	if err != nil {
		return res, failf("%v", err) // signed but malformed: still not acceptable
	}
	if err := compareFiles(m.Files, got); err != nil {
		return res, failf("%v", err)
	}
	res.Files = len(m.Files)
	res.RecordedArtifact = m.Artifact

	if raw, ok := small["summary.json"]; ok {
		var s struct {
			AGR struct {
				Level string `json:"level"`
			} `json:"agr"`
		}
		if json.Unmarshal(raw, &s) == nil && s.AGR.Level != "" {
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
	im, err := fsscan.ExtractImage(ctx, artifactTar, fsscan.DefaultLimits())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, context.Canceled) {
			return res, err
		}
		res.Artifact = ArtifactMismatch
		return res, fmt.Errorf("%w: %w: %s is not a valid image archive: %v", ErrVerification, ErrArtifactMismatch, artifactTar, err)
	}
	res.ArtifactDigest = im.ConfigDigest
	im.Close()
	if res.ArtifactDigest != m.Artifact {
		res.Artifact = ArtifactMismatch
		return res, fmt.Errorf("%w: %w: bundle records %s, %s is %s", ErrVerification, ErrArtifactMismatch, m.Artifact, artifactTar, res.ArtifactDigest)
	}
	res.Artifact = ArtifactMatch
	return res, nil
}

// readBundle streams the tar once. It returns every non-reserved member's
// SHA-256 and the bytes of the small files it needs (reserved names and
// summary.json). Only regular files with clean relative names are allowed,
// each at most once.
func readBundle(ctx context.Context, r io.Reader, lim limits) (map[string]string, map[string][]byte, error) {
	tr := tar.NewReader(bufio.NewReaderSize(r, 1<<20))
	got := map[string]string{}
	small := map[string][]byte{}
	seen := map[string]bool{}
	var total int64
	for n := 0; ; n++ {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, failf("bundle is not a valid tar: %v", err)
		}
		if n >= lim.maxEntries {
			return nil, nil, failf("bundle has more than %d entries", lim.maxEntries)
		}
		name := hdr.Name
		if hdr.Typeflag != tar.TypeReg {
			return nil, nil, failf("bundle entry %q is not a regular file (type %q)", name, hdr.Typeflag)
		}
		reserved := name == ManifestName || name == SignatureName
		if !reserved {
			if err := checkName(name); err != nil {
				return nil, nil, failf("bundle entry: %v", err)
			}
		}
		if seen[name] {
			return nil, nil, failf("bundle entry %q appears more than once", name)
		}
		seen[name] = true
		if hdr.Size < 0 || hdr.Size > lim.maxFileSize {
			return nil, nil, failf("bundle entry %q is %d bytes (limit %d)", name, hdr.Size, lim.maxFileSize)
		}
		if total += hdr.Size; total > lim.maxTotal {
			return nil, nil, failf("bundle is larger than %d bytes", lim.maxTotal)
		}
		keep := reserved || name == "summary.json"
		if keep && hdr.Size > lim.maxSmall {
			return nil, nil, failf("bundle entry %q is %d bytes (limit %d)", name, hdr.Size, lim.maxSmall)
		}
		h := sha256.New()
		var buf bytes.Buffer
		w := io.Writer(h)
		if keep {
			w = io.MultiWriter(h, &buf)
		}
		if c, err := io.CopyN(w, tr, hdr.Size); err != nil || c != hdr.Size {
			return nil, nil, failf("bundle entry %q is truncated", name)
		}
		if keep {
			small[name] = buf.Bytes()
		}
		if !reserved {
			got[name] = hex.EncodeToString(h.Sum(nil))
		}
	}
	return got, small, nil
}
