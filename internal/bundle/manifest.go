package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Reserved names at the top of an evidence directory / bundle. Neither is
// listed in the manifest: the manifest can't hash itself, and the signature
// is over the manifest.
const (
	ManifestName  = "MANIFEST.sha256"
	SignatureName = "MANIFEST.sig"
	sigHeader     = "gapproof-ed25519-signature-v1"
	noArtifact    = "none"
)

var (
	digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	hexRe    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Manifest is a parsed MANIFEST.sha256.
//
// The file is sha256sum-compatible: one "<hex>  <path>" line per file,
// sorted by path (bytewise), then a final "artifact sha256:<config digest>"
// line ("artifact none" for a scan with no image, e.g. --rootfs). GNU
// `sha256sum -c` checks the file lines and skips the artifact line with a
// warning, so approvers can cross-check with stock tools.
type Manifest struct {
	Files    map[string]string // slash path -> lowercase hex SHA-256
	Artifact string            // "sha256:<hex>", or "" when none was recorded
}

// Marshal renders the canonical manifest bytes.
func (m *Manifest) Marshal() []byte {
	paths := make([]string, 0, len(m.Files))
	for p := range m.Files {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	var b bytes.Buffer
	for _, p := range paths {
		fmt.Fprintf(&b, "%s  %s\n", m.Files[p], p)
	}
	a := m.Artifact
	if a == "" {
		a = noArtifact
	}
	fmt.Fprintf(&b, "artifact %s\n", a)
	return b.Bytes()
}

// ParseManifest parses and validates canonical manifest bytes. Anything not
// exactly what Marshal would produce is rejected, so there is one byte
// representation per manifest.
func ParseManifest(raw []byte) (*Manifest, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("manifest is not UTF-8")
	}
	s := string(raw)
	if !strings.HasSuffix(s, "\n") {
		return nil, errors.New("manifest does not end with a newline")
	}
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	m := &Manifest{Files: map[string]string{}}
	last := lines[len(lines)-1]
	a, ok := strings.CutPrefix(last, "artifact ")
	if !ok {
		return nil, errors.New("manifest has no final artifact line")
	}
	switch {
	case a == noArtifact:
	case digestRe.MatchString(a):
		m.Artifact = a
	default:
		return nil, fmt.Errorf("manifest artifact %q is not sha256:<64 hex>", a)
	}
	prev := ""
	for i, l := range lines[:len(lines)-1] {
		sum, p, ok := strings.Cut(l, "  ")
		if !ok || !hexRe.MatchString(sum) {
			return nil, fmt.Errorf("manifest line %d is not \"<sha256>  <path>\"", i+1)
		}
		if err := checkName(p); err != nil {
			return nil, fmt.Errorf("manifest line %d: %w", i+1, err)
		}
		if i > 0 && p <= prev {
			return nil, fmt.Errorf("manifest line %d: paths not strictly sorted (%q after %q)", i+1, p, prev)
		}
		prev = p
		m.Files[p] = sum
	}
	return m, nil
}

// checkName accepts clean, relative, slash-separated paths without control
// characters, that aren't one of the reserved names.
func checkName(p string) error {
	if !fs.ValidPath(p) || p == "." {
		return fmt.Errorf("unsafe path %q", p)
	}
	if strings.Contains(p, `\`) || strings.ContainsFunc(p, unicode.IsControl) || !utf8.ValidString(p) {
		return fmt.Errorf("unsafe characters in path %q", p)
	}
	if p == ManifestName || p == SignatureName {
		return fmt.Errorf("reserved name %q", p)
	}
	return nil
}

// hashTree hashes every regular file under dir except the reserved names.
// Symlinks and special files are refused: an evidence directory is plain
// files, and following a link could pull in content from elsewhere.
func hashTree(dir string) (map[string]string, error) {
	files := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		switch {
		case rel == ".":
			return nil
		case d.IsDir():
			return nil
		case !d.Type().IsRegular():
			return fmt.Errorf("%s is not a regular file (symlinks and special files can't be in an evidence bundle)", rel)
		case rel == ManifestName || rel == SignatureName:
			return nil
		}
		if err := checkName(rel); err != nil {
			return err
		}
		sum, err := hashFile(p)
		if err != nil {
			return err
		}
		files[rel] = sum
		return nil
	})
	return files, err
}

func hashFile(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// WriteManifest hashes every file in dir (scope and waivers copies are
// ordinary files, so they're covered) and writes dir/MANIFEST.sha256.
// artifactDigest is the scanned image's config digest ("sha256:<hex>"), or
// "" when there is no image.
func WriteManifest(dir, artifactDigest string) (*Manifest, error) {
	if artifactDigest != "" && !digestRe.MatchString(artifactDigest) {
		return nil, fmt.Errorf("artifact digest %q is not sha256:<64 hex>", artifactDigest)
	}
	files, err := hashTree(dir)
	if err != nil {
		return nil, err
	}
	m := &Manifest{Files: files, Artifact: artifactDigest}
	if err := os.WriteFile(filepath.Join(dir, ManifestName), m.Marshal(), 0o644); err != nil {
		return nil, err
	}
	return m, nil
}

// ReadManifest parses dir/MANIFEST.sha256.
func ReadManifest(dir string) (*Manifest, error) {
	raw, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		return nil, err
	}
	return ParseManifest(raw)
}

// Sign checks that dir/MANIFEST.sha256 still matches the directory (so a
// stale manifest is never signed) and writes dir/MANIFEST.sig: an Ed25519
// signature over the exact manifest bytes. It returns the signer's
// fingerprint.
func Sign(dir string, key ed25519.PrivateKey) (string, error) {
	raw, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		return "", err
	}
	m, err := ParseManifest(raw)
	if err != nil {
		return "", err
	}
	files, err := hashTree(dir)
	if err != nil {
		return "", err
	}
	if err := compareFiles(m.Files, files); err != nil {
		return "", fmt.Errorf("%s is stale: %w", ManifestName, err)
	}
	pub := key.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(key, raw)
	body := sigHeader + "\n" + Fingerprint(pub) + "\n" + base64.StdEncoding.EncodeToString(sig) + "\n"
	if err := os.WriteFile(filepath.Join(dir, SignatureName), []byte(body), 0o644); err != nil {
		return "", err
	}
	return Fingerprint(pub), nil
}

// parseSignature returns the claimed signer fingerprint and the signature.
func parseSignature(raw []byte) (string, []byte, error) {
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != 3 || lines[0] != sigHeader {
		return "", nil, fmt.Errorf("%s is not a %s file", SignatureName, sigHeader)
	}
	if !regexp.MustCompile(`^ed25519:[0-9a-f]{16}$`).MatchString(lines[1]) {
		return "", nil, fmt.Errorf("%s has a malformed key fingerprint", SignatureName)
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(lines[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return "", nil, fmt.Errorf("%s has a malformed signature", SignatureName)
	}
	return lines[1], sig, nil
}

// compareFiles reports the first difference between the manifest's view
// (want) and what is actually present (got), in path order.
func compareFiles(want, got map[string]string) error {
	var all []string
	for p := range want {
		all = append(all, p)
	}
	for p := range got {
		if _, ok := want[p]; !ok {
			all = append(all, p)
		}
	}
	slices.Sort(all)
	for _, p := range all {
		w, inWant := want[p]
		g, inGot := got[p]
		switch {
		case !inGot:
			return fmt.Errorf("%s is listed in the manifest but missing", p)
		case !inWant:
			return fmt.Errorf("%s is present but not listed in the manifest", p)
		case w != g:
			return fmt.Errorf("%s was modified (manifest sha256 %s, actual %s)", p, w, g)
		}
	}
	return nil
}
