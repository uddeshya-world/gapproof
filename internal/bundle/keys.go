// Package bundle writes, signs, packs and verifies Gapproof evidence bundles
// (docs/02_SPEC.md §3.6). Everything here is offline: SHA-256 for file
// hashes, Ed25519 for signatures, and a plain tar for transport.
//
// Signing is a property of the evidence bundle, not of the product, so it
// is never an AGR condition (docs/AGR_SPEC.md §1).
package bundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
)

// Key file headers. The formats are two text lines: the header, then the
// standard base64 of the raw key bytes (32-byte seed or 32-byte public key).
const (
	privateHeader = "gapproof-ed25519-private-key-v1"
	publicHeader  = "gapproof-ed25519-public-key-v1"
	maxKeyFile    = 4 << 10
)

// ErrKey means a key file is malformed or the wrong kind.
var ErrKey = errors.New("invalid key file")

// ErrKeyExists means Keygen would have overwritten an existing file.
var ErrKeyExists = errors.New("refusing to overwrite an existing key file")

// Fingerprint identifies a public key: "ed25519:" plus the first 16 hex
// digits of SHA-256 over the raw 32-byte key.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "ed25519:" + hex.EncodeToString(sum[:])[:16]
}

// Keygen writes <prefix>.key (mode 0600) and <prefix>.pub (mode 0644). It
// refuses to overwrite either file, and writes neither if one exists.
// It returns the public key's fingerprint.
func Keygen(prefix string) (string, error) {
	keyPath, pubPath := prefix+".key", prefix+".pub"
	for _, p := range []string{keyPath, pubPath} {
		if _, err := os.Lstat(p); err == nil {
			return "", fmt.Errorf("%w: %s already exists", ErrKeyExists, p)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	if err := writeExclusive(keyPath, encodeKey(privateHeader, priv.Seed()), 0o600); err != nil {
		return "", err
	}
	if err := writeExclusive(pubPath, encodeKey(publicHeader, pub), 0o644); err != nil {
		os.Remove(keyPath) // don't leave half a key pair behind
		return "", err
	}
	return Fingerprint(pub), nil
}

func encodeKey(header string, raw []byte) []byte {
	return []byte(header + "\n" + base64.StdEncoding.EncodeToString(raw) + "\n")
}

// writeExclusive creates path with O_EXCL (never follows or replaces an
// existing file or symlink) and forces perm regardless of the umask.
func writeExclusive(path string, data []byte, perm fs.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	return f.Close()
}

// LoadPrivateKey reads a key written by Keygen.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := readKey(path, privateHeader, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(raw), nil
}

// LoadPublicKey reads a public key written by Keygen.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	raw, err := readKey(path, publicHeader, ed25519.PublicKeySize)
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(raw), nil
}

func readKey(path, header string, size int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf, err := io.ReadAll(io.LimitReader(f, maxKeyFile+1))
	if err != nil {
		return nil, err
	}
	if len(buf) > maxKeyFile {
		return nil, fmt.Errorf("%w: %s is too large", ErrKey, path)
	}
	lines := strings.Split(strings.TrimRight(string(buf), "\n"), "\n")
	if len(lines) != 2 || lines[0] != header {
		if len(lines) > 0 && (lines[0] == privateHeader || lines[0] == publicHeader) {
			return nil, fmt.Errorf("%w: %s is a %s, want a %s", ErrKey, path, lines[0], header)
		}
		return nil, fmt.Errorf("%w: %s is not a %s file", ErrKey, path, header)
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(lines[1])
	if err != nil || len(raw) != size {
		return nil, fmt.Errorf("%w: %s has a malformed key", ErrKey, path)
	}
	return raw, nil
}
