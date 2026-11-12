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
	"runtime"
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
	if err := checkPublicKey(raw); err != nil {
		return nil, fmt.Errorf("%w (%s)", err, path)
	}
	return ed25519.PublicKey(raw), nil
}

// smallOrder lists the encodings of the Ed25519 points of small order
// (orders 1, 2, 4 and 8), including the non-canonical encodings of 0 and 1
// (y = p and y = p+1). It is libsodium's has_small_order blacklist; the
// sign bit of byte 31 is ignored when comparing, so the x-sign variants are
// covered too. A key on this list verifies forged signatures such as
// R = identity, S = 0 for every message.
var smallOrder = [7][32]byte{
	{0x00}, // y = 0: order 4
	{0x01}, // y = 1: the identity, order 1
	{0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
		0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05}, // order 8
	{0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
		0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a}, // order 8
	pMinus(1), // y = p-1 = -1: order 2
	pMinus(0), // y = p (non-canonical 0): order 4
	pPlus1(),  // y = p+1 (non-canonical 1): order 1
}

// pMinus returns the little-endian encoding of p-k, p = 2^255-19, k small.
func pMinus(k byte) [32]byte {
	var b [32]byte
	b[0] = 0xed - k
	for i := 1; i < 31; i++ {
		b[i] = 0xff
	}
	b[31] = 0x7f
	return b
}

func pPlus1() [32]byte {
	b := pMinus(0)
	b[0] = 0xee
	return b
}

// checkPublicKey rejects non-canonical encodings (y >= p) and points of
// small order. crypto/ed25519 accepts both, and a small-order key lets
// anyone forge a signature it verifies.
func checkPublicKey(raw []byte) error {
	if len(raw) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: public key has the wrong size", ErrKey)
	}
	var y [32]byte
	copy(y[:], raw)
	y[31] &= 0x7f
	// y >= p iff y is one of p .. 2^255-1: top byte 0x7f, bytes 1..30 0xff,
	// byte 0 >= 0xed.
	canonical := y[31] != 0x7f || y[0] < 0xed
	for i := 1; i < 31 && !canonical; i++ {
		canonical = y[i] != 0xff
	}
	if !canonical {
		return fmt.Errorf("%w: public key is not a canonical Ed25519 encoding", ErrKey)
	}
	for _, s := range smallOrder {
		if y == s {
			return fmt.Errorf("%w: public key is a small-order point (it would accept forged signatures)", ErrKey)
		}
	}
	return nil
}

// PrivateKeyWarning returns a warning when the private key file at path is
// readable or writable by group or other, or "" when it isn't (or the
// platform has no Unix permission bits).
func PrivateKeyWarning(path string) string {
	if runtime.GOOS == "windows" {
		return ""
	}
	fi, err := os.Stat(path)
	if err != nil {
		return ""
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Sprintf("warning: private key %s is accessible by group or other (mode %04o); chmod 600 it", path, perm)
	}
	return ""
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
			kind := map[string]string{privateHeader: "private", publicHeader: "public"}
			return nil, fmt.Errorf("%w: %s is a %s key, but a %s key is needed here", ErrKey, path, kind[lines[0]], kind[header])
		}
		return nil, fmt.Errorf("%w: %s is not a %s file", ErrKey, path, header)
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(lines[1])
	if err != nil || len(raw) != size {
		return nil, fmt.Errorf("%w: %s has a malformed key", ErrKey, path)
	}
	return raw, nil
}
