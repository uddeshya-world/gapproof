// Package detid derives deterministic, RFC 4122-shaped UUIDs from content,
// so generated documents (AI-BOM serial numbers, OSCAL UUIDs) are
// byte-identical for identical input (CLAUDE.md rule 6).
//
// The UUIDs are "v5-style": the layout of a name-based version 5 UUID, but
// the hash is SHA-256 (truncated to 128 bits) instead of SHA-1, so Gapproof
// only uses SHA-256 and Ed25519 itself. They are identifiers, not security
// claims.
package detid

import (
	"crypto/sha256"
	"encoding/hex"
)

// UUID returns a version-5-shaped UUID for the given namespace and parts.
// Parts are length-prefixed, so ("ab","c") and ("a","bc") differ.
func UUID(namespace string, parts ...string) string {
	h := sha256.New()
	write := func(s string) {
		var n [8]byte
		l := uint64(len(s))
		for i := range n {
			n[i] = byte(l >> (56 - 8*i))
		}
		h.Write(n[:])
		h.Write([]byte(s))
	}
	write(namespace)
	for _, p := range parts {
		write(p)
	}
	var u [16]byte
	copy(u[:], h.Sum(nil))
	u[6] = u[6]&0x0f | 0x50 // version 5 layout
	u[8] = u[8]&0x3f | 0x80 // RFC 4122 variant
	s := hex.EncodeToString(u[:])
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
}
