// Package rules embeds the community-editable rule pack and the CMVP
// snapshot, so the binary never fetches rules at runtime (CLAUDE.md rule 1).
//
// One phone-home rule per <ID>.yaml. Every rule needs positive and negative
// fixtures under testdata/<ID>/ (enforced by internal/phonehome tests), a
// source: URL it was verified against, and confidence: low if it couldn't be.
package rules

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"sort"
)

// PhoneHome holds the phone-home rules (*.yaml).
//
//go:embed *.yaml
var PhoneHome embed.FS

// CMVPSnapshot is the dated, manually curated list of validated crypto
// modules that the crypto inventory matches against.
//
//go:embed cmvp_snapshot.json
var CMVPSnapshot []byte

// PackVersion identifies the embedded rule pack and CMVP snapshot by
// content: "sha256:" plus the first 16 hex digits of a hash over every rule
// file (sorted by name) and the snapshot.
func PackVersion() string {
	h := sha256.New()
	names, _ := fs.Glob(PhoneHome, "*.yaml")
	sort.Strings(names)
	for _, n := range names {
		b, _ := PhoneHome.ReadFile(n)
		h.Write([]byte(n + "\x00"))
		h.Write(b)
		h.Write([]byte{0})
	}
	h.Write(CMVPSnapshot)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))[:16]
}
