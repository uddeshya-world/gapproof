// Package rules embeds the community-editable rule pack and the CMVP
// snapshot, so the binary never fetches rules at runtime (CLAUDE.md rule 1).
//
// One phone-home rule per <ID>.yaml. Every rule needs positive and negative
// fixtures under testdata/<ID>/ (enforced by internal/phonehome tests), a
// source: URL it was verified against, and confidence: low if it couldn't be.
package rules

import "embed"

// PhoneHome holds the phone-home rules (*.yaml).
//
//go:embed *.yaml
var PhoneHome embed.FS

// CMVPSnapshot is the dated, manually curated list of validated crypto
// modules that the crypto inventory matches against.
//
//go:embed cmvp_snapshot.json
var CMVPSnapshot []byte
