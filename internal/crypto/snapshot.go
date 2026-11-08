// Package crypto inventories the cryptographic modules in a scanned
// filesystem (spec §3.3) and maps each against a dated, manually curated
// CMVP snapshot. Statuses are validated-snapshot-match, unvalidated or
// unknown: never "compliant" (CLAUDE.md rule 4).
package crypto

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/uddeshya-world/gapproof/rules"
)

// Snapshot is rules/cmvp_snapshot.json.
type Snapshot struct {
	SnapshotDate string      `json:"snapshot_date"`
	Curated      string      `json:"curated"`
	Note         string      `json:"note"`
	Modules      []SnapEntry `json:"modules"`
}

// SnapEntry is one certificate (or in-process module) in the snapshot.
type SnapEntry struct {
	Library     string   `json:"library"`
	Name        string   `json:"name"`
	Versions    []string `json:"versions"`
	Certificate string   `json:"certificate,omitempty"`
	Standard    string   `json:"standard"`
	Status      string   `json:"status"` // active | historical | in-process
	Sunset      string   `json:"sunset,omitempty"`
	Note        string   `json:"note,omitempty"`
	Source      string   `json:"source"`
}

// BuiltinSnapshot parses the embedded snapshot.
func BuiltinSnapshot() (*Snapshot, error) { return ParseSnapshot(rules.CMVPSnapshot) }

// ParseSnapshot validates and parses a snapshot.
func ParseSnapshot(b []byte) (*Snapshot, error) {
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("cmvp snapshot: %w", err)
	}
	if _, err := time.Parse(time.DateOnly, s.SnapshotDate); err != nil {
		return nil, errors.New("cmvp snapshot: snapshot_date must be YYYY-MM-DD")
	}
	for i, m := range s.Modules {
		switch {
		case m.Library == "" || len(m.Versions) == 0 || m.Source == "":
			return nil, fmt.Errorf("cmvp snapshot: entry %d needs library, versions and source", i)
		case m.Status != "active" && m.Status != "historical" && m.Status != "in-process":
			return nil, fmt.Errorf("cmvp snapshot: entry %d: bad status %q", i, m.Status)
		case m.Status == "active" && m.Certificate == "":
			return nil, fmt.Errorf("cmvp snapshot: entry %d: an active entry needs a certificate number", i)
		}
	}
	return &s, nil
}

// lookup returns the snapshot entry for library@version, if any. Go records
// the exact module snapshot ("v1.0.0-c2097c7c"); the CMVP listing names the
// module version ("v1.0.0").
func (s *Snapshot) lookup(library, version string) *SnapEntry {
	if library == "go" {
		version, _, _ = strings.Cut(version, "-")
	}
	for i := range s.Modules {
		m := &s.Modules[i]
		if m.Library == library && slices.Contains(m.Versions, version) {
			return m
		}
	}
	return nil
}
