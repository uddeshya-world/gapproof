// Package diff compares two evidence directories (spec §2, M7): the AGR
// change, new/removed/changed findings, new egress destinations and model
// or crypto hash changes. Findings are matched on their rule and evidence,
// never on their ID, because IDs are renumbered per run.
package diff

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/uddeshya-world/gapproof/internal/evidence"
)

// FindingChange is a finding present in both runs whose status or
// severity changed.
type FindingChange struct {
	Old, New evidence.Finding
}

// HashChange is a file (model or crypto module) added, removed or changed.
type HashChange struct {
	Path   string `json:"path"`
	OldSHA string `json:"old_sha256,omitempty"` // "" = added
	NewSHA string `json:"new_sha256,omitempty"` // "" = removed
}

// Result is the comparison of two runs.
type Result struct {
	OldLevel, NewLevel string
	OldTarget          evidence.Target
	NewTarget          evidence.Target
	Added              []evidence.Finding
	Removed            []evidence.Finding
	Changed            []FindingChange
	EgressAdded        []evidence.EgressAttempt
	EgressRemoved      []evidence.EgressAttempt
	Models             []HashChange
	Crypto             []HashChange
	// ModulesLost ran in the old run but not in the new one (skipped or
	// failed). Their old findings aren't reported as resolved: nobody looked.
	ModulesLost []string
}

// Regressed reports whether the new run is worse: a lower level or any new
// open finding (for CI gates).
func (r *Result) Regressed() bool {
	if evidence.LevelRank(r.NewLevel) < evidence.LevelRank(r.OldLevel) || len(r.ModulesLost) > 0 {
		return true
	}
	if slices.ContainsFunc(r.Added, evidence.Finding.Open) {
		return true
	}
	// A waiver that expired or was removed, or a severity that went up.
	return slices.ContainsFunc(r.Changed, func(c FindingChange) bool {
		return (c.New.Open() && !c.Old.Open()) || (c.New.Open() && c.New.Severity.Rank() < c.Old.Severity.Rank())
	})
}

func findingKey(f evidence.Finding) string {
	e := f.Evidence
	return strings.Join([]string{f.Rule, e.Path, e.Member, e.Detail}, "\x00")
}

// Compare diffs old against new.
func Compare(old, new *evidence.Bundle) *Result {
	r := &Result{OldLevel: old.AGR.Level, NewLevel: new.AGR.Level, OldTarget: old.Target, NewTarget: new.Target}
	lost := map[string]bool{}
	for _, m := range evidence.Modules {
		if old.ModuleState(m) == evidence.ModuleRan && new.ModuleState(m) != evidence.ModuleRan {
			lost[m] = true
			r.ModulesLost = append(r.ModulesLost, m)
		}
	}

	ok, nk := occurrenceKeys(old.Findings), occurrenceKeys(new.Findings)
	om, nm := indexFindings(old.Findings, ok), indexFindings(new.Findings, nk)
	for i, f := range new.Findings {
		o, ok := om[nk[i]]
		switch {
		case !ok:
			r.Added = append(r.Added, f)
		case o.Status != f.Status || o.Severity != f.Severity:
			r.Changed = append(r.Changed, FindingChange{o, f})
		}
	}
	for i, f := range old.Findings {
		if lost[evidence.ModuleOf(f.Rule)] {
			continue
		}
		if _, found := nm[ok[i]]; !found {
			r.Removed = append(r.Removed, f)
		}
	}

	var oa, na []evidence.EgressAttempt
	if old.Egress != nil {
		oa = old.Egress.Attempts
	}
	if new.Egress != nil {
		na = new.Egress.Attempts
	}
	r.EgressAdded, r.EgressRemoved = setDiff(na, oa), setDiff(oa, na)

	r.Models = hashDiff(modelHashes(old), modelHashes(new))
	r.Crypto = hashDiff(cryptoHashes(old), cryptoHashes(new))
	return r
}

// occurrenceKeys numbers findings that share a key (same rule, path and
// detail at different offsets), so an extra occurrence shows up as new
// without making shifted offsets look like changes.
func occurrenceKeys(fs []evidence.Finding) []string {
	seen := map[string]int{}
	keys := make([]string, len(fs))
	for i, f := range fs {
		k := findingKey(f)
		keys[i] = fmt.Sprintf("%s\x00#%d", k, seen[k])
		seen[k]++
	}
	return keys
}

func indexFindings(fs []evidence.Finding, keys []string) map[string]evidence.Finding {
	m := make(map[string]evidence.Finding, len(fs))
	for i, f := range fs {
		m[keys[i]] = f
	}
	return m
}

// setDiff returns attempts in a whose destination isn't in b.
func setDiff(a, b []evidence.EgressAttempt) []evidence.EgressAttempt {
	seen := map[string]bool{}
	for _, x := range b {
		seen[x.Destination()] = true
	}
	var out []evidence.EgressAttempt
	for _, x := range a {
		if !seen[x.Destination()] {
			out = append(out, x)
			seen[x.Destination()] = true
		}
	}
	return out
}

func modelHashes(b *evidence.Bundle) map[string]string {
	m := map[string]string{}
	if b.Models != nil {
		for _, a := range b.Models.Artifacts {
			m[a.Path] = a.SHA256
		}
	}
	return m
}

func cryptoHashes(b *evidence.Bundle) map[string]string {
	m := map[string]string{}
	if b.Crypto != nil {
		for _, c := range b.Crypto.Modules {
			m[c.Path] = c.SHA256
		}
	}
	return m
}

func hashDiff(old, new map[string]string) []HashChange {
	var out []HashChange
	for p, n := range new {
		if o := old[p]; o != n {
			out = append(out, HashChange{Path: p, OldSHA: o, NewSHA: n})
		}
	}
	for p, o := range old {
		if _, ok := new[p]; !ok {
			out = append(out, HashChange{Path: p, OldSHA: o})
		}
	}
	slices.SortFunc(out, func(a, b HashChange) int { return cmp.Compare(a.Path, b.Path) })
	return out
}

// WriteSummary prints the free summary: the level change and counts.
func (r *Result) WriteSummary(w io.Writer) {
	arrow := "→"
	switch d := evidence.LevelRank(r.NewLevel) - evidence.LevelRank(r.OldLevel); {
	case d > 0:
		arrow = "→ (improved)"
	case d < 0:
		arrow = "→ (REGRESSED)"
	default:
		arrow = "→ (unchanged)"
	}
	fmt.Fprintf(w, "AGR: %s %s %s\n", r.OldLevel, arrow, r.NewLevel)
	if len(r.ModulesLost) > 0 {
		fmt.Fprintf(w, "REGRESSED coverage: %s ran before but not now (its old findings are not counted as resolved)\n", strings.Join(r.ModulesLost, ", "))
	}
	fmt.Fprintf(w, "findings: +%d new, -%d resolved, %d changed\n", len(r.Added), len(r.Removed), len(r.Changed))
	fmt.Fprintf(w, "egress destinations: +%d new, -%d gone · model files changed: %d · crypto modules changed: %d\n",
		len(r.EgressAdded), len(r.EgressRemoved), len(r.Models), len(r.Crypto))
}

// WriteFull prints the itemised diff.
func (r *Result) WriteFull(w io.Writer) {
	r.WriteSummary(w)
	section := func(title string, n int) bool {
		if n == 0 {
			return false
		}
		fmt.Fprintf(w, "\n%s (%d)\n", title, n)
		return true
	}
	if section("New findings", len(r.Added)) {
		for _, f := range r.Added {
			fmt.Fprintf(w, "  + %-8s %-8s %s\n", f.ID, f.Severity, f.Title)
		}
	}
	if section("Resolved findings", len(r.Removed)) {
		for _, f := range r.Removed {
			fmt.Fprintf(w, "  - %-8s %-8s %s\n", f.ID, f.Severity, f.Title)
		}
	}
	if section("Changed findings", len(r.Changed)) {
		for _, c := range r.Changed {
			fmt.Fprintf(w, "  ~ %s → %s  %s/%s → %s/%s  %s\n", c.Old.ID, c.New.ID, c.Old.Severity, c.Old.Status, c.New.Severity, c.New.Status, c.New.Title)
		}
	}
	if section("New egress destinations", len(r.EgressAdded)) {
		for _, a := range r.EgressAdded {
			fmt.Fprintf(w, "  + %s\n", a.Destination())
		}
	}
	if section("Egress destinations gone", len(r.EgressRemoved)) {
		for _, a := range r.EgressRemoved {
			fmt.Fprintf(w, "  - %s\n", a.Destination())
		}
	}
	hashes := func(title string, hs []HashChange) {
		if !section(title, len(hs)) {
			return
		}
		for _, h := range hs {
			switch {
			case h.OldSHA == "":
				fmt.Fprintf(w, "  + %s\n", h.Path)
			case h.NewSHA == "":
				fmt.Fprintf(w, "  - %s\n", h.Path)
			default:
				fmt.Fprintf(w, "  ~ %s  %s → %s\n", h.Path, shortHash(h.OldSHA), shortHash(h.NewSHA))
			}
		}
	}
	hashes("Model files", r.Models)
	hashes("Crypto modules", r.Crypto)
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
