package evidence

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Diff kinds.
const (
	DiffAdded   = "added"   // in the rescan, not in the signed evidence
	DiffRemoved = "removed" // in the signed evidence, not reproduced by the rescan
	DiffChanged = "changed"
)

// DiffEntry is one difference between the signed evidence and an offline
// rescan of the delivered image.
type DiffEntry struct {
	Kind    string // DiffAdded, DiffRemoved, DiffChanged
	Section string // "findings", "crypto", "models", "agents", "modules"
	Key     string // stable identity of the item
	Detail  string // what differs, for DiffChanged
}

// String is the one-line form.
func (d DiffEntry) String() string {
	s := fmt.Sprintf("%s %s: %s", d.Kind, d.Section, d.Key)
	if d.Detail != "" {
		s += " (" + d.Detail + ")"
	}
	return s
}

// CompareOpts says what CompareStatic looks at.
type CompareOpts struct {
	// Modules are the static modules both sides ran, a subset of ModPhoneHome,
	// ModCrypto, ModModels and ModAgents. Everything else is ignored: egress
	// and harness results can't be reproduced offline, and run metadata,
	// warnings and timestamps are not findings.
	Modules []string
	// IgnorePathPrefix drops model artefacts and findings under this path
	// prefix on both sides (inputs that were never inside the image).
	IgnorePathPrefix string
}

// CompareStatic diffs the static results of two evidence bundles
// deterministically: findings (by rule + evidence identity, then the full
// finding), the crypto and model inventories, and the agents/INV-01 result.
// The order of the result is stable.
func CompareStatic(recorded, rescan *Bundle, o CompareOpts) []DiffEntry {
	var out []DiffEntry
	has := func(m string) bool { return slices.Contains(o.Modules, m) }
	ignored := func(p string) bool { return o.IgnorePathPrefix != "" && strings.HasPrefix(p, o.IgnorePathPrefix) }

	pick := func(b *Bundle) map[string]Finding {
		m := map[string]Finding{}
		for _, f := range b.Findings {
			if has(ModuleOf(f.Rule)) && !ignored(f.Evidence.Path) {
				m[findingKey(f)] = f
			}
		}
		return m
	}
	out = diffMaps(out, "findings", pick(recorded), pick(rescan), findingDelta,
		func(k string, f Finding) string { return f.ID + " " + k })

	if has(ModCrypto) {
		rc, nc := recorded.Crypto, rescan.Crypto
		if rc == nil {
			rc = &CryptoSection{}
		}
		if nc == nil {
			nc = &CryptoSection{}
		}
		same := func(a, b string) string { return "record differs" }
		out = diffMaps(out, "crypto", cryptoModules(rc), cryptoModules(nc), same, nil)
		out = diffMaps(out, "crypto", providers(rc), providers(nc), same, nil)
		out = diffSets(out, "crypto", "fips config ", rc.Configs, nc.Configs)
		if rc.SnapshotDate != nc.SnapshotDate {
			out = append(out, DiffEntry{DiffChanged, "crypto", "cmvp snapshot date", rc.SnapshotDate + " -> " + nc.SnapshotDate})
		}
	}
	if has(ModModels) {
		pickModels := func(b *Bundle) map[string]string {
			m := map[string]string{}
			if b.Models != nil {
				for _, a := range b.Models.Artifacts {
					if !ignored(a.Path) {
						m[a.Path] = jsonOf(a)
					}
				}
			}
			return m
		}
		out = diffMaps(out, "models", pickModels(recorded), pickModels(rescan), func(a, b string) string { return "artifact record differs" }, nil)
	}
	if has(ModAgents) {
		switch {
		case recorded.Agents == nil && rescan.Agents != nil:
			out = append(out, DiffEntry{DiffAdded, "agents", "agents section", ""})
		case recorded.Agents != nil && rescan.Agents == nil:
			out = append(out, DiffEntry{DiffRemoved, "agents", "agents section", ""})
		case jsonOf(recorded.Agents) != jsonOf(rescan.Agents):
			out = append(out, DiffEntry{DiffChanged, "agents", "agents section", agentsDelta(recorded.Agents, rescan.Agents)})
		}
	}
	for _, m := range o.Modules {
		if r, n := recorded.ModuleState(m), rescan.ModuleState(m); r != n {
			out = append(out, DiffEntry{DiffChanged, "modules", m, r + " -> " + n})
		}
	}
	slices.SortStableFunc(out, func(a, b DiffEntry) int {
		return cmp.Or(cmp.Compare(a.Section, b.Section), cmp.Compare(a.Key, b.Key), cmp.Compare(a.Kind, b.Kind))
	})
	return out
}

func findingKey(f Finding) string {
	e := f.Evidence
	off := ""
	if e.Offset != nil {
		off = fmt.Sprint(*e.Offset)
	}
	return strings.Join([]string{f.Rule, e.Path, e.Member, e.SHA256, off, e.Detail}, "|")
}

// fieldDelta names the fields whose JSON differs.
func fieldDelta(names []string, a, b []any) string {
	var d []string
	for i, n := range names {
		if jsonOf(a[i]) != jsonOf(b[i]) {
			d = append(d, n)
		}
	}
	return strings.Join(d, ", ")
}

// findingDelta names the fields in which two findings with the same
// identity differ.
func findingDelta(a, b Finding) string {
	return fieldDelta(
		[]string{"id", "severity", "title", "explanation", "fix", "controls", "status", "waiver"},
		[]any{a.ID, a.Severity, a.Title, a.Explanation, a.Fix, a.Controls, a.Status, a.Waiver},
		[]any{b.ID, b.Severity, b.Title, b.Explanation, b.Fix, b.Controls, b.Status, b.Waiver})
}

func agentsDelta(a, b *AgentsSection) string {
	return fieldDelta(
		[]string{"manifest", "manifest sha256", "declared_no_agents", "agents", "mesa_spec", "inv01 threshold", "inv01 violations", "inv01 near misses"},
		[]any{a.Manifest, a.ManifestSHA256, a.DeclaredNoAgents, a.Agents, a.MESASpec, a.Threshold, a.Violations, a.NearMisses},
		[]any{b.Manifest, b.ManifestSHA256, b.DeclaredNoAgents, b.Agents, b.MESASpec, b.Threshold, b.Violations, b.NearMisses})
}

func cryptoModules(c *CryptoSection) map[string]string {
	m := map[string]string{}
	for _, x := range c.Modules {
		m[x.Path+"|"+x.Library+"|"+x.Version] = jsonOf(x)
	}
	return m
}

func providers(c *CryptoSection) map[string]string {
	m := map[string]string{}
	for _, x := range c.FIPSProviders {
		m["fips provider "+x.Path] = jsonOf(x)
	}
	return m
}

func jsonOf(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

// diffMaps appends added/removed/changed entries for two keyed maps. label
// builds the displayed key (nil: the map key). delta returns "" when the
// values are the same for display purposes.
func diffMaps[T any](out []DiffEntry, section string, rec, now map[string]T, delta func(a, b T) string, label func(k string, v T) string) []DiffEntry {
	if label == nil {
		label = func(k string, _ T) string { return k }
	}
	for k, a := range rec {
		b, ok := now[k]
		switch {
		case !ok:
			out = append(out, DiffEntry{DiffRemoved, section, label(k, a), ""})
		case jsonOf(a) != jsonOf(b):
			out = append(out, DiffEntry{DiffChanged, section, label(k, b), delta(a, b)})
		}
	}
	for k, b := range now {
		if _, ok := rec[k]; !ok {
			out = append(out, DiffEntry{DiffAdded, section, label(k, b), ""})
		}
	}
	return out
}

func diffSets(out []DiffEntry, section, prefix string, rec, now []string) []DiffEntry {
	for _, s := range rec {
		if !slices.Contains(now, s) {
			out = append(out, DiffEntry{DiffRemoved, section, prefix + s, ""})
		}
	}
	for _, s := range now {
		if !slices.Contains(rec, s) {
			out = append(out, DiffEntry{DiffAdded, section, prefix + s, ""})
		}
	}
	return out
}
