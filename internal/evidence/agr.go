package evidence

import (
	"fmt"
	"slices"
	"strings"
)

// AGRSpecVersion is the docs/AGR_SPEC.md version this code implements.
const AGRSpecVersion = "0.2-draft"

// Levels, lowest first.
const (
	LevelUnassessed = "unassessed"
	LevelAGR0       = "AGR-0"
	LevelAGR1       = "AGR-1"
	LevelAGR2       = "AGR-2"
	LevelAGR3       = "AGR-3"
	LevelAGR4       = "AGR-4"
)

var levels = []string{LevelUnassessed, LevelAGR0, LevelAGR1, LevelAGR2, LevelAGR3, LevelAGR4}

// RuleAgentPrefix starts every INV-01 violation rule.
const RuleAgentPrefix = "AGENT-INV01-"

// LevelRank maps unassessed to -1 and AGR-N to N. Unknown strings rank as
// unassessed.
func LevelRank(level string) int {
	if i := slices.Index(levels, level); i >= 0 {
		return i - 1
	}
	return -1
}

// MeetsMin reports whether level satisfies --min-agr n. A negative n means
// no threshold. unassessed is below every threshold (AGR_SPEC §5).
func MeetsMin(level string, n int) bool {
	if n < 0 {
		return true
	}
	if level == LevelUnassessed || slices.Index(levels, level) < 0 {
		return false
	}
	return LevelRank(level) >= n
}

// AGR is the level block of summary.json (AGR_SPEC §6).
type AGR struct {
	Level           string     `json:"level"`
	SpecVersion     string     `json:"spec_version"`
	ObservedWindowS int64      `json:"observed_window_s"`
	Blocking        []Blocking `json:"blocking"`
}

// Blocking is one reason the build doesn't reach the next level.
type Blocking struct {
	NextLevel  string   `json:"next_level"`
	Reason     string   `json:"reason"`
	FindingIDs []string `json:"finding_ids"`
}

// AGRInput is everything the level depends on. Findings must already be
// finalized (IDs assigned, waivers applied).
type AGRInput struct {
	EgressRan       bool // the egress module was run (not skipped)
	HarnessFailed   bool // the harness itself failed: no result
	TargetStarted   bool // the target started and became healthy with egress blocked
	WorkloadPassed  bool
	ObservedWindowS int64
	Attempts        []EgressAttempt // InScope already set
	ModulesRan      []string
	Skipped         []string // modules skipped with --skip
	Findings        []Finding
	ModelsHashed    bool // every model artefact is hashed in the AI-BOM
	AgentsManifest  bool // the agents module ran on a manifest
	INV01Violations int
}

func (in AGRInput) ran(m string) bool {
	return slices.Contains(in.ModulesRan, m) && !slices.Contains(in.Skipped, m)
}

func (in AGRInput) notRunReason(m, extra string) string {
	if slices.Contains(in.Skipped, m) {
		return m + " module skipped (--skip " + m + ")" + extra
	}
	return m + " module did not run" + extra
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func ids(fs []Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

// Compute returns the level per AGR_SPEC §1, §4 and §5: the highest level
// whose conditions all hold, checked strictly in order, plus everything
// blocking the next level.
func Compute(in AGRInput) AGR {
	r := AGR{Level: LevelUnassessed, SpecVersion: AGRSpecVersion, Blocking: []Blocking{}}
	block := func(next, reason string, fs []Finding) {
		r.Blocking = append(r.Blocking, Blocking{NextLevel: next, Reason: reason, FindingIDs: ids(fs)})
	}

	// unassessed → AGR-0: the egress module ran and the harness worked.
	switch {
	case slices.Contains(in.Skipped, ModEgress) || !in.EgressRan:
		block(LevelAGR0, in.notRunReason(ModEgress, ": static-only report, no level claimed"), nil)
		return r
	case in.HarnessFailed:
		block(LevelAGR0, "egress harness failed: no level claimed", nil)
		return r
	}
	r.Level = LevelAGR0
	r.ObservedWindowS = in.ObservedWindowS

	// AGR-0 → AGR-1: runs offline.
	if !in.TargetStarted {
		block(LevelAGR1, "target did not start or become healthy with all egress blocked", nil)
	}
	if !in.WorkloadPassed {
		block(LevelAGR1, "workload failed with all egress blocked", nil)
	}
	if len(r.Blocking) > 0 {
		return r
	}
	r.Level = LevelAGR1

	// AGR-1 → AGR-2: silent.
	var egressF []Finding
	for _, f := range in.Findings {
		if f.Rule == RuleEgressAttempt {
			egressF = append(egressF, f)
		}
	}
	out := 0
	for _, a := range DedupeAttempts(in.Attempts) {
		if !a.InScope {
			out++
		}
	}
	out = max(out, len(egressF))
	if out > 0 {
		block(LevelAGR2, plural(out, "out-of-scope egress attempt", "out-of-scope egress attempts"), egressF)
		return r
	}
	r.Level = LevelAGR2

	// AGR-2 → AGR-3: provable.
	for _, m := range []string{ModPhoneHome, ModCrypto, ModModels} {
		if !in.ran(m) {
			block(LevelAGR3, in.notRunReason(m, ""), nil)
		}
	}
	var unwaivable, highOpen []Finding
	for _, f := range in.Findings {
		m := ModuleOf(f.Rule)
		if m == ModAgents || f.Rule == RuleEgressAttempt {
			continue // INV-01 gates AGR-4; egress attempts gate AGR-2
		}
		if !Waivable(f.Rule) {
			unwaivable = append(unwaivable, f)
			continue
		}
		if f.Open() && f.Severity.Rank() <= High.Rank() {
			highOpen = append(highOpen, f)
		}
	}
	if len(unwaivable) > 0 {
		block(LevelAGR3, plural(len(unwaivable), "unwaivable finding", "unwaivable findings")+" (fix required, AGR_SPEC §4)", unwaivable)
	}
	if len(highOpen) > 0 {
		block(LevelAGR3, plural(len(highOpen), "open high/critical finding", "open high/critical findings")+" (fix, or accept in the waivers file)", highOpen)
	}
	if !in.ModelsHashed {
		block(LevelAGR3, "not every model artefact is hashed in the AI-BOM", nil)
	}
	if len(r.Blocking) > 0 {
		return r
	}
	r.Level = LevelAGR3

	// AGR-3 → AGR-4: contained.
	if !in.ran(ModAgents) || !in.AgentsManifest {
		reason := in.notRunReason(ModAgents, "")
		if !slices.Contains(in.Skipped, ModAgents) {
			reason += " (no agents manifest supplied)"
		}
		block(LevelAGR4, reason, nil)
		return r
	}
	var agentF []Finding
	for _, f := range in.Findings {
		if strings.HasPrefix(f.Rule, RuleAgentPrefix) {
			agentF = append(agentF, f)
		}
	}
	if v := max(in.INV01Violations, len(agentF)); v > 0 {
		block(LevelAGR4, plural(v, "INV-01 violation", "INV-01 violations"), agentF)
		return r
	}
	r.Level = LevelAGR4
	return r
}
