// Package report renders the self-contained HTML and Markdown reports
// (spec §3.7) from a loaded evidence bundle. The HTML page has inline CSS
// only: no JavaScript and no external URLs, so it opens with zero network
// requests. Every string from the evidence is treated as hostile and escaped.
package report

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/uddeshya-world/gapproof/internal/evidence"
)

// Coverage is the harness coverage statement (spec §3.1). It goes in every report.
const Coverage = "The egress harness detects IPv4 packets originated by processes in the target container " +
	"during the observation window. It does not detect: code paths the workload didn't exercise " +
	"(the static phone-home rules cover part of this), IPv6-only behaviour (IPv6 is disabled by design, " +
	"so a v6-only app shows as failing), or exfiltration through in-scope names the vendor declared. " +
	"Each in-scope attempt is listed so the approver can judge it."

// Disclaimer is the no-overclaim statement (CLAUDE.md rule 4, AGR_SPEC §7).
const Disclaimer = "AGR is an inventory-and-findings result. It is not a FIPS 140-3 validation, an ATO, " +
	"an accreditation or a certification, and it is not a guarantee. Control mappings are informative. " +
	"This report says what was checked, what was found and what the vendor accepted, so that the people " +
	"who grant approvals have evidence instead of promises."

// Labels used for the agents section (AGR_SPEC §1).
const (
	AgentsManifestLabel = "Based on a vendor-declared manifest."
	NoAgentsLabel       = "No agentic tool use, vendor-declared."
)

var moduleTitles = map[string]string{
	evidence.ModEgress:    "Egress (observed)",
	evidence.ModPhoneHome: "Phone-home (static rules)",
	evidence.ModCrypto:    "Crypto inventory",
	evidence.ModModels:    "Model artefacts",
	evidence.ModAgents:    "Agent containment",
	evidence.ModOther:     "Other findings",
}

// fixItem is one line of "What to fix first".
type fixItem struct {
	ID, Severity, Title, Fix string
}

type section struct {
	Module, Title, Status string
	Findings              []evidence.Finding
}

// view is the shared model both renderers walk, in report order.
type view struct {
	B          *evidence.Bundle
	Label      string
	LevelClass string
	Blocking   []evidence.Blocking
	FixFirst   []fixItem
	Sections   []section
	Coverage   string
	Disclaimer string
}

func newView(b *evidence.Bundle) view {
	v := view{B: b, Label: b.AGR.LevelLabel(), Blocking: b.AGR.Blocking, Coverage: Coverage, Disclaimer: Disclaimer}
	v.LevelClass = "lvl-" + strings.ToLower(strings.TrimPrefix(b.AGR.Level, "AGR-"))
	if b.AGR.Level == "" || b.AGR.Level == evidence.LevelUnassessed {
		v.LevelClass = "lvl-unassessed"
	}
	urgent := slices.Clone(b.Findings)
	urgent = slices.DeleteFunc(urgent, func(f evidence.Finding) bool {
		return !f.Open() || f.Severity.Rank() > evidence.High.Rank()
	})
	slices.SortStableFunc(urgent, func(a, b evidence.Finding) int { return cmp.Compare(a.Severity.Rank(), b.Severity.Rank()) })
	for _, f := range urgent {
		v.FixFirst = append(v.FixFirst, fixItem{ID: f.ID, Severity: string(f.Severity), Title: f.Title, Fix: oneLine(f.Fix)})
	}
	byModule := map[string][]evidence.Finding{}
	for _, f := range b.Findings {
		m := evidence.ModuleOf(f.Rule)
		byModule[m] = append(byModule[m], f)
	}
	for _, m := range evidence.Modules {
		v.Sections = append(v.Sections, section{Module: m, Title: moduleTitles[m], Status: b.ModuleState(m), Findings: byModule[m]})
	}
	if fs := byModule[evidence.ModOther]; len(fs) > 0 {
		v.Sections = append(v.Sections, section{Module: evidence.ModOther, Title: moduleTitles[evidence.ModOther], Status: evidence.ModuleRan, Findings: fs})
	}
	return v
}

// oneLine returns the first line of s, trimmed and capped.
func oneLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if r := []rune(s); len(r) > 240 {
		s = string(r[:239]) + "…"
	}
	return s
}

// location renders a finding's evidence anchor: path!member@offset.
func location(e evidence.Evidence) string {
	s := e.Path
	if e.Member != "" {
		s += "!" + e.Member
	}
	if e.Offset != nil {
		s += "@" + strconv.FormatInt(*e.Offset, 10)
	}
	return s
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func statusText(st string) string {
	switch st {
	case evidence.ModuleRan:
		return "ran"
	case evidence.ModuleSkipped:
		return "skipped (--skip)"
	case evidence.ModuleFailed:
		return "failed (no result)"
	}
	return "did not run"
}

func attemptPort(a evidence.EgressAttempt) string {
	if a.Port == 0 {
		return ""
	}
	return strconv.Itoa(a.Port)
}

func scopeText(a evidence.EgressAttempt) string {
	if a.InScope {
		return "in scope (declared)"
	}
	return "OUT OF SCOPE"
}

func sizeText(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 4; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTP"[exp])
}
