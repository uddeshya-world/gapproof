package evidence

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

// Module names, in report and ID order.
const (
	ModEgress    = "egress"
	ModPhoneHome = "phonehome"
	ModCrypto    = "crypto"
	ModModels    = "models"
	ModAgents    = "agents"
	ModOther     = "other"
)

// Modules lists the scan modules in canonical order (ModOther is not a module).
var Modules = []string{ModEgress, ModPhoneHome, ModCrypto, ModModels, ModAgents}

var modulePrefix = map[string]string{
	ModEgress: "EG", ModPhoneHome: "PH", ModCrypto: "CR", ModModels: "MD", ModAgents: "AG", ModOther: "OT",
}

func moduleRank(m string) int {
	if i := slices.Index(Modules, m); i >= 0 {
		return i
	}
	return len(Modules)
}

// ModuleOf maps a rule ID to the module that emits it.
func ModuleOf(rule string) string {
	switch {
	case strings.HasPrefix(rule, "EGRESS-"), strings.HasPrefix(rule, "HARNESS-"):
		return ModEgress
	case strings.HasPrefix(rule, "PH-"):
		return ModPhoneHome
	case strings.HasPrefix(rule, "CRYPTO-"):
		return ModCrypto
	case strings.HasPrefix(rule, "MODEL-"):
		return ModModels
	case strings.HasPrefix(rule, "AGENT-"):
		return ModAgents
	}
	return ModOther
}

// compareFindings is the total order used for ID assignment: module, then
// the scanners' order (Sort), then every remaining field so that input
// order never leaks into the output.
func compareFindings(a, b Finding) int {
	return cmp.Or(
		cmp.Compare(moduleRank(ModuleOf(a.Rule)), moduleRank(ModuleOf(b.Rule))),
		cmp.Compare(a.Evidence.Path, b.Evidence.Path),
		cmp.Compare(a.Evidence.Member, b.Evidence.Member),
		cmp.Compare(offset(a), offset(b)),
		cmp.Compare(a.Rule, b.Rule),
		cmp.Compare(a.Evidence.Detail, b.Evidence.Detail),
		cmp.Compare(a.Severity.Rank(), b.Severity.Rank()),
		cmp.Compare(a.Title, b.Title),
		cmp.Compare(a.Evidence.SHA256, b.Evidence.SHA256),
		cmp.Compare(a.Explanation, b.Explanation),
		cmp.Compare(a.Fix, b.Fix),
		slices.Compare(a.Controls, b.Controls),
	)
}

// AssignIDs sorts findings deterministically and numbers them per module:
// EG-0001, PH-0001, CR-0001, MD-0001, AG-0001 (OT- for unknown rules).
func AssignIDs(fs []Finding) {
	slices.SortStableFunc(fs, compareFindings)
	next := map[string]int{}
	for i := range fs {
		m := ModuleOf(fs[i].Rule)
		next[m]++
		fs[i].ID = fmt.Sprintf("%s-%04d", modulePrefix[m], next[m])
	}
}
