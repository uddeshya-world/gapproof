package evidence

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

const dateLayout = "2006-01-02"

// Waivable reports whether a rule may be waived (AGR_SPEC §4). The table is
// an allowlist: phone-home and crypto rules, plus the model rules Gapproof
// can't verify. Every other rule, including any rule not in the table, is
// unwaivable (fail closed).
func Waivable(rule string) bool {
	switch rule {
	case "MODEL-PARSE-FAILED", "MODEL-UNSCANNED-FORMAT",
		"MODEL-ONNX-EXTERNAL-DATA-MISSING", "MODEL-NUMPY-OBJECT-ARRAY":
		return true
	}
	return strings.HasPrefix(rule, "PH-") || strings.HasPrefix(rule, "CRYPTO-")
}

// WaiverMatch selects a finding by its evidence. Every non-empty field must
// equal the finding's field exactly; at least one must be set.
type WaiverMatch struct {
	Path   string `yaml:"path,omitempty" json:"path,omitempty"`
	Member string `yaml:"member,omitempty" json:"member,omitempty"`
	Detail string `yaml:"detail,omitempty" json:"detail,omitempty"`
}

func (m WaiverMatch) matches(e Evidence) bool {
	return (m.Path == "" || m.Path == e.Path) &&
		(m.Member == "" || m.Member == e.Member) &&
		(m.Detail == "" || m.Detail == e.Detail)
}

func (m WaiverMatch) String() string {
	var parts []string
	if m.Path != "" {
		parts = append(parts, "path="+quoteIfNeeded(m.Path))
	}
	if m.Member != "" {
		parts = append(parts, "member="+quoteIfNeeded(m.Member))
	}
	if m.Detail != "" {
		parts = append(parts, "detail="+quoteIfNeeded(m.Detail))
	}
	return strings.Join(parts, " ")
}

// Waiver is one accepted risk (AGR_SPEC §3).
type Waiver struct {
	Index         int         `yaml:"-" json:"index"` // 1-based position in the file
	Rule          string      `yaml:"rule" json:"rule"`
	Match         WaiverMatch `yaml:"match" json:"match"`
	Justification string      `yaml:"justification" json:"justification"`
	Owner         string      `yaml:"owner" json:"owner"`
	Expires       string      `yaml:"expires" json:"expires"` // YYYY-MM-DD, valid through that day (UTC)
}

func (w Waiver) label() string {
	return fmt.Sprintf("waiver #%d (%s %s)", w.Index, w.Rule, w.Match)
}

// WaiverRef is the waiver attached to a waived finding.
type WaiverRef struct {
	Index         int         `json:"index"`
	Match         WaiverMatch `json:"match"`
	Justification string      `json:"justification"`
	Owner         string      `json:"owner"`
	Expires       string      `json:"expires"`
}

// Waivers is a loaded gapproof.waivers.yaml.
type Waivers struct {
	SHA256  string
	Waivers []Waiver
	Raw     []byte
}

type waiversFile struct {
	WaiversVersion int      `yaml:"waivers_version"`
	Waivers        []Waiver `yaml:"waivers"`
}

// LoadWaivers reads and validates a waivers file. Problems, including a
// waiver for an unwaivable rule, are *UsageError.
func LoadWaivers(path string) (*Waivers, error) {
	b, err := readConfig(path, "waivers")
	if err != nil {
		return nil, err
	}
	return ParseWaivers(b)
}

// ParseWaivers validates waivers file bytes (see LoadWaivers).
func ParseWaivers(b []byte) (*Waivers, error) {
	var f waiversFile
	if err := decodeStrict(b, &f, "waivers"); err != nil {
		return nil, err
	}
	if f.WaiversVersion != 1 {
		return nil, usagef("waivers file: waivers_version must be 1, got %d", f.WaiversVersion)
	}
	seen := map[string]int{}
	for i := range f.Waivers {
		w := &f.Waivers[i]
		w.Index = i + 1
		switch {
		case w.Rule == "":
			return nil, usagef("waivers file: waiver #%d: rule is required", w.Index)
		case !Waivable(w.Rule):
			return nil, usagef("waivers file: waiver #%d: %s can't be waived (AGR_SPEC §4); fix the finding instead", w.Index, w.Rule)
		case w.Match == WaiverMatch{}:
			return nil, usagef("waivers file: waiver #%d: match needs at least one of path, member, detail", w.Index)
		case strings.TrimSpace(w.Justification) == "":
			return nil, usagef("waivers file: waiver #%d: justification is required", w.Index)
		case strings.TrimSpace(w.Owner) == "":
			return nil, usagef("waivers file: waiver #%d: owner is required", w.Index)
		}
		if t, err := time.Parse(dateLayout, w.Expires); err != nil || t.Format(dateLayout) != w.Expires {
			return nil, usagef("waivers file: waiver #%d: expires must be a YYYY-MM-DD date, got %q", w.Index, w.Expires)
		}
		key := w.Rule + "\x00" + w.Match.String()
		if j, dup := seen[key]; dup {
			return nil, usagef("waivers file: waivers #%d and #%d are identical", j, w.Index)
		}
		seen[key] = w.Index
	}
	return &Waivers{SHA256: sha256Hex(b), Waivers: f.Waivers, Raw: slices.Clone(b)}, nil
}

// AppliedWaiver records which finding a waiver covered.
type AppliedWaiver struct {
	FindingID string `json:"finding_id"`
	Waiver
}

// WaiverResult is what applying a waivers file did. It goes in evidence.json
// and drives the report's "Accepted risks" section.
type WaiverResult struct {
	SHA256  string          `json:"sha256"`
	Applied []AppliedWaiver `json:"applied"`
	Stale   []Waiver        `json:"stale"`   // matched nothing
	Expired []Waiver        `json:"expired"` // ignored: past expiry on the run date
}

// Warnings lists stale and expired waivers for the run's warnings.
func (r *WaiverResult) Warnings() []string {
	if r == nil {
		return nil
	}
	var out []string
	for _, w := range r.Expired {
		out = append(out, fmt.Sprintf("%s expired on %s and was ignored; the finding is open", w.label(), w.Expires))
	}
	for _, w := range r.Stale {
		out = append(out, fmt.Sprintf("%s is stale: it matches no finding", w.label()))
	}
	return out
}

// Finalize prepares a run's findings: it sorts them, assigns IDs, marks
// every finding open, then applies the waivers valid on runDate. A waiver
// must match exactly one finding: zero is reported as stale, several is a
// *UsageError, as is a finding matched by two waivers. Expired waivers are
// ignored and reported. Waived findings are kept with status "waived".
// w may be nil (no waivers file); the result is then nil too.
func Finalize(findings []Finding, w *Waivers, runDate time.Time) ([]Finding, *WaiverResult, error) {
	fs := slices.Clone(findings)
	for i := range fs {
		fs[i].Status = StatusOpen
		fs[i].Waiver = nil
		fs[i].Controls = slices.Clone(fs[i].Controls)
	}
	AssignIDs(fs)
	if w == nil {
		return fs, nil, nil
	}
	if runDate.IsZero() {
		return nil, nil, fmt.Errorf("finalize: run date is required to evaluate waiver expiry")
	}
	today := runDate.UTC().Format(dateLayout)
	res := &WaiverResult{SHA256: w.SHA256, Applied: []AppliedWaiver{}, Stale: []Waiver{}, Expired: []Waiver{}}
	waivedBy := map[int]Waiver{}
	for _, wv := range w.Waivers {
		if wv.Expires < today {
			res.Expired = append(res.Expired, wv)
			continue
		}
		var hits []int
		for i, f := range fs {
			if f.Rule == wv.Rule && wv.Match.matches(f.Evidence) {
				hits = append(hits, i)
			}
		}
		switch len(hits) {
		case 0:
			res.Stale = append(res.Stale, wv)
			continue
		case 1:
		default:
			ids := make([]string, len(hits))
			for k, i := range hits {
				ids[k] = fs[i].ID
			}
			return nil, nil, usagef("%s matches %d findings (%s); a waiver must match exactly one, so narrow its match",
				wv.label(), len(hits), strings.Join(ids, ", "))
		}
		i := hits[0]
		if prev, dup := waivedBy[i]; dup {
			return nil, nil, usagef("%s and %s both match finding %s", prev.label(), wv.label(), fs[i].ID)
		}
		waivedBy[i] = wv
		fs[i].Status = StatusWaived
		fs[i].Waiver = &WaiverRef{Index: wv.Index, Match: wv.Match, Justification: wv.Justification, Owner: wv.Owner, Expires: wv.Expires}
		res.Applied = append(res.Applied, AppliedWaiver{FindingID: fs[i].ID, Waiver: wv})
	}
	return fs, res, nil
}
