package evidence

import (
	"cmp"
	"slices"
)

// Severity of a finding. AGR_SPEC §1: open high/critical findings block AGR-3.
type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

// Rank orders severities, most severe first.
func (s Severity) Rank() int {
	switch s {
	case Critical:
		return 0
	case High:
		return 1
	case Medium:
		return 2
	case Low:
		return 3
	default:
		return 4
	}
}

// Finding is one evidence-backed result (CLAUDE.md rule 5). ID is assigned
// deterministically when a run's findings are aggregated (M4); scanners
// leave it empty.
type Finding struct {
	ID          string   `json:"id,omitempty"`
	Rule        string   `json:"rule"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Explanation string   `json:"explanation"`
	Evidence    Evidence `json:"evidence"`
	Fix         string   `json:"fix"`
	Controls    []string `json:"controls"`
	// Status is "open" or "waived". Scanners leave it empty; Finalize sets
	// it. A waived finding is never deleted (AGR_SPEC §3).
	Status Status     `json:"status,omitempty"`
	Waiver *WaiverRef `json:"waiver,omitempty"`
}

// Status of a finding after waivers are applied.
type Status string

const (
	StatusOpen   Status = "open"
	StatusWaived Status = "waived"
)

// Open reports whether the finding still counts against the level.
func (f Finding) Open() bool { return f.Status != StatusWaived }

// Evidence is the raw, checkable basis for a finding.
type Evidence struct {
	Path   string `json:"path,omitempty"`   // rootfs-relative, slash-separated
	Member string `json:"member,omitempty"` // entry inside an archive (zip member), if any
	SHA256 string `json:"sha256,omitempty"` // of the file at Path
	Offset *int64 `json:"offset,omitempty"` // byte offset inside the file or member
	Detail string `json:"detail,omitempty"` // e.g. "GLOBAL os.system", "location=../../etc/passwd"
}

// Off returns a pointer for Evidence.Offset.
func Off(n int64) *int64 { return &n }

// Sort orders findings deterministically: path, member, offset, rule, detail (rule 6).
func Sort(fs []Finding) {
	slices.SortStableFunc(fs, func(a, b Finding) int {
		return cmp.Or(
			cmp.Compare(a.Evidence.Path, b.Evidence.Path),
			cmp.Compare(a.Evidence.Member, b.Evidence.Member),
			cmp.Compare(offset(a), offset(b)),
			cmp.Compare(a.Rule, b.Rule),
			cmp.Compare(a.Evidence.Detail, b.Evidence.Detail),
		)
	})
}

func offset(f Finding) int64 {
	if f.Evidence.Offset == nil {
		return -1
	}
	return *f.Evidence.Offset
}
