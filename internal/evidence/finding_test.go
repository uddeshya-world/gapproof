package evidence

import (
	"slices"
	"testing"
)

func TestSortIsDeterministic(t *testing.T) {
	mk := func(path, member string, off *int64, rule, detail string) Finding {
		return Finding{Rule: rule, Evidence: Evidence{Path: path, Member: member, Offset: off, Detail: detail}}
	}
	want := []Finding{
		mk("a", "", nil, "R2", ""),
		mk("a", "", Off(5), "R1", ""),
		mk("a", "", Off(5), "R2", "x"),
		mk("a", "", Off(5), "R2", "y"),
		mk("a", "m", nil, "R1", ""),
		mk("b", "", nil, "R1", ""),
	}
	got := slices.Clone(want)
	slices.Reverse(got)
	Sort(got)
	for i := range want {
		if got[i].Evidence.Path != want[i].Evidence.Path || got[i].Rule != want[i].Rule || got[i].Evidence.Detail != want[i].Evidence.Detail || got[i].Evidence.Member != want[i].Evidence.Member {
			t.Fatalf("position %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestSeverityRank(t *testing.T) {
	order := []Severity{Critical, High, Medium, Low, Info}
	for i := 1; i < len(order); i++ {
		if order[i-1].Rank() >= order[i].Rank() {
			t.Errorf("%s should rank above %s", order[i-1], order[i])
		}
	}
	if Severity("bogus").Rank() != Info.Rank() {
		t.Error("unknown severities rank lowest")
	}
}
