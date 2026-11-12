package evidence

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// agr4 is an input that reaches AGR-4; each test case breaks one thing.
func agr4() AGRInput {
	return AGRInput{
		EgressRan: true, TargetStarted: true, WorkloadPassed: true, ObservedWindowS: 600,
		Attempts:     []EgressAttempt{{Kind: KindDNS, Name: "db", InScope: true}},
		ModulesRan:   slices.Clone(Modules),
		ModelsHashed: true, AgentsManifest: true,
	}
}

func fnd(id, rule string, sev Severity, st Status) Finding {
	return Finding{ID: id, Rule: rule, Severity: sev, Status: st}
}

func TestComputeLevels(t *testing.T) {
	tests := []struct {
		name      string
		mut       func(*AGRInput)
		level     string
		next      string // next_level of the blocking entries ("" = none)
		reasons   []string
		ids       []string
		window    int64
		noWindows bool
	}{
		{name: "all conditions hold", mut: func(*AGRInput) {}, level: LevelAGR4, window: 600},
		// §5 --skip rows.
		{name: "skip egress", mut: func(in *AGRInput) { in.Skipped = []string{ModEgress} }, level: LevelUnassessed,
			next: LevelAGR0, reasons: []string{"egress module skipped (--skip egress): static-only report, no level claimed"}},
		{name: "egress did not run", mut: func(in *AGRInput) { in.EgressRan = false }, level: LevelUnassessed,
			next: LevelAGR0, reasons: []string{"egress module did not run: static-only report, no level claimed"}},
		{name: "harness failed", mut: func(in *AGRInput) { in.HarnessFailed = true }, level: LevelUnassessed,
			next: LevelAGR0, reasons: []string{"egress harness failed: no level claimed"}},
		{name: "skip phonehome", mut: func(in *AGRInput) { in.Skipped = []string{ModPhoneHome} }, level: LevelAGR2,
			next: LevelAGR3, reasons: []string{"phonehome module skipped (--skip phonehome)"}, window: 600},
		{name: "skip crypto", mut: func(in *AGRInput) { in.Skipped = []string{ModCrypto} }, level: LevelAGR2,
			next: LevelAGR3, reasons: []string{"crypto module skipped (--skip crypto)"}, window: 600},
		{name: "skip models", mut: func(in *AGRInput) { in.Skipped = []string{ModModels} }, level: LevelAGR2,
			next: LevelAGR3, reasons: []string{"models module skipped (--skip models)"}, window: 600},
		{name: "models not run", mut: func(in *AGRInput) { in.ModulesRan = []string{ModEgress, ModPhoneHome, ModCrypto} }, level: LevelAGR2,
			next: LevelAGR3, reasons: []string{"models module did not run"}, window: 600},
		{name: "skip agents", mut: func(in *AGRInput) { in.Skipped = []string{ModAgents} }, level: LevelAGR3,
			next: LevelAGR4, reasons: []string{"agents module skipped (--skip agents)"}, window: 600},
		{name: "no agents manifest", mut: func(in *AGRInput) { in.AgentsManifest = false }, level: LevelAGR3,
			next: LevelAGR4, reasons: []string{"agents module did not run (no agents manifest supplied)"}, window: 600},
		// §1 transitions.
		{name: "target did not start", mut: func(in *AGRInput) { in.TargetStarted, in.WorkloadPassed = false, false }, level: LevelAGR0,
			next: LevelAGR1, reasons: []string{"target did not start or become healthy with all egress blocked", "workload failed with all egress blocked"}, window: 600},
		{name: "workload failed", mut: func(in *AGRInput) { in.WorkloadPassed = false }, level: LevelAGR0,
			next: LevelAGR1, reasons: []string{"workload failed with all egress blocked"}, window: 600},
		{name: "out-of-scope attempts", mut: func(in *AGRInput) {
			in.Attempts = append(in.Attempts, EgressAttempt{Kind: KindDNS, Name: "a.example"}, EgressAttempt{Kind: KindTCP, Name: "a.example", Port: 443})
			in.Findings = []Finding{fnd("EG-0001", RuleEgressAttempt, High, StatusOpen), fnd("EG-0002", RuleEgressAttempt, High, StatusOpen)}
		}, level: LevelAGR1, next: LevelAGR2, reasons: []string{"2 out-of-scope egress attempts"}, ids: []string{"EG-0001", "EG-0002"}, window: 600},
		{name: "one attempt without a finding still blocks", mut: func(in *AGRInput) {
			in.Attempts = []EgressAttempt{{Kind: KindICMP, OrigDstIP: "8.8.8.8"}}
		}, level: LevelAGR1, next: LevelAGR2, reasons: []string{"1 out-of-scope egress attempt"}, window: 600},
		{name: "in-scope attempts don't count", mut: func(in *AGRInput) {
			in.Attempts = append(in.Attempts, EgressAttempt{Kind: KindTCP, OrigDstIP: "10.0.0.1", Port: 5432, InScope: true})
		}, level: LevelAGR4, window: 600},
		{name: "model artefact not hashed", mut: func(in *AGRInput) { in.ModelsHashed = false }, level: LevelAGR2,
			next: LevelAGR3, reasons: []string{"not every model artefact is hashed in the AI-BOM"}, window: 600},
		{name: "INV-01 violations", mut: func(in *AGRInput) {
			in.Findings = []Finding{fnd("AG-0001", "AGENT-INV01-PATH", High, StatusOpen)}
			in.INV01Violations = 1
		}, level: LevelAGR3, next: LevelAGR4, reasons: []string{"1 INV-01 violation"}, ids: []string{"AG-0001"}, window: 600},
		// Ruling (agents module): AGENT-INV01-* is unwaivable but never counts
		// toward AGR-3's unwaivable check; it blocks AGR-4 only.
		{name: "unwaivable INV-01 findings don't block AGR-3", mut: func(in *AGRInput) {
			in.Findings = []Finding{fnd("AG-0001", "AGENT-INV01-READ-TO-SINK", Critical, StatusOpen), fnd("AG-0002", "AGENT-INV01-READ-TO-EXEC", Low, StatusOpen)}
		}, level: LevelAGR3, next: LevelAGR4, reasons: []string{"2 INV-01 violations"}, ids: []string{"AG-0001", "AG-0002"}, window: 600},
		{name: "INV-01 count without findings", mut: func(in *AGRInput) { in.INV01Violations = 3 }, level: LevelAGR3,
			next: LevelAGR4, reasons: []string{"3 INV-01 violations"}, window: 600},
		{name: "medium findings don't block", mut: func(in *AGRInput) {
			in.Findings = []Finding{fnd("CR-0001", "CRYPTO-WEAK-HASH", Medium, StatusOpen)}
		}, level: LevelAGR4, window: 600},
		{name: "several AGR-3 blockers are all listed", mut: func(in *AGRInput) {
			in.Skipped = []string{ModCrypto}
			in.ModelsHashed = false
			in.Findings = []Finding{fnd("MD-0001", "MODEL-PICKLE-CODE-EXEC", Critical, StatusOpen), fnd("PH-0001", "PH-X", High, StatusOpen)}
		}, level: LevelAGR2, next: LevelAGR3, reasons: []string{
			"crypto module skipped (--skip crypto)",
			"1 unwaivable finding (fix required, AGR_SPEC §4)",
			"1 open high/critical finding (fix, or accept in the waivers file)",
			"not every model artefact is hashed in the AI-BOM",
		}, ids: []string{"MD-0001", "PH-0001"}, window: 600},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := agr4()
			tt.mut(&in)
			got := Compute(in)
			if got.Level != tt.level {
				t.Fatalf("level = %s, want %s (blocking %+v)", got.Level, tt.level, got.Blocking)
			}
			if got.SpecVersion != AGRSpecVersion || got.ObservedWindowS != tt.window {
				t.Errorf("spec/window = %s/%d", got.SpecVersion, got.ObservedWindowS)
			}
			var reasons, ids []string
			for _, b := range got.Blocking {
				if b.NextLevel != tt.next {
					t.Errorf("blocking next_level %s, want %s", b.NextLevel, tt.next)
				}
				if b.FindingIDs == nil {
					t.Error("finding_ids must be [] not null")
				}
				reasons = append(reasons, b.Reason)
				ids = append(ids, b.FindingIDs...)
			}
			if !slices.Equal(reasons, tt.reasons) {
				t.Errorf("reasons:\n got %q\nwant %q", reasons, tt.reasons)
			}
			if !slices.Equal(ids, tt.ids) {
				t.Errorf("ids = %q, want %q", ids, tt.ids)
			}
		})
	}
}

// TestWaivableTable covers every row of AGR_SPEC §4, both as Waivable and
// as its effect on the level: a waivable high finding reaches AGR-3 once
// waived; an unwaivable one blocks AGR-3 at any severity and status.
func TestWaivableTable(t *testing.T) {
	rows := []struct {
		rule     string
		waivable bool
	}{
		{"PH-CHROMA-TELEMETRY", true},
		{"CRYPTO-UNVALIDATED-MODULE", true},
		{"CRYPTO-UNKNOWN-MODULE", true},
		{"CRYPTO-WEAK-HASH", true},
		{RuleEgressAttempt, false},
		{"MODEL-PICKLE-CODE-EXEC", false},
		{"MODEL-PICKLE-UNKNOWN-IMPORT", false},
		{"MODEL-PICKLE-UNRESOLVED-IMPORT", false},
		{"MODEL-KERAS-LAMBDA", false},
		{"MODEL-KERAS-UNSAFE-MODULE", false},
		{"MODEL-TORCHSCRIPT", false},
		{"MODEL-CHAT-TEMPLATE-SUSPICIOUS", false},
		{"MODEL-REMOTE-CODE", false},
		{"MODEL-ONNX-EXTERNAL-DATA-ESCAPE", false},
		{"MODEL-ARCHIVE-ANOMALY", false},
		{"MODEL-PARSE-FAILED", true},
		{"MODEL-UNSCANNED-FORMAT", true},
		{"MODEL-ONNX-EXTERNAL-DATA-MISSING", true},
		{"MODEL-NUMPY-OBJECT-ARRAY", true},
		{"AGENT-INV01-READ-TO-SINK", false},
		{"MODEL-SOMETHING-NEW", false}, // unknown rules fail closed
		{"HARNESS-NET-ADMIN", false},
	}
	for _, r := range rows {
		t.Run(r.rule, func(t *testing.T) {
			if got := Waivable(r.rule); got != r.waivable {
				t.Fatalf("Waivable = %v, want %v", got, r.waivable)
			}
			if r.rule == RuleEgressAttempt || strings.HasPrefix(r.rule, RuleAgentPrefix) {
				return // they gate AGR-2 and AGR-4 (TestComputeLevels)
			}
			in := agr4()
			in.Findings = []Finding{fnd("X-0001", r.rule, High, StatusWaived)}
			got := Compute(in)
			if r.waivable && got.Level != LevelAGR4 {
				t.Errorf("waived %s: level %s, want AGR-4", r.rule, got.Level)
			}
			if !r.waivable && got.Level != LevelAGR2 {
				t.Errorf("unwaivable %s: level %s, want AGR-2", r.rule, got.Level)
			}
			in.Findings[0].Status = StatusOpen
			if got := Compute(in); got.Level != LevelAGR2 {
				t.Errorf("open high %s: level %s, want AGR-2", r.rule, got.Level)
			}
			in.Findings[0].Severity = Low
			want := LevelAGR4
			if !r.waivable {
				want = LevelAGR2
			}
			if got := Compute(in); got.Level != want {
				t.Errorf("open low %s: level %s, want %s", r.rule, got.Level, want)
			}
		})
	}
}

func TestMeetsMin(t *testing.T) {
	tests := []struct {
		level string
		n     int
		want  bool
	}{
		{LevelUnassessed, -1, true},
		{LevelUnassessed, 0, false},
		{"garbage", 0, false},
		{LevelAGR0, 0, true},
		{LevelAGR0, 1, false},
		{LevelAGR1, 1, true},
		{LevelAGR2, 3, false},
		{LevelAGR3, 3, true},
		{LevelAGR4, 4, true},
		{LevelAGR4, 0, true},
	}
	for _, tt := range tests {
		if got := MeetsMin(tt.level, tt.n); got != tt.want {
			t.Errorf("MeetsMin(%s, %d) = %v, want %v", tt.level, tt.n, got, tt.want)
		}
	}
	if LevelRank(LevelUnassessed) != -1 || LevelRank(LevelAGR4) != 4 || LevelRank("x") != -1 {
		t.Error("LevelRank")
	}
}

// TestEndToEndLevel runs the pipeline a scan uses: attempts → scope →
// egress findings → Finalize with waivers → bundle → Compute.
func TestEndToEndLevel(t *testing.T) {
	scope, err := ParseScope([]byte("scope_version: 1\ninternal_names: [db]\n"))
	if err != nil {
		t.Fatal(err)
	}
	attempts := scope.Mark([]EgressAttempt{{Kind: KindDNS, Name: "db"}}, "app")
	w, err := ParseWaivers([]byte(`waivers_version: 1
waivers:
  - rule: CRYPTO-UNVALIDATED-MODULE
    match: {path: lib/libcrypto.so.3}
    justification: accepted
    owner: sec@vendor.example
    expires: 2027-01-01
`))
	if err != nil {
		t.Fatal(err)
	}
	raw := append(EgressFindings(attempts), Finding{Rule: "CRYPTO-UNVALIDATED-MODULE", Severity: High, Evidence: Evidence{Path: "lib/libcrypto.so.3"}})
	fs, wr, err := Finalize(raw, w, time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	b := Bundle{
		Modules: []ModuleStatus{{Name: ModEgress, Status: ModuleRan}, {Name: ModPhoneHome, Status: ModuleRan},
			{Name: ModCrypto, Status: ModuleRan}, {Name: ModModels, Status: ModuleRan}, {Name: ModAgents, Status: ModuleNotRun}},
		Egress:   &EgressSection{TargetStarted: true, WorkloadPassed: true, ObservedWindowS: 180, Attempts: attempts},
		Models:   &ModelsSection{},
		Findings: fs, Waivers: wr,
	}
	got := Compute(b.AGRInput())
	if got.Level != LevelAGR3 || got.ObservedWindowS != 180 {
		t.Fatalf("got %+v, want AGR-3 observed 180", got)
	}
	if got.LevelLabel() != "AGR-3 (observed 3m)" {
		t.Errorf("label %q", got.LevelLabel())
	}
	b.Modules[0].Status = ModuleFailed
	if got := Compute(b.AGRInput()); got.Level != LevelUnassessed {
		t.Errorf("failed egress module: %s", got.Level)
	}
	b.Modules[0].Status = ModuleSkipped
	if got := Compute(b.AGRInput()); got.Level != LevelUnassessed {
		t.Errorf("skipped egress module: %s", got.Level)
	}
}

// Validation findings (AGR vs spec audit, 2026-11-12).
func TestComputeFailsClosed(t *testing.T) {
	cases := []struct {
		name  string
		mut   func(*AGRInput)
		level string
	}{
		{"zero window is not silence", func(in *AGRInput) { in.ObservedWindowS = 0 }, LevelAGR1},
		{"negative window", func(in *AGRInput) { in.ObservedWindowS = -5 }, LevelAGR1},
		{"non-INV01 agents finding is unwaivable", func(in *AGRInput) {
			in.Findings = []Finding{fnd("A1", "AGENT-MANIFEST-BAD", Critical, StatusOpen)}
		}, LevelAGR2},
		{"agents info note does not gate", func(in *AGRInput) {
			in.Findings = []Finding{fnd("A1", "AGENT-NEARMISS-x", Info, StatusOpen)}
		}, LevelAGR4},
		{"unknown severity ranks as critical", func(in *AGRInput) {
			in.Findings = []Finding{fnd("P1", "PH-X", Severity("HIGH"), StatusOpen)}
		}, LevelAGR2},
		{"empty severity ranks as critical", func(in *AGRInput) {
			in.Findings = []Finding{fnd("P1", "PH-X", "", StatusOpen)}
		}, LevelAGR2},
	}
	for _, c := range cases {
		in := agr4()
		c.mut(&in)
		if got := Compute(in).Level; got != c.level {
			t.Errorf("%s: level %s, want %s", c.name, got, c.level)
		}
	}
}

func TestAllHashedNeedsHex(t *testing.T) {
	m := &ModelsSection{Artifacts: []ModelArtifact{{SHA256: strings.Repeat("z", 64)}}}
	if m.AllHashed() {
		t.Error("64 non-hex chars counted as a hash")
	}
	m.Artifacts[0].SHA256 = strings.Repeat("a", 64)
	if !m.AllHashed() {
		t.Error("valid hex hash rejected")
	}
}
