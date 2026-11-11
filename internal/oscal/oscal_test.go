package oscal

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/uddeshya-world/gapproof/internal/evidence"
)

var update = flag.Bool("update", false, "rewrite golden files")

var (
	t0 = time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)
	t1 = t0.Add(10 * time.Minute)
)

// sampleFindings: the models golden scan's findings plus one finding from
// each other rule family.
func sampleFindings(t *testing.T) []evidence.Finding {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/samples/models-scan.json")
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		Findings []evidence.Finding `json:"findings"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return append(r.Findings,
		evidence.Finding{ID: "EG-0001", Rule: "EGRESS-ATTEMPT", Severity: evidence.High, Title: "Egress attempt to api.openai.com",
			Explanation: "The target tried to reach a public host.\nIt was blocked.", Evidence: evidence.Evidence{Detail: "dns api.openai.com"}, Fix: "Disable the client."},
		evidence.Finding{ID: "PH-0001", Rule: "PH-CHROMA-TELEMETRY", Severity: evidence.Medium, Title: "Chroma telemetry on",
			Evidence: evidence.Evidence{Path: "app/settings.py", SHA256: strings.Repeat("e", 64)}, Controls: []string{"CM-7"}},
		evidence.Finding{ID: "CR-0001", Rule: "CRYPTO-UNVALIDATED-MODULE", Severity: evidence.High, Title: "Unvalidated OpenSSL",
			Evidence: evidence.Evidence{Path: "usr/lib/libssl.so.3"}},
		evidence.Finding{ID: "AG-0001", Rule: "AGENT-INV01-EXFIL", Severity: evidence.Critical, Title: "read_file reaches http_post"},
	)
}

func sampleInput(t *testing.T) Input {
	return Input{
		ToolVersion:   "v0.2.0-test",
		Started:       t0,
		Ended:         t1,
		Subject:       "demo/fixed-rag:1.0",
		SubjectDigest: "sha256:" + strings.Repeat("ab", 32),
		Level:         "AGR-1",
		Findings:      sampleFindings(t),
		StatusOf: func(f evidence.Finding) string {
			if f.ID == "CR-0001" {
				return "waived"
			}
			return "open"
		},
	}
}

func render(t *testing.T, in Input) []byte {
	t.Helper()
	d, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestGolden(t *testing.T) {
	raw := render(t, sampleInput(t))
	p := filepath.Join("testdata", FileName)
	if *update {
		os.WriteFile(p, raw, 0o644)
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (run with -update)", err)
	}
	if !bytes.Equal(raw, want) {
		t.Error("oscal-ar.json differs from golden (review, then -update)")
	}
	// Deterministic, even with findings in a different input order.
	in := sampleInput(t)
	slices.Reverse(in.Findings)
	if !bytes.Equal(render(t, in), raw) {
		t.Error("output depends on input finding order")
	}
}

func TestStructure(t *testing.T) {
	in := sampleInput(t)
	d, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	ar := d.AssessmentResults
	r := ar.Results[0]
	if len(r.Observations) != len(in.Findings) {
		t.Errorf("%d observations for %d findings", len(r.Observations), len(in.Findings))
	}
	uuidRe := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	seen := map[string]bool{}
	check := func(u string) {
		if !uuidRe.MatchString(u) || seen[u] {
			t.Errorf("bad or duplicate uuid %q", u)
		}
		seen[u] = true
	}
	check(ar.UUID)
	check(r.UUID)
	obs := map[string]Observation{}
	for _, o := range r.Observations {
		check(o.UUID)
		obs[o.UUID] = o
	}
	targets := map[string]int{}
	for _, f := range r.Findings {
		check(f.UUID)
		if _, ok := obs[f.RelatedObservations[0].ObservationUUID]; !ok {
			t.Errorf("finding %s relates to unknown observation", f.UUID)
		}
		if !strings.Contains(f.Remarks, "informative") {
			t.Errorf("finding %s lacks the informative remark", f.UUID)
		}
		targets[f.Target.TargetID]++
	}
	for _, c := range []string{"sc-7", "ac-4", "cm-7", "sc-12", "sc-13", "si-3", "si-7", "cm-8", "sr-3", "sr-4", "ac-3", "ac-6"} {
		if targets[c] == 0 {
			t.Errorf("no finding targets %s", c)
		}
	}
	if ar.ImportAP.Href != "#"+ar.BackMatter.Resources[0].UUID {
		t.Error("import-ap does not point at the back-matter resource")
	}
	if ar.Metadata.LastModified != "2026-11-09T10:10:00Z" || r.Start != "2026-11-09T10:00:00Z" || r.End != "2026-11-09T10:10:00Z" {
		t.Errorf("times: %s %s %s", ar.Metadata.LastModified, r.Start, r.End)
	}
	for _, s := range []string{ar.Metadata.Remarks, r.Remarks, r.ReviewedControls.Remarks} {
		if !strings.Contains(s, "informative") {
			t.Errorf("missing informative disclaimer: %q", s)
		}
	}
	// The waived finding is recorded as accepted risk, not as satisfied.
	for _, f := range r.Findings {
		if strings.HasPrefix(f.Title, "Unvalidated OpenSSL") {
			if f.Target.Status.State != "not-satisfied" || f.Target.Status.Reason != "other" || !strings.Contains(f.Remarks, "waived") {
				t.Errorf("waived finding = %+v", f)
			}
		}
	}
	// Multi-line text becomes single-line in props.
	for _, o := range r.Observations {
		for _, p := range o.Props {
			if strings.ContainsAny(p.Value, "\n\t") || p.Value != strings.TrimSpace(p.Value) {
				t.Errorf("prop %s value %q not single-line", p.Name, p.Value)
			}
		}
	}
}

func TestMinimalAndErrors(t *testing.T) {
	if _, err := Build(Input{}); err == nil {
		t.Error("missing start accepted")
	}
	if _, err := Build(Input{Started: t1, Ended: t0}); err == nil {
		t.Error("end before start accepted")
	}
	d, err := Build(Input{Started: t0, Findings: []evidence.Finding{{Rule: "X-UNMAPPED"}}})
	if err != nil {
		t.Fatal(err)
	}
	r := d.AssessmentResults.Results[0]
	if r.End != "" || d.AssessmentResults.Metadata.Version != "unversioned" || d.AssessmentResults.Metadata.LastModified != "2026-11-09T10:00:00Z" {
		t.Errorf("defaults: %+v", d.AssessmentResults.Metadata)
	}
	if len(r.Observations) != 1 || len(r.Findings) != 0 || r.Observations[0].Title != "X-UNMAPPED" || r.Observations[0].RelevantEvidence != nil {
		t.Errorf("unmapped finding: %+v", r)
	}
	if len(r.ReviewedControls.ControlSelections[0].IncludeControls) != len(ReviewedControls()) {
		t.Error("reviewed controls should list the whole mapping table")
	}
	// Status defaults to open even if StatusOf returns "".
	d, _ = Build(Input{Started: t0, Findings: []evidence.Finding{{Rule: "PH-X"}}, StatusOf: func(evidence.Finding) string { return " " }})
	if f := d.AssessmentResults.Results[0].Findings[0]; f.Target.Status.Reason != "fail" {
		t.Errorf("blank status: %+v", f)
	}
	// No findings at all.
	d, _ = Build(Input{Started: t0})
	raw, _ := Marshal(d)
	if bytes.Contains(raw, []byte(`"observations"`)) || bytes.Contains(raw, []byte(`"findings"`)) {
		t.Errorf("empty arrays must be omitted (OSCAL minItems 1):\n%s", raw)
	}
}

func TestControls(t *testing.T) {
	tests := []struct {
		f    evidence.Finding
		want string
	}{
		{evidence.Finding{Rule: "EGRESS-DNS"}, "ac-4 sc-7"},
		{evidence.Finding{Rule: "PH-HF-TELEMETRY"}, "cm-7"},
		{evidence.Finding{Rule: "CRYPTO-UNKNOWN-MODULE"}, "sc-12 sc-13"},
		{evidence.Finding{Rule: "MODEL-PICKLE-CODE-EXEC"}, "si-3 si-7"},
		{evidence.Finding{Rule: "MODEL-PARSE-FAILED"}, "cm-8 sr-3 sr-4"},
		{evidence.Finding{Rule: "MODEL-ARCHIVE-ANOMALY", Controls: []string{"SI-7", " SI-7 ", "bad id!", ""}}, "cm-8 si-7 sr-3 sr-4"},
		{evidence.Finding{Rule: "AGENT-INV01-X"}, "ac-3 ac-4 ac-6"},
		{evidence.Finding{Rule: "OTHER", Controls: []string{"AU-2", "1x"}}, "au-2"},
	}
	for _, tc := range tests {
		if got := strings.Join(Controls(tc.f), " "); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.f.Rule, got, tc.want)
		}
	}
}

func TestSchemaValid(t *testing.T) {
	minimal, err := Build(Input{Started: t0, ToolVersion: "v0"})
	if err != nil {
		t.Fatal(err)
	}
	rawMin, _ := Marshal(minimal)
	validateInContainer(t, "oscal-ar", map[string][]byte{
		"oscal-ar.json":         render(t, sampleInput(t)),
		"oscal-ar-minimal.json": rawMin,
	})
}
