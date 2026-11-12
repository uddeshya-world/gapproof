// Package oscal renders findings as an OSCAL 1.1.2 assessment-results
// document (oscal-ar.json, docs/02_SPEC.md §3.6).
//
// One observation per Gapproof finding; one OSCAL finding per (finding,
// mapped control) pair, related to its observation. The control mapping is
// informative (CLAUDE.md rule 4) and every document says so. UUIDs are
// derived from content (internal/detid), and the only timestamps are the
// run's start/end passed in by the caller, so output is deterministic.
package oscal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/uddeshya-world/gapproof/internal/detid"
	"github.com/uddeshya-world/gapproof/internal/evidence"
)

const (
	// FileName is the document's name in the evidence directory.
	FileName = "oscal-ar.json"
	// Version is the OSCAL version the output targets.
	Version = "1.1.2"
	// NS qualifies Gapproof's own property names.
	NS = "https://github.com/uddeshya-world/gapproof/ns/oscal"

	// Informative is stated on the document, the result and every finding.
	Informative = "Control mappings are informative, not a determination of compliance. Gapproof reports an inventory and findings; it does not grant an ATO, certify FIPS 140-3 or accredit a system."
)

// Input is everything the document is built from.
type Input struct {
	ToolVersion   string
	Started       time.Time // run start (run metadata); required
	Ended         time.Time // run end; optional
	Subject       string    // human name of the scanned artefact
	SubjectDigest string    // image config digest, if any
	Level         string    // AGR level, if computed
	Findings      []evidence.Finding
	// StatusOf returns a finding's status ("open", "waived", ...). nil
	// means every finding is open.
	StatusOf func(evidence.Finding) string
}

// mapping is spec §3.6, NIST SP 800-53 rev. 5 control ids.
var (
	ctlEgress     = []string{"sc-7", "ac-4"}
	ctlTelemetry  = []string{"cm-7"}
	ctlCrypto     = []string{"sc-12", "sc-13"}
	ctlProvenance = []string{"cm-8", "sr-3", "sr-4"}
	ctlCodeExec   = []string{"si-3", "si-7"}
	ctlAgents     = []string{"ac-3", "ac-4", "ac-6"}
)

// codeOnLoad are the model rules that are unsafe deserialization.
var codeOnLoad = map[string]bool{
	"MODEL-PICKLE-CODE-EXEC": true, "MODEL-PICKLE-UNKNOWN-IMPORT": true, "MODEL-PICKLE-UNRESOLVED-IMPORT": true,
	"MODEL-TORCHSCRIPT": true, "MODEL-KERAS-LAMBDA": true, "MODEL-KERAS-UNSAFE-MODULE": true,
	"MODEL-NUMPY-OBJECT-ARRAY": true, "MODEL-REMOTE-CODE": true, "MODEL-CHAT-TEMPLATE-SUSPICIOUS": true,
}

// ReviewedControls is every control the mapping table can produce, sorted.
func ReviewedControls() []string {
	var all []string
	for _, c := range [][]string{ctlEgress, ctlTelemetry, ctlCrypto, ctlProvenance, ctlCodeExec, ctlAgents} {
		all = append(all, c...)
	}
	return sortedUnique(all)
}

// Controls returns the informative control ids (lowercase OSCAL form, e.g.
// "sc-7") for a finding: the spec §3.6 table by rule family, plus any
// controls the finding itself names.
func Controls(f evidence.Finding) []string {
	var cs []string
	r := f.Rule
	switch {
	case strings.HasPrefix(r, "EGRESS-"), strings.HasPrefix(r, "EG-"):
		cs = ctlEgress
	case strings.HasPrefix(r, "PH-"):
		cs = ctlTelemetry
	case strings.HasPrefix(r, "CRYPTO-"):
		cs = ctlCrypto
	case codeOnLoad[r]:
		cs = ctlCodeExec
	case strings.HasPrefix(r, "MODEL-"):
		cs = ctlProvenance
	case strings.HasPrefix(r, "AGENT-"):
		cs = ctlAgents
	}
	all := slices.Clone(cs)
	for _, c := range f.Controls {
		if c = strings.ToLower(strings.TrimSpace(c)); c != "" && tokenOK(c) {
			all = append(all, c)
		}
	}
	return sortedUnique(all)
}

func sortedUnique(xs []string) []string {
	xs = slices.Clone(xs)
	slices.Sort(xs)
	return slices.Compact(xs)
}

// tokenOK is a conservative subset of the OSCAL token datatype.
func tokenOK(s string) bool {
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r == '_':
		case i > 0 && (r >= '0' && r <= '9' || r == '.' || r == '-'):
		default:
			return false
		}
	}
	return s != ""
}

// ---- document model (field order = JSON order) ----

// Document is the top-level OSCAL object.
type Document struct {
	AssessmentResults AssessmentResults `json:"assessment-results"`
}

type AssessmentResults struct {
	UUID       string     `json:"uuid"`
	Metadata   Metadata   `json:"metadata"`
	ImportAP   ImportAP   `json:"import-ap"`
	Results    []Result   `json:"results"`
	BackMatter BackMatter `json:"back-matter"`
}

type Metadata struct {
	Title        string `json:"title"`
	LastModified string `json:"last-modified"`
	Version      string `json:"version"`
	OSCALVersion string `json:"oscal-version"`
	Remarks      string `json:"remarks"`
}

type ImportAP struct {
	Href    string `json:"href"`
	Remarks string `json:"remarks"`
}

type Result struct {
	UUID             string            `json:"uuid"`
	Title            string            `json:"title"`
	Description      string            `json:"description"`
	Start            string            `json:"start"`
	End              string            `json:"end,omitempty"`
	Props            []Prop            `json:"props,omitempty"`
	ReviewedControls ReviewedControlsT `json:"reviewed-controls"`
	Observations     []Observation     `json:"observations,omitempty"`
	Findings         []Finding         `json:"findings,omitempty"`
	Remarks          string            `json:"remarks"`
}

type Prop struct {
	Name  string `json:"name"`
	NS    string `json:"ns,omitempty"`
	Value string `json:"value"`
}

type ReviewedControlsT struct {
	ControlSelections []ControlSelection `json:"control-selections"`
	Remarks           string             `json:"remarks"`
}

type ControlSelection struct {
	IncludeControls []ControlRef `json:"include-controls"`
}

type ControlRef struct {
	ControlID string `json:"control-id"`
}

type Observation struct {
	UUID             string     `json:"uuid"`
	Title            string     `json:"title"`
	Description      string     `json:"description"`
	Props            []Prop     `json:"props,omitempty"`
	Methods          []string   `json:"methods"`
	Types            []string   `json:"types"`
	RelevantEvidence []Evidence `json:"relevant-evidence,omitempty"`
	Collected        string     `json:"collected"`
	Remarks          string     `json:"remarks,omitempty"`
}

type Evidence struct {
	Description string `json:"description"`
	Props       []Prop `json:"props,omitempty"`
}

type Finding struct {
	UUID                string       `json:"uuid"`
	Title               string       `json:"title"`
	Description         string       `json:"description"`
	Props               []Prop       `json:"props,omitempty"`
	Target              Target       `json:"target"`
	RelatedObservations []RelatedObs `json:"related-observations"`
	Remarks             string       `json:"remarks"`
}

type Target struct {
	Type     string `json:"type"`
	TargetID string `json:"target-id"`
	Status   Status `json:"status"`
}

type Status struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

type RelatedObs struct {
	ObservationUUID string `json:"observation-uuid"`
}

type BackMatter struct {
	Resources []Resource `json:"resources"`
}

type Resource struct {
	UUID        string `json:"uuid"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

// ---- building ----

// line makes a value valid for OSCAL's single-line string datatype:
// whitespace runs collapse to one space, and the ends are trimmed.
func line(s string) string { return strings.Join(strings.Fields(s), " ") }

func prop(name, value string) (Prop, bool) {
	v := line(value)
	return Prop{Name: name, NS: NS, Value: v}, v != ""
}

func props(kv ...string) []Prop {
	var ps []Prop
	for i := 0; i+1 < len(kv); i += 2 {
		if p, ok := prop(kv[i], kv[i+1]); ok {
			ps = append(ps, p)
		}
	}
	return ps
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// findingKey identifies a finding for UUID derivation.
func findingKey(f evidence.Finding) string {
	off := ""
	if f.Evidence.Offset != nil {
		off = strconv.FormatInt(*f.Evidence.Offset, 10)
	}
	return strings.Join([]string{f.ID, f.Rule, f.Evidence.Path, f.Evidence.Member, off, f.Evidence.Detail}, "\x00")
}

// Build constructs the document.
func Build(in Input) (*Document, error) {
	if in.Started.IsZero() {
		return nil, errors.New("oscal: run start time is required")
	}
	if !in.Ended.IsZero() && in.Ended.Before(in.Started) {
		return nil, errors.New("oscal: run end is before its start")
	}
	fs := slices.Clone(in.Findings)
	evidence.Sort(fs)
	statusOf := in.StatusOf
	if statusOf == nil {
		statusOf = func(evidence.Finding) string { return "open" }
	}

	// Seed: a hash of everything that defines the document, so UUIDs are
	// stable across runs of identical input and differ otherwise.
	seedSrc, err := json.Marshal(struct {
		V, Sub, Dig, Lvl, S, E string
		F                      []evidence.Finding
		St                     []string
	}{in.ToolVersion, in.Subject, in.SubjectDigest, in.Level, ts(in.Started), endStr(in.Ended), fs, statuses(fs, statusOf)})
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(seedSrc)
	seed := hex.EncodeToString(sum[:])
	id := func(parts ...string) string { return detid.UUID("gapproof/oscal-ar/"+seed, parts...) }

	subject := in.Subject
	if subject == "" {
		subject = "scanned artefact"
	}
	version := line(in.ToolVersion)
	if version == "" {
		version = "unversioned"
	}
	lastMod := in.Ended
	if lastMod.IsZero() {
		lastMod = in.Started
	}
	planRes := id("back-matter", "plan")

	res := Result{
		UUID:        id("result"),
		Title:       "Gapproof air-gap readiness scan of " + subject,
		Description: "Static and runtime checks of " + subject + " by Gapproof " + version + ": egress, phone-home configuration, crypto inventory, model artefacts and agent tool paths, as enabled for this run.",
		Start:       ts(in.Started),
		End:         endStr(in.Ended),
		Props:       props("subject-digest", in.SubjectDigest, "agr-level", in.Level),
		ReviewedControls: ReviewedControlsT{
			ControlSelections: []ControlSelection{{IncludeControls: controlRefs(ReviewedControls())}},
			Remarks:           "NIST SP 800-53 rev. 5 controls that Gapproof's checks inform (docs/02_SPEC.md §3.6). " + Informative,
		},
		Remarks: Informative,
	}
	for i, f := range fs {
		obsID := id("observation", strconv.Itoa(i), findingKey(f))
		status := line(statusOf(f))
		if status == "" {
			status = "open"
		}
		title := line(f.Title)
		if title == "" {
			title = f.Rule
		}
		desc := strings.TrimSpace(f.Explanation)
		if desc == "" {
			desc = title
		}
		obs := Observation{
			UUID:        obsID,
			Title:       title,
			Description: desc,
			Props:       props("finding-id", f.ID, "rule", f.Rule, "severity", string(f.Severity), "status", status),
			Methods:     []string{"TEST"},
			Types:       []string{"finding"},
			Collected:   ts(in.Started),
		}
		if ev := evidenceOf(f); ev != nil {
			obs.RelevantEvidence = []Evidence{*ev}
		}
		if fix := strings.TrimSpace(f.Fix); fix != "" {
			obs.Remarks = "Fix: " + fix
		}
		res.Observations = append(res.Observations, obs)

		for _, c := range Controls(f) {
			st := Status{State: "not-satisfied", Reason: "fail"}
			remarks := "Open finding. " + Informative
			if status != "open" {
				st.Reason = "other"
				remarks = "Finding status: " + status + " (accepted risk is recorded, not resolved). " + Informative
			}
			res.Findings = append(res.Findings, Finding{
				UUID:        id("finding", obsID, c),
				Title:       title + " (" + strings.ToUpper(c) + ")",
				Description: "Gapproof rule " + f.Rule + " is informatively mapped to NIST SP 800-53 " + strings.ToUpper(c) + ".",
				Props:       props("rule", f.Rule, "severity", string(f.Severity), "status", status),
				Target: Target{
					Type:     "objective-id",
					TargetID: c,
					Status:   st,
				},
				RelatedObservations: []RelatedObs{{obsID}},
				Remarks:             remarks,
			})
		}
	}

	return &Document{AssessmentResults{
		UUID: id("document"),
		Metadata: Metadata{
			Title:        "Gapproof assessment results: " + subject,
			LastModified: ts(lastMod),
			Version:      version,
			OSCALVersion: Version,
			Remarks:      Informative,
		},
		ImportAP: ImportAP{
			Href:    "#" + planRes,
			Remarks: "Gapproof runs without a separate OSCAL assessment plan; the referenced resource describes the scan configuration.",
		},
		Results: []Result{res},
		BackMatter: BackMatter{Resources: []Resource{{
			UUID:        planRes,
			Title:       "Gapproof scan configuration",
			Description: "The checks are those of Gapproof " + version + " with the modules and options recorded in summary.json and evidence.json of the same evidence bundle.",
		}}},
	}}, nil
}

func endStr(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return ts(t)
}

func statuses(fs []evidence.Finding, statusOf func(evidence.Finding) string) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = statusOf(f)
	}
	return out
}

func controlRefs(ids []string) []ControlRef {
	out := make([]ControlRef, len(ids))
	for i, c := range ids {
		out[i] = ControlRef{c}
	}
	return out
}

func evidenceOf(f evidence.Finding) *Evidence {
	e := f.Evidence
	var parts []string
	if e.Path != "" {
		parts = append(parts, "path "+e.Path)
	}
	if e.Member != "" {
		parts = append(parts, "member "+e.Member)
	}
	if e.Offset != nil {
		parts = append(parts, "offset "+strconv.FormatInt(*e.Offset, 10))
	}
	if e.SHA256 != "" {
		parts = append(parts, "sha256 "+e.SHA256)
	}
	if e.Detail != "" {
		parts = append(parts, e.Detail)
	}
	if len(parts) == 0 {
		return nil
	}
	off := ""
	if e.Offset != nil {
		off = strconv.FormatInt(*e.Offset, 10)
	}
	return &Evidence{
		Description: strings.Join(parts, "; "),
		Props:       props("path", e.Path, "member", e.Member, "offset", off, "sha256", e.SHA256, "detail", e.Detail),
	}
}

// Marshal renders the document as indented JSON with a trailing newline.
func Marshal(d *Document) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(d); err != nil {
		return nil, fmt.Errorf("oscal: %w", err)
	}
	return buf.Bytes(), nil
}
