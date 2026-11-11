package evidence

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// SchemaVersion identifies the evidence.json / summary.json layout.
const SchemaVersion = "gapproof.evidence/0.1"

// File names inside an evidence directory (spec §3.6).
const (
	EvidenceFile = "evidence.json"
	SummaryFile  = "summary.json"
)

// maxEvidenceFile bounds what Load reads: evidence may come from elsewhere.
const maxEvidenceFile = 256 << 20

// Module statuses.
const (
	ModuleRan     = "ran"
	ModuleSkipped = "skipped" // --skip
	ModuleFailed  = "failed"  // ran but couldn't produce a result
	ModuleNotRun  = "not-run" // e.g. agents with no manifest
)

// ModuleStatus records whether a module ran.
type ModuleStatus struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Note   string `json:"note,omitempty"`
}

// Target identifies what was scanned.
type Target struct {
	Image          string `json:"image,omitempty"`           // as given on the command line
	ConfigDigest   string `json:"config_digest,omitempty"`   // content binding (D-011)
	ImageID        string `json:"image_id,omitempty"`        // engine image ID
	ArtifactDigest string `json:"artifact_digest,omitempty"` // sha256 of the scanned tar
	Hostname       string `json:"hostname,omitempty"`        // always in scope
}

// EgressSection is the harness result.
type EgressSection struct {
	HarnessFailed   bool            `json:"harness_failed"`
	TargetStarted   bool            `json:"target_started"`
	WorkloadPassed  bool            `json:"workload_passed"`
	ObservedWindowS int64           `json:"observed_window_s"`
	Attempts        []EgressAttempt `json:"attempts"` // deduplicated set
}

// CryptoModule mirrors crypto.Module (same JSON shape).
type CryptoModule struct {
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	Library     string `json:"library"`
	Version     string `json:"version,omitempty"`
	Origin      string `json:"origin"`
	Package     string `json:"package,omitempty"`
	Status      string `json:"status"`
	Certificate string `json:"certificate,omitempty"`
	Note        string `json:"note,omitempty"`
}

// FIPSProvider mirrors crypto.FIPSProvider.
type FIPSProvider struct {
	Path       string `json:"path"`
	Version    string `json:"version,omitempty"`
	Configured bool   `json:"configured"`
}

// CryptoSection is the crypto inventory (findings live in Evidence.Findings).
type CryptoSection struct {
	SnapshotDate  string         `json:"cmvp_snapshot_date"`
	Modules       []CryptoModule `json:"modules"`
	FIPSProviders []FIPSProvider `json:"fips_providers"`
	Configs       []string       `json:"fips_configs"`
}

// ModelArtifact mirrors models.Artifact.
type ModelArtifact struct {
	Path         string            `json:"path"`
	Format       string            `json:"format"`
	Size         int64             `json:"size"`
	SHA256       string            `json:"sha256"`
	License      string            `json:"license,omitempty"`
	Architecture string            `json:"architecture,omitempty"`
	Name         string            `json:"name,omitempty"`
	Tensors      int               `json:"tensors,omitempty"`
	Parameters   int64             `json:"parameters,omitempty"`
	DTypes       []string          `json:"dtypes,omitempty"`
	Imports      []string          `json:"imports,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// ModelsSection lists every model artefact (the AI-BOM source).
type ModelsSection struct {
	Artifacts []ModelArtifact `json:"artifacts"`
}

// AllHashed reports whether every artefact carries a SHA-256.
func (m *ModelsSection) AllHashed() bool {
	if m == nil {
		return false
	}
	for _, a := range m.Artifacts {
		if len(a.SHA256) != 64 {
			return false
		}
	}
	return true
}

// AgentsSection is the agents module result. Its findings are AGENT-INV01-*.
type AgentsSection struct {
	Manifest         string   `json:"manifest"` // vendor-declared manifest the analysis is based on
	ManifestSHA256   string   `json:"manifest_sha256"`
	DeclaredNoAgents bool     `json:"declared_no_agents"` // manifest says agents: []
	Agents           []string `json:"agents"`
	Violations       int      `json:"inv01_violations"`
}

// RunMeta is the only place timestamps live (rule 6). It's written to
// summary.json, never to evidence.json.
type RunMeta struct {
	ID         string    `json:"id"`
	RunDate    string    `json:"run_date"` // YYYY-MM-DD (UTC), used for waiver expiry
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
}

// Bundle is one run's complete result. Everything except Run is a pure
// function of the inputs and is written to evidence.json.
type Bundle struct {
	SchemaVersion    string         `json:"schema_version"`
	ToolVersion      string         `json:"tool_version"`
	RulePackVersion  string         `json:"rule_pack_version"`
	CMVPSnapshotDate string         `json:"cmvp_snapshot_date,omitempty"`
	Target           Target         `json:"target"`
	AGR              AGR            `json:"agr"`
	Modules          []ModuleStatus `json:"modules"`
	Scope            *Scope         `json:"scope"`   // null: no scope file
	Waivers          *WaiverResult  `json:"waivers"` // null: no waivers file
	Egress           *EgressSection `json:"egress,omitempty"`
	Crypto           *CryptoSection `json:"crypto,omitempty"`
	Models           *ModelsSection `json:"models,omitempty"`
	Agents           *AgentsSection `json:"agents,omitempty"`
	Findings         []Finding      `json:"findings"`
	Warnings         []string       `json:"warnings"`
	Run              RunMeta        `json:"-"`
}

// ModuleState returns a module's status (ModuleNotRun if unrecorded).
func (ev *Bundle) ModuleState(name string) string {
	for _, m := range ev.Modules {
		if m.Name == name {
			return m.Status
		}
	}
	return ModuleNotRun
}

// AGRInput derives the level inputs from the evidence itself, so the level
// is always a function of what evidence.json records.
func (ev *Bundle) AGRInput() AGRInput {
	in := AGRInput{Findings: ev.Findings, ModelsHashed: ev.Models.AllHashed()}
	for _, m := range ev.Modules {
		switch m.Status {
		case ModuleRan:
			in.ModulesRan = append(in.ModulesRan, m.Name)
		case ModuleSkipped:
			in.Skipped = append(in.Skipped, m.Name)
		}
	}
	switch st := ev.ModuleState(ModEgress); {
	case st == ModuleRan && ev.Egress != nil:
		in.EgressRan = true
		in.HarnessFailed = ev.Egress.HarnessFailed
		in.TargetStarted = ev.Egress.TargetStarted
		in.WorkloadPassed = ev.Egress.WorkloadPassed
		in.ObservedWindowS = ev.Egress.ObservedWindowS
		in.Attempts = ev.Egress.Attempts
	case st == ModuleFailed:
		in.EgressRan, in.HarnessFailed = true, true
	}
	if ev.Agents != nil && ev.ModuleState(ModAgents) == ModuleRan {
		in.AgentsManifest = true
		in.INV01Violations = ev.Agents.Violations
	}
	return in
}

// Normalize puts the evidence in canonical form: sorted, deduplicated,
// nil slices made empty, and the waivers' warnings merged in. WriteEvidence
// calls it; callers rarely need to.
func (ev *Bundle) Normalize() {
	ev.SchemaVersion = SchemaVersion
	ev.Modules = slices.Clone(ev.Modules)
	slices.SortStableFunc(ev.Modules, func(a, b ModuleStatus) int {
		return cmp.Or(cmp.Compare(moduleRank(a.Name), moduleRank(b.Name)), cmp.Compare(a.Name, b.Name))
	})
	ev.Modules = orEmpty(ev.Modules)
	ev.Findings = orEmpty(slices.Clone(ev.Findings))
	slices.SortStableFunc(ev.Findings, func(a, b Finding) int {
		return cmp.Or(cmp.Compare(moduleRank(ModuleOf(a.Rule)), moduleRank(ModuleOf(b.Rule))), cmp.Compare(a.ID, b.ID), compareFindings(a, b))
	})
	for i := range ev.Findings {
		ev.Findings[i].Controls = orEmpty(ev.Findings[i].Controls)
		if ev.Findings[i].Status == "" {
			ev.Findings[i].Status = StatusOpen
		}
	}
	ev.Warnings = append(slices.Clone(ev.Warnings), ev.Waivers.Warnings()...)
	slices.Sort(ev.Warnings)
	ev.Warnings = orEmpty(slices.Compact(ev.Warnings))
	ev.AGR.Blocking = orEmpty(ev.AGR.Blocking)
	for i := range ev.AGR.Blocking {
		ev.AGR.Blocking[i].FindingIDs = orEmpty(ev.AGR.Blocking[i].FindingIDs)
	}
	if ev.Egress != nil {
		e := *ev.Egress
		e.Attempts = DedupeAttempts(e.Attempts)
		ev.Egress = &e
	}
	if ev.Crypto != nil {
		c := *ev.Crypto
		c.Modules = orEmpty(slices.Clone(c.Modules))
		slices.SortStableFunc(c.Modules, func(a, b CryptoModule) int {
			return cmp.Or(cmp.Compare(a.Path, b.Path), cmp.Compare(a.Library, b.Library), cmp.Compare(a.Version, b.Version))
		})
		c.FIPSProviders = orEmpty(slices.Clone(c.FIPSProviders))
		slices.SortStableFunc(c.FIPSProviders, func(a, b FIPSProvider) int { return cmp.Compare(a.Path, b.Path) })
		c.Configs = orEmpty(slices.Clone(c.Configs))
		slices.Sort(c.Configs)
		ev.Crypto = &c
	}
	if ev.Models != nil {
		m := *ev.Models
		m.Artifacts = orEmpty(slices.Clone(m.Artifacts))
		slices.SortStableFunc(m.Artifacts, func(a, b ModelArtifact) int { return cmp.Compare(a.Path, b.Path) })
		ev.Models = &m
	}
	if ev.Agents != nil {
		a := *ev.Agents
		a.Agents = orEmpty(slices.Clone(a.Agents))
		slices.Sort(a.Agents)
		ev.Agents = &a
	}
	if ev.Waivers != nil {
		w := *ev.Waivers
		w.Applied, w.Stale, w.Expired = orEmpty(w.Applied), orEmpty(w.Stale), orEmpty(w.Expired)
		ev.Waivers = &w
	}
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// ModuleCounts summarises one module for summary.json.
type ModuleCounts struct {
	Status         string         `json:"status"`
	Findings       int            `json:"findings"`
	Open           int            `json:"open"`
	Waived         int            `json:"waived"`
	OpenBySeverity map[string]int `json:"open_by_severity"`
	Attempts       *int           `json:"attempts,omitempty"`     // egress only: size of the set
	OutOfScope     *int           `json:"out_of_scope,omitempty"` // egress only
}

// Summary is summary.json (AGR_SPEC §6).
type Summary struct {
	SchemaVersion    string                  `json:"schema_version"`
	AGR              AGR                     `json:"agr"`
	ToolVersion      string                  `json:"tool_version"`
	RulePackVersion  string                  `json:"rule_pack_version"`
	CMVPSnapshotDate string                  `json:"cmvp_snapshot_date,omitempty"`
	Target           Target                  `json:"target"`
	Counts           map[string]ModuleCounts `json:"counts"`
	Run              RunMeta                 `json:"run"`
}

// Summarize builds summary.json from normalized evidence.
func (ev *Bundle) Summarize() Summary {
	s := Summary{
		SchemaVersion: SchemaVersion, AGR: ev.AGR, ToolVersion: ev.ToolVersion,
		RulePackVersion: ev.RulePackVersion, CMVPSnapshotDate: ev.CMVPSnapshotDate,
		Target: ev.Target, Counts: map[string]ModuleCounts{}, Run: ev.Run,
	}
	s.Run.StartedAt, s.Run.FinishedAt = s.Run.StartedAt.UTC(), s.Run.FinishedAt.UTC()
	for _, m := range Modules {
		s.Counts[m] = ModuleCounts{Status: ev.ModuleState(m), OpenBySeverity: map[string]int{}}
	}
	for _, f := range ev.Findings {
		m := ModuleOf(f.Rule)
		c, ok := s.Counts[m]
		if !ok {
			c = ModuleCounts{Status: ModuleRan, OpenBySeverity: map[string]int{}}
		}
		c.Findings++
		if f.Open() {
			c.Open++
			c.OpenBySeverity[string(f.Severity)]++
		} else {
			c.Waived++
		}
		s.Counts[m] = c
	}
	if ev.Egress != nil {
		c := s.Counts[ModEgress]
		set := DedupeAttempts(ev.Egress.Attempts)
		n, out := len(set), 0
		for _, a := range set {
			if !a.InScope {
				out++
			}
		}
		c.Attempts, c.OutOfScope = &n, &out
		s.Counts[ModEgress] = c
	}
	return s
}

func marshal(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Marshal returns the canonical evidence.json and summary.json bytes.
func (ev Bundle) Marshal() (evidenceJSON, summaryJSON []byte, err error) {
	ev.Normalize()
	if evidenceJSON, err = marshal(&ev); err != nil {
		return nil, nil, err
	}
	if summaryJSON, err = marshal(ev.Summarize()); err != nil {
		return nil, nil, err
	}
	return evidenceJSON, summaryJSON, nil
}

// WriteEvidence writes evidence.json and summary.json into dir (created if
// needed). Identical evidence gives byte-identical files: 2-space indent,
// stable ordering, a trailing newline, timestamps only in summary.json's
// run block.
func WriteEvidence(dir string, ev Bundle) error {
	e, s, err := ev.Marshal()
	if err != nil {
		return fmt.Errorf("encode evidence: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, EvidenceFile), e, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, SummaryFile), s, 0o644)
}

func readJSON(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxEvidenceFile+1))
	if err != nil {
		return err
	}
	if len(b) > maxEvidenceFile {
		return fmt.Errorf("%s is larger than %d bytes", path, maxEvidenceFile)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// Load reads an evidence directory written by WriteEvidence (for report,
// replay and diff). The run metadata comes from summary.json.
func Load(dir string) (*Bundle, error) {
	var ev Bundle
	if err := readJSON(filepath.Join(dir, EvidenceFile), &ev); err != nil {
		return nil, err
	}
	if ev.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%s: schema %q, this build reads %q", EvidenceFile, ev.SchemaVersion, SchemaVersion)
	}
	var s Summary
	if err := readJSON(filepath.Join(dir, SummaryFile), &s); err != nil {
		return nil, err
	}
	if s.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%s: schema %q, this build reads %q", SummaryFile, s.SchemaVersion, SchemaVersion)
	}
	if s.AGR.Level != ev.AGR.Level {
		return nil, fmt.Errorf("%s says %s but %s says %s", SummaryFile, s.AGR.Level, EvidenceFile, ev.AGR.Level)
	}
	ev.Run = s.Run
	return &ev, nil
}

// FormatWindow renders an observation window, e.g. 600 → "10m", 90 → "1m30s".
func FormatWindow(sec int64) string {
	if sec <= 0 {
		return "0s"
	}
	var b strings.Builder
	if h := sec / 3600; h > 0 {
		fmt.Fprintf(&b, "%dh", h)
	}
	if m := sec % 3600 / 60; m > 0 {
		fmt.Fprintf(&b, "%dm", m)
	}
	if s := sec % 60; s > 0 {
		fmt.Fprintf(&b, "%ds", s)
	}
	return b.String()
}

// LevelLabel is the badge text, e.g. "AGR-2 (observed 10m)" or
// "unassessed (static-only report)".
func (a AGR) LevelLabel() string {
	if a.Level == LevelUnassessed || a.Level == "" {
		return "unassessed (static-only report)"
	}
	return fmt.Sprintf("%s (observed %s)", a.Level, FormatWindow(a.ObservedWindowS))
}
