package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/uddeshya-world/gapproof/internal/evidence"
	"github.com/uddeshya-world/gapproof/internal/fsscan"
	"github.com/uddeshya-world/gapproof/rules"
)

// staticModules are the modules `verify --rescan` can reproduce offline from
// the image tar alone. The egress harness is dynamic and is never re-run.
var staticModules = []string{evidence.ModPhoneHome, evidence.ModCrypto, evidence.ModModels, evidence.ModAgents}

// rescanFiles are the bundle members the rescan needs, read while the bundle
// is verified (so they are exactly the bytes the signature covers).
var rescanFiles = []string{evidence.EvidenceFile, evidence.SummaryFile, scopeCopy, waiversCopy, agentsCopy}

// maxDiffLines bounds the diff printed to the terminal.
const maxDiffLines = 40

// rescanResult is the outcome of re-running the static modules.
type rescanResult struct {
	Diffs      []evidence.DiffEntry
	Compared   []string // modules that were re-run and compared
	Notes      []string // what was not reproduced, and why
	Findings   int      // static findings in the rescan
	ToolDiffer string   // "" or the version difference, for context on a mismatch
}

// Match reports whether the static results were reproduced.
func (r *rescanResult) Match() bool { return len(r.Diffs) == 0 }

// lines renders the result for the terminal. Paths come from the scanned
// image, so every line is neutralised.
func (r *rescanResult) lines() []string {
	var out []string
	if r.Match() {
		out = append(out, fmt.Sprintf("rescan: match: static findings reproduced (%s; %d findings)", strings.Join(r.Compared, ", "), r.Findings))
	} else {
		out = append(out, fmt.Sprintf("rescan: MISMATCH: %d difference(s) between the signed evidence and an offline rescan (%s)", len(r.Diffs), strings.Join(r.Compared, ", ")))
		for i, d := range r.Diffs {
			if i == maxDiffLines {
				out = append(out, fmt.Sprintf("  ... and %d more", len(r.Diffs)-maxDiffLines))
				break
			}
			out = append(out, "  "+safe(d.String()))
		}
		if r.ToolDiffer != "" {
			out = append(out, "  note: "+r.ToolDiffer)
		}
	}
	for _, n := range r.Notes {
		out = append(out, "rescan: "+safe(n))
	}
	out = append(out, "rescan: egress and harness results are dynamic and were not re-run; they rest on the signed evidence")
	return out
}

// rescanStatic re-runs the static modules on the delivered image tar and
// diffs the result against the signed evidence in files. It reuses the scan's
// own static pipeline (scanRun.static, scanRun.runAgents), so the same code
// produces both sides. Nothing is executed from the image and nothing leaves
// the machine (CLAUDE.md rules 1 and 3).
func rescanStatic(ctx context.Context, artifact string, files map[string][]byte, progress io.Writer) (*rescanResult, error) {
	for _, n := range []string{evidence.EvidenceFile, evidence.SummaryFile} {
		if _, ok := files[n]; !ok {
			return nil, usagef("--rescan: the bundle has no %s", n)
		}
	}
	// Load through the reader the other commands use: write the verified
	// bytes to a private temp directory.
	dir, err := os.MkdirTemp("", "gapproof-rescan-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(dir, n), b, 0o600); err != nil {
			return nil, err
		}
	}
	rec, err := evidence.Load(dir)
	if err != nil {
		return nil, usagef("--rescan: %v", err)
	}
	var scopePath, waiversPath string
	if _, ok := files[scopeCopy]; ok {
		scopePath = filepath.Join(dir, scopeCopy)
	}
	if _, ok := files[waiversCopy]; ok {
		waiversPath = filepath.Join(dir, waiversCopy)
	}
	if rec.Scope != nil && scopePath == "" {
		return nil, usagef("--rescan: the evidence used a scope file but the bundle does not carry %s", scopeCopy)
	}
	if rec.Waivers != nil && waiversPath == "" {
		return nil, usagef("--rescan: the evidence used a waivers file but the bundle does not carry %s", waiversCopy)
	}
	scope, waivers, err := loadPolicy(scopePath, waiversPath)
	if err != nil {
		return nil, err
	}
	// Waiver expiry is judged on the scan's run date, not today's.
	runDate, err := time.Parse(time.DateOnly, rec.Run.RunDate)
	if err != nil {
		return nil, usagef("--rescan: bad run date %q in summary.json", rec.Run.RunDate)
	}

	res := &rescanResult{}
	s := &scanRun{o: &scanOpts{}, progress: progress, skipped: map[string]bool{evidence.ModEgress: true}, waivers: waivers}
	var agentData []byte
	for _, m := range staticModules {
		switch {
		case rec.ModuleState(m) != evidence.ModuleRan:
			s.skipped[m] = true
			res.Notes = append(res.Notes, fmt.Sprintf("%s: %s in the signed evidence, not compared", m, rec.ModuleState(m)))
		case m == evidence.ModAgents && rec.Agents != nil && files[agentsCopy] == nil:
			s.skipped[m] = true
			res.Notes = append(res.Notes, "agents: the bundle carries no "+agentsCopy+" (older bundle), not compared")
		default:
			res.Compared = append(res.Compared, m)
		}
	}
	if slices.Contains(res.Compared, evidence.ModAgents) {
		agentData = files[agentsCopy]
	}
	if rec.Models != nil {
		for _, a := range rec.Models.Artifacts {
			if strings.HasPrefix(a.Path, extraModelsPrefix) {
				res.Notes = append(res.Notes, "models: artefacts from --models were not inside the image, not compared")
				break
			}
		}
	}

	im, err := fsscan.ExtractImage(ctx, artifact, fsscan.DefaultLimits())
	if err != nil {
		return nil, fmt.Errorf("--artifact %s: %w", artifact, err)
	}
	defer im.Close()
	s.im = im
	if rec.Target.ConfigDigest != "" && im.ConfigDigest != rec.Target.ConfigDigest {
		return nil, &checkFailedError{fmt.Sprintf("rescan: the image's config digest %s is not the scanned %s", im.ConfigDigest, rec.Target.ConfigDigest)}
	}
	if err := s.static(ctx); err != nil {
		return nil, err
	}
	if agentData != nil && rec.Agents != nil {
		if err := s.runAgents(rec.Agents.Manifest, agentData); err != nil {
			return nil, err
		}
	}
	fs, wr, err := evidence.Finalize(s.findings, waivers, runDate)
	if err != nil {
		return nil, err
	}
	s.b.Findings, s.b.Waivers, s.b.Scope = fs, wr, scope
	s.b.Normalize()
	for _, f := range s.b.Findings {
		if slices.Contains(res.Compared, evidence.ModuleOf(f.Rule)) {
			res.Findings++
		}
	}
	res.Diffs = evidence.CompareStatic(rec, &s.b, evidence.CompareOpts{Modules: res.Compared, IgnorePathPrefix: extraModelsPrefix})
	if rec.ToolVersion != version || rec.RulePackVersion != rules.PackVersion() {
		res.ToolDiffer = fmt.Sprintf("signed evidence was produced by gapproof %s (rule pack %s); this binary is %s (rule pack %s)",
			rec.ToolVersion, rec.RulePackVersion, version, rules.PackVersion())
	}
	return res, nil
}
