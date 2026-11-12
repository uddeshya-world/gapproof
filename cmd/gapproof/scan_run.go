package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/uddeshya-world/gapproof/internal/agents"
	"github.com/uddeshya-world/gapproof/internal/aibom"
	"github.com/uddeshya-world/gapproof/internal/bundle"
	"github.com/uddeshya-world/gapproof/internal/crypto"
	"github.com/uddeshya-world/gapproof/internal/evidence"
	"github.com/uddeshya-world/gapproof/internal/fsscan"
	"github.com/uddeshya-world/gapproof/internal/harness"
	"github.com/uddeshya-world/gapproof/internal/inventory"
	"github.com/uddeshya-world/gapproof/internal/models"
	"github.com/uddeshya-world/gapproof/internal/oscal"
	"github.com/uddeshya-world/gapproof/internal/phonehome"
	"github.com/uddeshya-world/gapproof/internal/report"
	"github.com/uddeshya-world/gapproof/internal/sinkhole"
	"github.com/uddeshya-world/gapproof/rules"
)

// Files the scan writes next to evidence.json and summary.json (spec §3.6).
const (
	scopeCopy   = "gapproof.scope.yaml"
	waiversCopy = "gapproof.waivers.yaml"
	agentsCopy  = "gapproof.agents.yaml" // the manifest as read (YAML or MCP JSON), so `verify --rescan` can reproduce the agents result
	reportHTML  = "report.html"
	reportMD    = "report.md"
)

// extraModelsPrefix marks model paths that came from --models, not the image.
const extraModelsPrefix = "(--models)/"

// scanRun is one scan: the pipeline from target to evidence directory.
type scanRun struct {
	o        *scanOpts
	progress io.Writer // live progress lines (stderr)
	b        evidence.Bundle
	findings []evidence.Finding
	models   *models.Result // for the AI-BOM
	im       *fsscan.Image
	skipped  map[string]bool
	waivers  *evidence.Waivers
	agentRaw []byte // the --agents manifest as read, copied into the evidence
}

func (o *scanOpts) run(ctx context.Context, stdout, stderr io.Writer) (err error) {
	s := &scanRun{o: o, progress: stderr, skipped: map[string]bool{}}
	for _, m := range o.skip {
		s.skipped[m] = true
	}
	started := time.Now().UTC()
	s.b = evidence.Bundle{
		SchemaVersion:   evidence.SchemaVersion,
		ToolVersion:     version,
		RulePackVersion: rules.PackVersion(),
		Run:             evidence.RunMeta{ID: newRunID(), RunDate: started.Format(time.DateOnly), StartedAt: started},
	}

	// Inputs that can be wrong are checked before anything slow runs.
	scope, waivers, err := loadPolicy(o.scope, o.waivers)
	s.waivers = waivers
	if err != nil {
		return err
	}
	s.b.Scope = scope
	var agentData []byte
	if o.agents != "" && !s.skipped["agents"] {
		if agentData, err = agents.ReadManifestFile(o.agents); err != nil {
			return usagef("--agents: %v", err)
		}
	}
	if o.image != "" && !isFile(o.image) && looksLikePath(o.image) {
		return usagef("--image %s: no such file (a local image ref has no path separators or archive suffix)", o.image)
	}
	for flag, dir := range map[string]string{"--rootfs": o.rootfs, "--models": o.models} {
		if dir == "" {
			continue
		}
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			return usagef("%s %s is not a directory", flag, dir)
		}
	}
	if o.models != "" && s.skipped["models"] {
		return usagef("--models was given but the models module is skipped")
	}
	if o.agents != "" && s.skipped["agents"] {
		return usagef("--agents was given but the agents module is skipped")
	}
	var engine *harness.Engine
	if !s.skipped["egress"] || (o.image != "" && !isFile(o.image)) {
		if engine, err = harness.DetectEngine(ctx); err != nil {
			return err
		}
	}
	if !s.skipped["egress"] {
		if err := harness.Check(ctx, engine); err != nil {
			return fmt.Errorf("%w (or pass --skip egress)", err)
		}
	}
	created, err := prepareOut(o.out)
	if err != nil {
		return err
	}
	defer func() {
		// Don't leave an empty evidence directory behind on failure.
		if err != nil && created {
			if ents, _ := os.ReadDir(o.out); len(ents) == 0 {
				os.Remove(o.out)
			}
		}
	}()

	// Target.
	tarPath, cleanup, err := s.openTarget(ctx, engine)
	if err != nil {
		return err
	}
	defer cleanup()
	defer s.im.Close()

	// Static modules.
	if err := s.static(ctx); err != nil {
		return err
	}
	s.agentRaw = agentData
	if err := s.runAgents(displayName(o.agents), agentData); err != nil {
		return err
	}
	// Dynamic module.
	if err := s.runEgress(ctx, engine, tarPath, scope); err != nil {
		return err
	}

	// Aggregate.
	fs, wr, err := evidence.Finalize(s.findings, waivers, started)
	if err != nil {
		var ue *evidence.UsageError
		if errors.As(err, &ue) {
			return usagef("%s", ue.Msg)
		}
		return err
	}
	s.b.Findings, s.b.Waivers = fs, wr
	s.b.Run.FinishedAt = time.Now().UTC()
	s.b.Normalize()
	s.b.AGR = evidence.Compute(s.b.AGRInput())
	if err := s.write(); err != nil {
		return err
	}

	color := isTerminal(stdout) && os.Getenv("NO_COLOR") == ""
	for _, l := range renderTTY(&s.b, nil, color) {
		fmt.Fprintln(stdout, l)
	}
	fmt.Fprintf(stdout, "\nevidence: %s  (report.html, report.md, summary.json; sign with `gapproof sign --in %s --key <key>`)\n", o.out, o.out)
	if o.minAGR >= 0 && !evidence.MeetsMin(s.b.AGR.Level, o.minAGR) {
		return &belowThresholdError{s.b.AGR.Level, fmt.Sprintf("AGR-%d", o.minAGR)}
	}
	return nil
}

func (s *scanRun) logf(format string, a ...any) {
	fmt.Fprintf(s.progress, "› "+format+"\n", a...)
}

// openTarget extracts the image (or opens the rootfs) and returns the
// tarball path the egress harness will load ("" for a rootfs).
func (s *scanRun) openTarget(ctx context.Context, engine *harness.Engine) (string, func(), error) {
	o := s.o
	nop := func() {}
	if o.rootfs != "" {
		im, err := fsscan.OpenRootFS(o.rootfs)
		if err != nil {
			return "", nop, usagef("--rootfs: %v", err)
		}
		s.im = im
		s.b.Target = evidence.Target{Image: displayName(o.rootfs)}
		s.logf("rootfs %s (static only: egress can't be observed without running an image)", o.rootfs)
		return "", nop, nil
	}
	tarPath, cleanup := o.image, nop
	if !isFile(o.image) {
		dir, err := os.MkdirTemp("", "gapproof-save-")
		if err != nil {
			return "", nop, err
		}
		cleanup = func() { os.RemoveAll(dir) }
		tarPath = filepath.Join(dir, "image.tar")
		s.logf("saving local image %s", o.image)
		if err := harness.SaveTarget(ctx, engine, o.image, tarPath); err != nil {
			cleanup()
			return "", nop, usagef("--image: %v", err)
		}
	}
	s.logf("extracting %s", o.image)
	im, err := fsscan.ExtractImage(ctx, tarPath, fsscan.DefaultLimits())
	if err != nil {
		cleanup()
		return "", nop, fmt.Errorf("--image %s: %w", o.image, err)
	}
	s.im = im
	img := o.image
	if isFile(img) {
		img = displayName(img) // a tar path; a ref like ghcr.io/org/app:1 is kept whole
	}
	s.b.Target = evidence.Target{Image: img, ConfigDigest: im.ConfigDigest, ImageID: im.ImageID}
	if isFile(o.image) {
		if s.b.Target.ArtifactDigest, err = sha256File(o.image); err != nil {
			cleanup()
			return "", nop, err
		}
	}
	s.b.Warnings = append(s.b.Warnings, im.Warnings...)
	return tarPath, cleanup, nil
}

// static runs phonehome, crypto and models on the extracted filesystem.
func (s *scanRun) static(ctx context.Context) error {
	var inv *inventory.Inventory
	if !s.skipped["phonehome"] || !s.skipped["crypto"] {
		s.logf("inventory")
		var err error
		if inv, err = inventory.Build(ctx, s.im.Root, inventory.DefaultLimits()); err != nil {
			return fmt.Errorf("inventory: %w", err)
		}
	}

	if s.want("phonehome") {
		s.logf("phonehome: %d rules", len(mustRules()))
		fs, err := phonehome.Evaluate(ctx, mustRules(), phonehome.Input{Root: s.im.Root, Inv: inv, Env: s.im.Env, ConfigDigest: s.im.ConfigDigest})
		if err != nil {
			s.failed("phonehome", err)
		} else {
			s.ran("phonehome", "")
			s.findings = append(s.findings, fs...)
		}
	}

	if s.want("crypto") {
		s.logf("crypto inventory")
		snap, err := crypto.BuiltinSnapshot()
		if err != nil {
			return err
		}
		res, err := crypto.Scan(ctx, s.im.Root, inv, snap, crypto.DefaultOptions())
		if err != nil {
			s.failed("crypto", err)
		} else {
			s.ran("crypto", "")
			s.b.CMVPSnapshotDate = res.SnapshotDate
			sec := &evidence.CryptoSection{SnapshotDate: res.SnapshotDate, Configs: res.Configs}
			for _, m := range res.Modules {
				sec.Modules = append(sec.Modules, evidence.CryptoModule(m))
			}
			for _, p := range res.FIPSProviders {
				sec.FIPSProviders = append(sec.FIPSProviders, evidence.FIPSProvider(p))
			}
			s.b.Crypto = sec
			s.findings = append(s.findings, res.Findings...)
			s.b.Warnings = append(s.b.Warnings, res.Warnings...)
		}
	}

	if s.want("models") {
		s.logf("models")
		res, err := models.Scan(ctx, s.im.Root, models.DefaultOptions())
		if err == nil && s.o.models != "" {
			var extra *models.Result
			if extra, err = scanExtraModels(ctx, s.o.models); err == nil {
				res.Artifacts = append(res.Artifacts, extra.Artifacts...)
				res.Findings = append(res.Findings, extra.Findings...)
			}
		}
		if err != nil {
			s.failed("models", err)
		} else {
			s.ran("models", "")
			s.models = res
			sec := &evidence.ModelsSection{}
			for _, a := range res.Artifacts {
				sec.Artifacts = append(sec.Artifacts, evidence.ModelArtifact(a))
			}
			s.b.Models = sec
			s.findings = append(s.findings, res.Findings...)
		}
	}
	return nil
}

func scanExtraModels(ctx context.Context, dir string) (*models.Result, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, usagef("--models: %v", err)
	}
	defer root.Close()
	res, err := models.Scan(ctx, root, models.DefaultOptions())
	if err != nil {
		return nil, err
	}
	for i := range res.Artifacts {
		res.Artifacts[i].Path = extraModelsPrefix + res.Artifacts[i].Path
	}
	for i := range res.Findings {
		if p := res.Findings[i].Evidence.Path; p != "" {
			res.Findings[i].Evidence.Path = extraModelsPrefix + p
		}
	}
	return res, nil
}

// runAgents analyses an agents manifest under the name recorded in the
// evidence. `scan` and `verify --rescan` share it.
func (s *scanRun) runAgents(name string, data []byte) error {
	switch {
	case s.skipped["agents"]:
		s.status("agents", evidence.ModuleSkipped, "--skip agents")
		return nil
	case data == nil:
		s.status("agents", evidence.ModuleNotRun, "no --agents manifest (AGR-4 needs one; `agents: []` declares none)")
		return nil
	}
	s.logf("agents: %s", name)
	res, fs, err := agents.Analyze(name, data)
	if err != nil {
		hint := ""
		if t := strings.TrimSpace(string(data)); strings.HasPrefix(t, "{") {
			hint = " (for an MCP tools/list dump, run `gapproof agents import-mcp` and review the suggested agents.yaml)"
		}
		return usagef("--agents %s: %v%s", name, err, hint)
	}
	s.ran("agents", res.Statement)
	s.b.Agents = &evidence.AgentsSection{
		Manifest:         name,
		ManifestSHA256:   res.ManifestSHA256,
		DeclaredNoAgents: res.NoAgents,
		MESASpec:         res.MESASpec,
		Threshold:        evidence.INV01Threshold{P: res.Threshold[agents.DimP], U: res.Threshold[agents.DimU], E: res.Threshold[agents.DimE]},
		Violations:       res.Violations,
		NearMisses:       res.NearMisses,
	}
	if m, err := agents.ParseManifest(data); err == nil {
		for _, a := range m.Agents {
			s.b.Agents.Agents = append(s.b.Agents.Agents, a.Name)
		}
		slices.Sort(s.b.Agents.Agents)
	}
	if res.Suggestion != "" {
		s.b.Warnings = append(s.b.Warnings, "agents: "+res.Suggestion)
	}
	s.findings = append(s.findings, fs...)
	return nil
}

func (s *scanRun) runEgress(ctx context.Context, e *harness.Engine, tarPath string, scope *evidence.Scope) error {
	if s.skipped["egress"] {
		s.status("egress", evidence.ModuleSkipped, "--skip egress")
		return nil
	}
	s.logf("egress: loading target into %s (never pulled)", e.Bin)
	id, err := harness.LoadTarget(ctx, e, tarPath)
	if err != nil {
		return err
	}
	if id != s.im.ConfigDigest && id != s.im.ImageID && !slices.Contains(s.im.AltImageIDs, id) {
		return fmt.Errorf("the engine loaded image %s, but the scanned archive is %s: refusing to observe a different image", id, s.im.ConfigDigest)
	}
	s.logf("egress: observing for %s with all egress blocked", s.o.observe)
	ctx, stop := signalContext(ctx)
	defer stop()
	res, err := harness.Run(ctx, e, harness.Config{
		Target: id, Workload: s.o.workload, Observe: s.o.observe, Pcap: s.o.pcap, OneShot: s.o.oneShot,
		OutDir: s.o.out, RunID: s.b.Run.ID,
	})
	if ctx.Err() != nil {
		return fmt.Errorf("egress: interrupted (containers removed): %w", ctx.Err())
	}
	sec := &evidence.EgressSection{}
	s.b.Egress = sec
	if err != nil {
		sec.HarnessFailed = true
		// The detail (container IDs, timings) goes to stderr only: evidence.json
		// must not depend on it (rule 6).
		s.logf("egress FAILED: %v", err)
		s.status("egress", evidence.ModuleFailed, "the harness itself failed (details on stderr); no level claimed")
		return nil
	}
	note := ""
	if len(res.Refused) > 0 {
		note = "target not run: it asks for " + strings.Join(res.Refused, ", ")
	}
	s.ran("egress", note)
	sec.TargetStarted = res.TargetStarted && len(res.Refused) == 0
	sec.WorkloadPassed = res.Passed()
	sec.ObservedWindowS = int64(res.Observed / time.Second)
	sec.OneShot = res.OneShot
	var raw []evidence.EgressAttempt
	for _, ev := range res.Events {
		if a, ok := attemptOf(ev); ok {
			raw = append(raw, a)
		}
	}
	sec.Attempts = scope.Mark(evidence.DedupeAttempts(raw), harness.TargetHostname)
	s.b.Target.Hostname = harness.TargetHostname
	s.b.Warnings = append(s.b.Warnings, res.Notes...)
	s.findings = append(s.findings, evidence.EgressFindings(sec.Attempts)...)
	return nil
}

func attemptOf(ev sinkhole.Event) (evidence.EgressAttempt, bool) {
	switch ev.Kind {
	case sinkhole.KindDNS, sinkhole.KindTCP, sinkhole.KindUDP, sinkhole.KindICMP, sinkhole.KindIP:
	default:
		return evidence.EgressAttempt{}, false
	}
	dst := ev.OrigDstIP
	// A synthetic answer address depends on query order; the name it stands
	// for is the stable identity (the address stays in egress.log.jsonl).
	if ip, err := netip.ParseAddr(dst); err == nil && sinkhole.IsSynthetic(ip) && ev.Name != "" {
		dst = ""
	}
	return evidence.EgressAttempt{
		Kind: ev.Kind, Name: ev.Name, OrigDstIP: dst, Port: ev.Port,
		ProtoHint: ev.ProtoHint, SNI: ev.SNI, ALPN: ev.ALPN, HTTPHost: ev.HTTPHost,
	}, true
}

// write produces every evidence file, then the manifest over all of them.
func (s *scanRun) write() error {
	out := s.o.out
	if err := evidence.WriteEvidence(out, s.b); err != nil {
		return err
	}
	if s.b.Scope != nil {
		if err := os.WriteFile(filepath.Join(out, scopeCopy), s.b.Scope.Raw, 0o644); err != nil {
			return err
		}
	}
	if s.o.waivers != "" {
		if err := os.WriteFile(filepath.Join(out, waiversCopy), s.waivers.Raw, 0o644); err != nil {
			return err
		}
	}
	if s.agentRaw != nil && s.b.Agents != nil {
		if err := os.WriteFile(filepath.Join(out, agentsCopy), s.agentRaw, 0o644); err != nil {
			return err
		}
	}
	subject := s.b.Target.Image
	if s.im != nil && len(s.im.RepoTags) > 0 {
		subject = s.im.RepoTags[0]
	}
	mres := s.models
	if mres == nil {
		mres = &models.Result{}
	}
	bom, err := aibom.Build(aibom.Input{ToolVersion: version, Subject: aibom.Subject{Name: subject, ConfigDigest: s.b.Target.ConfigDigest, ImageID: s.b.Target.ImageID}, Models: mres})
	if err != nil {
		return fmt.Errorf("ai-bom: %w", err)
	}
	if err := writeMarshal(filepath.Join(out, aibom.FileName), func() ([]byte, error) { return aibom.Marshal(bom) }); err != nil {
		return err
	}
	doc, err := oscal.Build(oscal.Input{
		ToolVersion: version, Started: s.b.Run.StartedAt, Ended: s.b.Run.FinishedAt,
		Subject: subject, SubjectDigest: s.b.Target.ConfigDigest, Level: s.b.AGR.Level,
		Findings: s.b.Findings, StatusOf: func(f evidence.Finding) string { return string(f.Status) },
	})
	if err != nil {
		return fmt.Errorf("oscal: %w", err)
	}
	if err := writeMarshal(filepath.Join(out, oscal.FileName), func() ([]byte, error) { return oscal.Marshal(doc) }); err != nil {
		return err
	}
	if err := writeReports(out, &s.b, "both"); err != nil {
		return err
	}
	_, err = bundle.WriteManifest(out, s.b.Target.ConfigDigest)
	return err
}

func writeReports(dir string, b *evidence.Bundle, format string) error {
	if format == "html" || format == "both" {
		if err := writeMarshal(filepath.Join(dir, reportHTML), func() ([]byte, error) { return report.HTML(b) }); err != nil {
			return err
		}
	}
	if format == "md" || format == "both" {
		return writeMarshal(filepath.Join(dir, reportMD), func() ([]byte, error) { return report.Markdown(b) })
	}
	return nil
}

func writeMarshal(path string, f func() ([]byte, error)) error {
	b, err := f()
	if err != nil {
		return fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return os.WriteFile(path, b, 0o644)
}

// want reports whether a module should run, recording it as skipped if not.
func (s *scanRun) want(m string) bool {
	if s.skipped[m] {
		s.status(m, evidence.ModuleSkipped, "--skip "+m)
		return false
	}
	return true
}

func (s *scanRun) ran(m, note string) { s.status(m, evidence.ModuleRan, note) }

func (s *scanRun) failed(m string, err error) {
	s.status(m, evidence.ModuleFailed, err.Error())
	s.logf("%s FAILED: %v", m, err)
}

func (s *scanRun) status(m, st, note string) {
	s.b.Modules = append(s.b.Modules, evidence.ModuleStatus{Name: m, Status: st, Note: note})
}

func loadPolicy(scopePath, waiversPath string) (*evidence.Scope, *evidence.Waivers, error) {
	var scope *evidence.Scope
	var waivers *evidence.Waivers
	var err error
	if scopePath != "" {
		if scope, err = evidence.LoadScope(scopePath); err != nil {
			return nil, nil, usagef("--scope: %v", err)
		}
	}
	if waiversPath != "" {
		if waivers, err = evidence.LoadWaivers(waiversPath); err != nil {
			return nil, nil, usagef("--waivers: %v", err)
		}
	}
	return scope, waivers, nil
}

// prepareOut creates the evidence directory. It must be new or empty, so
// MANIFEST.sha256 never covers a stale file from an earlier run.
func prepareOut(dir string) (created bool, err error) {
	ents, err := os.ReadDir(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return false, usagef("--out: %v", err)
		}
		return true, nil
	case err != nil:
		return false, usagef("--out: %v", err)
	case len(ents) > 0:
		return false, usagef("--out %s is not empty (evidence directories are written once; pick a new one)", dir)
	}
	return false, nil
}

// displayName is how an input path is recorded in the evidence: its base
// name, so the same inputs give the same evidence.json from any working
// directory (rule 6).
func displayName(p string) string {
	return filepath.Base(filepath.Clean(p))
}

func mustRules() []*phonehome.Rule {
	rs, err := phonehome.Builtin()
	if err != nil {
		panic(err) // embedded and tested; can't fail at runtime
	}
	return rs
}

func newRunID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func looksLikePath(p string) bool {
	return strings.HasSuffix(p, ".tar") || strings.HasPrefix(p, ".") || strings.HasPrefix(p, "/")
}

func isFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

func sha256File(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
