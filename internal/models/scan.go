// Package models finds, hashes and statically checks model artefacts in a
// scanned filesystem (spec §3.4). It never loads, imports or unpickles
// anything: every format is parsed from bytes, and anything it can't verify
// is reported as a finding (fail closed).
package models

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/uddeshya-world/gapproof/internal/evidence"
)

// Options bound how much work any one file can cause.
type Options struct {
	MaxSafetensorsHeader int64   // bytes (the reference loader caps at 100 MB)
	MaxPickleBytes       int64   // decompressed bytes read from one zip member
	ZipRatio             float64 // decompressed:compressed, per member
	ZipRatioFloor        int64   // ratio only enforced past this many bytes
	MaxZipEntries        int
	MaxZipTotalBytes     int64 // decompressed bytes read from all members of one zip (overlapping-member bombs)
	MaxJSONBytes         int64 // HF configs, Keras config.json
	MaxGGUFMetadata      int64 // bytes of GGUF header + metadata + tensor infos
	MaxONNXFields        int   // protobuf fields visited in one ONNX file (work budget)
	MaxPickleOps         int   // opcodes walked in one pickle stream (work budget)
	MaxImports           int   // distinct pickle imports recorded per file (memory budget)
}

// DefaultOptions are safe for real models. Every budget counts bytes, fields
// or opcodes, never wall-clock time, so results stay deterministic (rule 6).
func DefaultOptions() Options {
	return Options{
		MaxSafetensorsHeader: 100 << 20,
		MaxPickleBytes:       256 << 20,
		ZipRatio:             100,
		ZipRatioFloor:        16 << 20,
		MaxZipEntries:        100_000,
		MaxZipTotalBytes:     1 << 30,
		MaxJSONBytes:         16 << 20,
		MaxGGUFMetadata:      1 << 30,
		MaxONNXFields:        16 << 20,
		MaxPickleOps:         200_000_000,
		MaxImports:           10_000,
	}
}

// Artifact is one model file, for the AI-BOM.
type Artifact struct {
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
	Imports      []string          `json:"imports,omitempty"` // every pickle import, sorted
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// Result is the module output. Both slices are deterministically sorted.
type Result struct {
	Artifacts []Artifact         `json:"artifacts"`
	Findings  []evidence.Finding `json:"findings"`
}

type scanner struct {
	ctx      context.Context
	root     *os.Root
	opt      Options
	res      Result
	licenses map[string]string // dir -> licence from README front matter
	extra    []string          // ONNX external data files to inventory
}

// Scan walks root and reports every model artefact it finds.
func Scan(ctx context.Context, root *os.Root, opt Options) (*Result, error) {
	s := &scanner{ctx: ctx, root: root, opt: opt, licenses: map[string]string{}}
	var files []string
	err := fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable dirs are skipped; extraction already bounded the tree
		}
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		// Only regular files: symlinks are never followed.
		if d.Type().IsRegular() && candidate(p) {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.Sort(files)
	for _, p := range files {
		if path.Base(p) == "README.md" {
			if l := s.readmeLicense(p); l != "" {
				s.licenses[path.Dir(p)] = l
			}
		}
	}
	for _, p := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if path.Base(p) != "README.md" {
			if err := s.file(p, ""); err != nil {
				return nil, err
			}
		}
	}
	for _, p := range s.extra {
		if !slices.ContainsFunc(s.res.Artifacts, func(a Artifact) bool { return a.Path == p }) {
			if err := s.file(p, "onnx-external-data"); err != nil {
				return nil, err
			}
		}
	}
	for i := range s.res.Artifacts {
		a := &s.res.Artifacts[i]
		if a.License == "" {
			a.License = s.licenses[path.Dir(a.Path)]
		}
	}
	slices.SortFunc(s.res.Artifacts, func(a, b Artifact) int { return cmp.Compare(a.Path, b.Path) })
	evidence.Sort(s.res.Findings)
	if s.res.Artifacts == nil {
		s.res.Artifacts = []Artifact{}
	}
	if s.res.Findings == nil {
		s.res.Findings = []evidence.Finding{}
	}
	return &s.res, nil
}

var weightExt = setOf(".safetensors", ".gguf", ".onnx", ".pt", ".pth", ".ckpt", ".bin", ".pkl", ".pickle",
	".joblib", ".npy", ".npz", ".keras", ".h5", ".hdf5")

var hfJSON = setOf("config.json", "tokenizer_config.json", "generation_config.json", "tokenizer.json")

func candidate(p string) bool {
	base := path.Base(p)
	return weightExt[strings.ToLower(path.Ext(base))] || hfJSON[base] || base == "README.md"
}

// file scans one candidate. forceFormat skips sniffing (ONNX external data).
func (s *scanner) file(p, forceFormat string) error {
	f, err := s.root.Open(p)
	if err != nil {
		return nil // vanished or unreadable: not a model we can report on
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return nil
	}
	size := fi.Size()
	var head [16]byte
	k, _ := f.ReadAt(head[:], 0)
	h := head[:k]

	format := forceFormat
	if format == "" {
		format = sniff(p, h)
	}
	if format == "" {
		return nil // not a model file (e.g. firmware .bin, an unrelated config.json)
	}
	sum, err := hashFile(f)
	if err != nil {
		return fmt.Errorf("hashing %s: %w", p, err)
	}
	a := Artifact{Path: p, Format: format, Size: size, SHA256: sum}
	c := &fileCtx{s: s, path: p, sha: sum, art: &a}

	switch format {
	case "safetensors":
		st, err := parseSafetensors(f, size, s.opt.MaxSafetensorsHeader)
		if err != nil {
			c.failed("", nil, err)
		}
		a.Tensors, a.Parameters, a.DTypes, a.Metadata = st.tensors, st.parameters, st.dtypes, st.metadata
	case "gguf":
		c.gguf(f)
	case "onnx":
		c.onnx(f, size)
	case "pytorch-zip", "torchscript", "npz", "keras":
		c.zipArchive(f, size)
	case "pickle":
		c.rawPickle(f)
	case "joblib-compressed":
		c.add(RuleUnscanned, "", nil, "compressed joblib archive")
	case "npy":
		c.npy(f)
	case "keras-h5":
		c.h5(f)
	case "hf-config", "hf-tokenizer-config":
		if !c.hfJSON(f, size) {
			return nil // a config.json that isn't a model config
		}
	}
	slices.Sort(a.Imports)
	s.res.Artifacts = append(s.res.Artifacts, a)
	return nil
}

// sniff decides the format from the name and leading bytes. "" = not a model.
func sniff(p string, h []byte) string {
	base := path.Base(p)
	ext := strings.ToLower(path.Ext(base))
	isZip := bytes.HasPrefix(h, []byte("PK\x03\x04")) || bytes.HasPrefix(h, []byte("PK\x05\x06"))
	isPickle := len(h) >= 2 && h[0] == 0x80 && h[1] >= 2 && h[1] <= 5
	switch {
	case base == "config.json" || base == "generation_config.json":
		return "hf-config"
	case base == "tokenizer_config.json":
		return "hf-tokenizer-config"
	case base == "tokenizer.json":
		return "hf-tokenizer"
	}
	switch ext {
	case ".safetensors":
		return "safetensors"
	case ".gguf":
		return "gguf"
	case ".onnx":
		return "onnx"
	case ".npy":
		return "npy"
	case ".npz":
		return "npz"
	case ".keras":
		return "keras"
	case ".h5", ".hdf5":
		if bytes.HasPrefix(h, []byte("\x89HDF\r\n\x1a\n")) {
			return "keras-h5"
		}
		return ""
	case ".bin":
		switch {
		case isZip:
			return "pytorch-zip"
		case isPickle:
			return "pickle"
		}
		return "" // most .bin files aren't models
	case ".joblib":
		if !isZip && !isPickle && len(h) > 0 && (h[0] == 0x78 || bytes.HasPrefix(h, []byte{0x1f, 0x8b}) ||
			bytes.HasPrefix(h, []byte{0xfd, '7', 'z'}) || bytes.HasPrefix(h, []byte{0x04, 0x22, 0x4d, 0x18}) || h[0] == 0x5d) {
			return "joblib-compressed"
		}
	}
	if isZip {
		return "pytorch-zip"
	}
	return "pickle" // .pt/.pth/.ckpt/.pkl/.pickle/.joblib: walk it; failure is a finding
}

func hashFile(f *os.File) (string, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// fileCtx carries one artefact's identity into its findings.
type fileCtx struct {
	s        *scanner
	path     string
	sha      string
	art      *Artifact
	seen     map[string]bool
	imps     map[string]bool // art.Imports as a set
	zipTotal int64           // decompressed bytes read from this file's zip members
}

// errLimit marks an error as a hostile-input limit hit (CLAUDE.md rule 3).
// Its MODEL-PARSE-FAILED detail starts with "limit: ", so an approver can
// tell a bomb or an over-budget file from plain corruption.
var errLimit = errors.New("limit")

func limitErrorf(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errLimit, fmt.Sprintf(format, a...))
}

// failed records MODEL-PARSE-FAILED for err (fail closed, D-010).
func (c *fileCtx) failed(member string, off *int64, err error) {
	d := err.Error()
	if errors.Is(err, errLimit) {
		d = "limit: " + strings.Replace(d, "limit: ", "", 1)
	}
	c.add(RuleParseFailed, member, off, d)
}

func (c *fileCtx) add(rule, member string, off *int64, detail string) {
	key := rule + "\x00" + member + "\x00" + detail
	if c.seen == nil {
		c.seen = map[string]bool{}
	}
	if c.seen[key] {
		return // one finding per (rule, member, detail); the first offset wins
	}
	c.seen[key] = true
	ri := rules[rule]
	c.s.res.Findings = append(c.s.res.Findings, evidence.Finding{
		Rule:        rule,
		Severity:    ri.sev,
		Title:       ri.title,
		Explanation: ri.explanation,
		Evidence:    evidence.Evidence{Path: c.path, Member: member, SHA256: c.sha, Offset: off, Detail: detail},
		Fix:         ri.fix,
		Controls:    ri.controls,
	})
}

// imports reports every import a walker collected. Past MaxImports
// distinct imports in one file it records a limit finding and stops.
func (c *fileCtx) imports(member string, imps []Import) {
	if c.imps == nil {
		c.imps = map[string]bool{}
	}
	for _, im := range imps {
		k := im.String()
		if !c.imps[k] {
			if lim := cmp.Or(c.s.opt.MaxImports, defaultWalkLimits.maxImports); len(c.imps) >= lim {
				c.failed(member, evidence.Off(im.Offset), limitErrorf("more than %d distinct pickle imports in one file", lim))
				return
			}
			c.imps[k] = true
			c.art.Imports = append(c.art.Imports, k)
		}
		if !im.Resolved {
			c.add(RulePickleUnresolved, member, evidence.Off(im.Offset), im.Opcode+" with non-static operands")
			continue
		}
		if rule := classifyImport(im.Module, im.Name); rule != "" {
			c.add(rule, member, evidence.Off(im.Offset), fmt.Sprintf("%s %s.%s", im.Opcode, im.Module, im.Name))
		}
	}
}

// legacyTorchMagic is the first pickle of a pre-1.6 torch.save file.
var legacyTorchMagic = []byte("\x80\x02\x8a\x0al\xfc\x9cF\xf9 j\xa8P\x19.")

// walkPickles walks consecutive pickles from r: exactly 5 for a legacy torch
// file (after which raw storage bytes follow), otherwise as long as another
// protocol-2+ pickle starts.
func (c *fileCtx) walkPickles(r io.Reader, member string) { c.walkPicklesAt(r, member, 0) }

// walkPicklesAt is walkPickles with offsets starting at base.
func (c *fileCtx) walkPicklesAt(r io.Reader, member string, base int64) {
	pr := newPreader(r, base)
	legacy := false
	if b, err := pr.br.Peek(len(legacyTorchMagic)); err == nil && bytes.Equal(b, legacyTorchMagic) {
		legacy = true
	}
	w := newWalker(pr)
	w.lim.maxOps = cmp.Or(c.s.opt.MaxPickleOps, w.lim.maxOps)
	w.lim.maxImports = cmp.Or(c.s.opt.MaxImports, w.lim.maxImports)
	for i := 0; ; i++ {
		if i > 0 {
			if legacy && i >= 5 {
				break
			}
			b, err := pr.br.Peek(1)
			if err != nil || (!legacy && b[0] != 0x80) {
				break
			}
			if i >= maxPickles {
				// Reported, never silently cut short.
				c.failed(member, evidence.Off(pr.off), limitErrorf("more than %d consecutive pickles", maxPickles))
				return
			}
		}
		err := w.one()
		c.imports(member, w.imports)
		w.imports = w.imports[:0]
		if err != nil {
			if errors.Is(err, errMemberLimit) {
				return // withMember reports the limit once
			}
			var pe *PickleError
			if errors.As(err, &pe) {
				c.failed(member, evidence.Off(pe.Offset), err)
			} else {
				c.failed(member, nil, err)
			}
			return
		}
	}
}

// maxPickles is how many consecutive pickles one stream may hold.
const maxPickles = 64

func (c *fileCtx) rawPickle(f *os.File) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		c.failed("", nil, err)
		return
	}
	c.walkPickles(f, "")
}

func (s *scanner) readmeLicense(p string) string {
	f, err := s.root.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, 64<<10))
	text := string(b)
	front, ok := strings.CutPrefix(text, "---\n")
	if !ok {
		return ""
	}
	front, _, ok = strings.Cut(front, "\n---")
	if !ok {
		return ""
	}
	for l := range strings.SplitSeq(front, "\n") {
		if v, ok := strings.CutPrefix(l, "license:"); ok {
			return strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return ""
}
