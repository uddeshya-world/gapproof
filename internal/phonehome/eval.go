package phonehome

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/uddeshya-world/gapproof/internal/evidence"
	"github.com/uddeshya-world/gapproof/internal/inventory"
)

// Input is what the rules are evaluated against.
type Input struct {
	Root         *os.Root
	Inv          *inventory.Inventory
	Env          []string // image config Env, KEY=VALUE
	ConfigDigest string   // evidence anchor for env-based findings
}

// ImageConfigPath is the evidence path used for findings that come from the
// image environment rather than a file.
const ImageConfigPath = "(image config)"

const maxSourceHitsPerRule = 20

// Evaluate runs every rule and returns sorted findings.
func Evaluate(ctx context.Context, rs []*Rule, in Input) ([]evidence.Finding, error) {
	env := inventory.EnvMap(in.Env)
	unlessFiles, err := collectUnlessFiles(ctx, rs, in.Root)
	if err != nil {
		return nil, err
	}
	hashes := map[string]string{}
	hashOf := func(p string) string {
		if h, ok := hashes[p]; ok {
			return h
		}
		h := fileHash(in.Root, p)
		hashes[p] = h
		return h
	}

	findings := []evidence.Finding{}
	for _, r := range rs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if suppressed(r, env, unlessFiles[r.ID]) {
			continue
		}
		m := r.Match
		var pkgs []inventory.PythonPackage
		verNote := map[string]string{} // METADATA path -> version-range note
		for _, name := range m.PythonPackage {
			for _, p := range in.Inv.Package(name) {
				if r.versionSpec != nil {
					inRange, ok := r.versionSpec.Contains(p.Version)
					if !inRange {
						continue
					}
					verNote[p.Metadata] = ", in affected range " + r.versionSpec.String()
					if !ok {
						verNote[p.Metadata] = ", version isn't PEP 440 so treated as in affected range " + r.versionSpec.String()
					}
				}
				pkgs = append(pkgs, p)
			}
		}
		if len(m.PythonPackage) > 0 && len(pkgs) == 0 {
			continue
		}
		envHits := envMatches(m.Env, env)
		if len(m.Env) > 0 && len(envHits) == 0 {
			continue
		}
		urlHits := publicURLMatches(m.EnvPublicURL, env)
		if len(m.EnvPublicURL) > 0 && len(urlHits) == 0 {
			continue
		}
		var src []sourceHit
		if r.sourceRe != nil {
			if src, err = scanSources(ctx, in, r); err != nil {
				return nil, err
			}
			if len(src) == 0 {
				continue
			}
		}

		why := unlessText(r)
		add := func(ev evidence.Evidence) {
			findings = append(findings, evidence.Finding{
				Rule: r.ID, Severity: r.Severity, Title: r.Title, Explanation: strings.TrimSpace(r.Explanation),
				Evidence: ev, Fix: r.Fix, Controls: r.Controls,
			})
		}
		switch {
		case len(src) > 0: // the most specific evidence: the line in the app
			for _, h := range src {
				add(evidence.Evidence{Path: h.path, SHA256: hashOf(h.path), Offset: evidence.Off(h.offset), Detail: h.line})
			}
		case len(pkgs) > 0:
			for _, p := range pkgs {
				d := fmt.Sprintf("%s %s installed%s", p.RawName, p.Version, verNote[p.Metadata])
				if len(envHits)+len(urlHits) > 0 {
					d += "; " + strings.Join(append(envHits, urlHits...), "; ")
				}
				add(evidence.Evidence{Path: p.Metadata, SHA256: hashOf(p.Metadata), Detail: d + why})
			}
		default:
			add(evidence.Evidence{Path: ImageConfigPath, SHA256: strings.TrimPrefix(in.ConfigDigest, "sha256:"),
				Detail: strings.Join(append(envHits, urlHits...), "; ")})
		}
	}
	evidence.Sort(findings)
	return findings, nil
}

// valueMatches: "*" = set and non-empty; "!x" = set and not x; else equal
// (case-insensitive, trimmed).
func valueMatches(v string, set bool, pats []string) bool {
	v = strings.TrimSpace(v)
	for _, p := range pats {
		switch {
		case !set:
			return false
		case p == "*":
			if v != "" {
				return true
			}
		case strings.HasPrefix(p, "!"):
			if !strings.EqualFold(v, p[1:]) {
				return true
			}
		case strings.EqualFold(v, p):
			return true
		}
	}
	return false
}

func envMatches(want map[string][]string, env map[string]string) []string {
	var hits []string
	for _, k := range sortedKeys(want) {
		v, set := env[k]
		if valueMatches(v, set, want[k]) {
			hits = append(hits, fmt.Sprintf("image env %s=%s", k, v))
		}
	}
	return hits
}

func publicURLMatches(vars []string, env map[string]string) []string {
	var hits []string
	for _, k := range vars {
		if v, ok := env[k]; ok {
			if host, public := PublicHost(v); public {
				hits = append(hits, fmt.Sprintf("image env %s points at public host %s", k, host))
			}
		}
	}
	return hits
}

func suppressed(r *Rule, env map[string]string, files []string) bool {
	for k, pats := range r.Match.UnlessEnv {
		v, set := env[k]
		if valueMatches(v, set, pats) {
			return true
		}
	}
	return len(files) > 0
}

func unlessText(r *Rule) string {
	if len(r.Match.UnlessEnv) == 0 && r.Match.UnlessFile == nil {
		return ""
	}
	var parts []string
	for _, k := range sortedKeys(r.Match.UnlessEnv) {
		parts = append(parts, k+"="+strings.Join(r.Match.UnlessEnv[k], "|"))
	}
	s := "; not disabled in the image"
	if len(parts) > 0 {
		s += " (none of " + strings.Join(parts, ", ") + ")"
	}
	if r.Match.UnlessFile != nil {
		s += "; no matching config file"
	}
	return s
}

// PublicHost reports whether a URL or host:port names a host outside private
// address space and internal DNS conventions. Unparseable values count as
// public: Gapproof fails closed.
func PublicHost(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", false
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Hostname() == "" {
		return raw, true
	}
	h := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if ip, err := netip.ParseAddr(h); err == nil {
		cgnat := netip.MustParsePrefix("100.64.0.0/10")
		return h, !(ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || cgnat.Contains(ip))
	}
	if h == "localhost" || !strings.Contains(h, ".") {
		return h, false // single-label names resolve inside the network (compose/k8s services)
	}
	for _, suf := range []string{".local", ".localhost", ".internal", ".localdomain", ".lan", ".home.arpa", ".svc", ".cluster.local"} {
		if strings.HasSuffix(h, suf) {
			return h, false
		}
	}
	return h, true
}

type sourceHit struct {
	path   string
	offset int64
	line   string
}

// scanSources returns the first match per application source file.
func scanSources(ctx context.Context, in Input, r *Rule) ([]sourceHit, error) {
	var hits []sourceHit
	for _, p := range in.Inv.Sources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		f, err := in.Root.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		var off int64
		for sc.Scan() {
			l := sc.Text()
			if r.sourceRe.MatchString(l) {
				hits = append(hits, sourceHit{p, off, trimLine(l)})
				break
			}
			off += int64(len(l)) + 1
		}
		f.Close()
		if len(hits) >= maxSourceHitsPerRule {
			break
		}
	}
	return hits, nil
}

func trimLine(l string) string {
	l = strings.TrimSpace(l)
	if len(l) > 160 {
		l = l[:160] + "…"
	}
	return l
}

// collectUnlessFiles finds, in one walk, the files satisfying each rule's
// unless_file condition.
func collectUnlessFiles(ctx context.Context, rs []*Rule, root *os.Root) (map[string][]string, error) {
	out := map[string][]string{}
	var want []*Rule
	for _, r := range rs {
		if r.unlessPathRe != nil {
			want = append(want, r)
		}
	}
	if len(want) == 0 {
		return out, nil
	}
	err := fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if !d.Type().IsRegular() {
			return nil
		}
		for _, r := range want {
			if !r.unlessPathRe.MatchString(p) {
				continue
			}
			b, err := readLimited(root, p, 1<<20)
			if err == nil && r.unlessContentRe.Match(b) {
				out[r.ID] = append(out[r.ID], p)
			}
		}
		return nil
	})
	return out, err
}

func readLimited(root *os.Root, p string, max int64) ([]byte, error) {
	f, err := root.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max))
}

func fileHash(root *os.Root, p string) string {
	f, err := root.Open(filepath.FromSlash(p))
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}
