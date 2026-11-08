// Package inventory takes one bounded pass over a scanned filesystem and
// records what the rule-based modules need: installed Python distributions
// and the application's own source files. It reads metadata as text only.
package inventory

import (
	"bufio"
	"context"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
)

// PythonPackage is one installed distribution.
type PythonPackage struct {
	Name      string   `json:"name"` // normalised (PEP 503)
	RawName   string   `json:"raw_name"`
	Version   string   `json:"version"`
	Metadata  string   `json:"metadata"`             // path of METADATA / PKG-INFO
	WheelTags []string `json:"wheel_tags,omitempty"` // from the WHEEL file; empty for source installs
}

// Inventory is the result of one walk. All slices are sorted.
type Inventory struct {
	Python  []PythonPackage `json:"python"`
	Sources []string        `json:"sources"`                   // application .py/.js files
	Skipped int             `json:"skipped_sources,omitempty"` // over the source-file cap
}

// Limits bound the walk.
type Limits struct {
	MaxSources    int   // application source files kept
	MaxSourceSize int64 // bytes; larger files aren't scanned as source
}

func DefaultLimits() Limits { return Limits{MaxSources: 50_000, MaxSourceSize: 2 << 20} }

var nonAlnum = regexp.MustCompile(`[-_.]+`)

// Normalize returns the PEP 503 normalised project name.
func Normalize(name string) string { return strings.ToLower(nonAlnum.ReplaceAllString(name, "-")) }

var sourceExt = map[string]bool{".py": true, ".js": true, ".mjs": true, ".cjs": true}

// IsLibraryPath reports whether p is third-party or interpreter code rather
// than the application: site-packages, node_modules, the Python stdlib.
func IsLibraryPath(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		switch {
		case seg == "site-packages", seg == "dist-packages", seg == "node_modules", seg == "__pycache__":
			return true
		case strings.HasPrefix(seg, "python") && len(seg) > 6 && (seg[6] >= '0' && seg[6] <= '9'):
			return true // lib/python3.12/...
		}
	}
	return strings.HasPrefix(p, "usr/share/") || strings.HasPrefix(p, "usr/lib/node")
}

// Build walks root once.
func Build(ctx context.Context, root *os.Root, lim Limits) (*Inventory, error) {
	inv := &Inventory{Python: []PythonPackage{}, Sources: []string{}}
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
		base := path.Base(p)
		dir := path.Dir(p)
		switch {
		case base == "METADATA" && strings.HasSuffix(dir, ".dist-info"),
			base == "PKG-INFO" && strings.HasSuffix(dir, ".egg-info"):
			if pkg, ok := readMetadata(root, p); ok {
				if strings.HasSuffix(dir, ".dist-info") {
					pkg.WheelTags = readWheelTags(root, dir+"/WHEEL")
				}
				inv.Python = append(inv.Python, pkg)
			}
		case sourceExt[path.Ext(base)] && !IsLibraryPath(p):
			if fi, err := d.Info(); err != nil || fi.Size() > lim.MaxSourceSize {
				return nil
			}
			if len(inv.Sources) >= lim.MaxSources {
				inv.Skipped++
				return nil
			}
			inv.Sources = append(inv.Sources, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(inv.Python, func(a, b PythonPackage) int {
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return strings.Compare(a.Metadata, b.Metadata)
	})
	slices.Sort(inv.Sources)
	return inv, nil
}

// Package returns every installed distribution with that (normalised) name.
func (inv *Inventory) Package(name string) []PythonPackage {
	name = Normalize(name)
	var out []PythonPackage
	for _, p := range inv.Python {
		if p.Name == name {
			out = append(out, p)
		}
	}
	return out
}

// readMetadata reads the RFC 822 header block of METADATA / PKG-INFO.
func readMetadata(root *os.Root, p string) (PythonPackage, bool) {
	f, err := root.Open(p)
	if err != nil {
		return PythonPackage{}, false
	}
	defer f.Close()
	pkg := PythonPackage{Metadata: p}
	sc := bufio.NewScanner(io.LimitReader(f, 256<<10))
	for sc.Scan() {
		l := sc.Text()
		if l == "" {
			break // end of headers; the long description follows
		}
		if v, ok := strings.CutPrefix(l, "Name:"); ok && pkg.RawName == "" {
			pkg.RawName = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(l, "Version:"); ok && pkg.Version == "" {
			pkg.Version = strings.TrimSpace(v)
		}
	}
	if pkg.RawName == "" {
		return PythonPackage{}, false
	}
	pkg.Name = Normalize(pkg.RawName)
	return pkg, true
}

func readWheelTags(root *os.Root, p string) []string {
	f, err := root.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	var tags []string
	sc := bufio.NewScanner(io.LimitReader(f, 64<<10))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "Tag:"); ok {
			tags = append(tags, strings.TrimSpace(v))
		}
	}
	slices.Sort(tags)
	return tags
}

// EnvMap parses KEY=VALUE pairs (image config Env). Later entries win, as
// in Docker.
func EnvMap(env []string) map[string]string {
	m := map[string]string{}
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		if ok && k != "" {
			m[k] = v
		}
	}
	return m
}
