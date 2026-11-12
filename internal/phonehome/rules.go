// Package phonehome evaluates the embedded rule pack (spec §3.2) against a
// scanned filesystem and its image environment. It catches phone-home paths
// the egress observation window might not exercise. It only reads files.
package phonehome

import (
	"bytes"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/uddeshya-world/gapproof/internal/evidence"
	"github.com/uddeshya-world/gapproof/rules"
)

// Rule is one phone-home rule (rules/<ID>.yaml).
type Rule struct {
	ID          string            `yaml:"id" json:"id"`
	Title       string            `yaml:"title" json:"title"`
	Severity    evidence.Severity `yaml:"severity" json:"severity"`
	Confidence  string            `yaml:"confidence" json:"confidence"`
	Explanation string            `yaml:"explanation" json:"explanation"`
	Match       Match             `yaml:"match" json:"match"`
	Fix         string            `yaml:"fix" json:"fix"`
	Controls    []string          `yaml:"controls" json:"controls"`
	Source      []string          `yaml:"source" json:"source"`

	sourceRe, unlessPathRe, unlessContentRe *regexp.Regexp
	versionSpec                             VersionSpec
}

// Match lists conditions; every condition present must hold. Any satisfied
// unless_* condition suppresses the rule.
type Match struct {
	// Any of these Python distributions is installed.
	PythonPackage StringList `yaml:"python_package,omitempty" json:"python_package,omitempty"`
	// Only installed versions of those packages inside this PEP 440 range
	// count, e.g. "<1.5.4" (D-036). An unparseable installed version counts.
	PythonPackageVersion string `yaml:"python_package_version,omitempty" json:"python_package_version,omitempty"`
	// Any of these image env vars has one of the listed values.
	Env map[string][]string `yaml:"env,omitempty" json:"env,omitempty"`
	// Any of these image env vars holds a URL/host that isn't private.
	EnvPublicURL []string `yaml:"env_public_url,omitempty" json:"env_public_url,omitempty"`
	// Application source (.py/.js outside site-packages) matches.
	SourceRegex string `yaml:"source_regex,omitempty" json:"source_regex,omitempty"`

	UnlessEnv  map[string][]string `yaml:"unless_env,omitempty" json:"unless_env,omitempty"`
	UnlessFile *FileMatch          `yaml:"unless_file,omitempty" json:"unless_file,omitempty"`
}

// FileMatch is satisfied by any file whose path and content both match.
type FileMatch struct {
	PathRegex    string `yaml:"path_regex" json:"path_regex"`
	ContentRegex string `yaml:"content_regex" json:"content_regex"`
}

// StringList accepts a YAML scalar or sequence.
type StringList []string

func (s *StringList) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		*s = []string{n.Value}
		return nil
	case yaml.SequenceNode:
		var xs []string
		if err := n.Decode(&xs); err != nil {
			return err
		}
		*s = xs
		return nil
	}
	return fmt.Errorf("line %d: want a string or a list of strings", n.Line)
}

var idRe = regexp.MustCompile(`^PH-[A-Z0-9]+(-[A-Z0-9]+)*$`)

var validSeverity = map[evidence.Severity]bool{evidence.Critical: true, evidence.High: true, evidence.Medium: true, evidence.Low: true, evidence.Info: true}

// Builtin loads the embedded rule pack.
func Builtin() ([]*Rule, error) { return Load(rules.PhoneHome) }

// Load reads and validates every *.yaml rule in fsys, sorted by ID.
func Load(fsys fs.FS) ([]*Rule, error) {
	names, err := fs.Glob(fsys, "*.yaml")
	if err != nil {
		return nil, err
	}
	var out []*Rule
	seen := map[string]string{}
	for _, name := range names {
		b, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, err
		}
		dec := yaml.NewDecoder(bytes.NewReader(b))
		dec.KnownFields(true) // a typo in a rule must fail, not silently never match
		r := &Rule{}
		if err := dec.Decode(r); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if err := r.validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if want := r.ID + ".yaml"; path.Base(name) != want {
			return nil, fmt.Errorf("%s: rule %s must live in %s", name, r.ID, want)
		}
		if prev, ok := seen[r.ID]; ok {
			return nil, fmt.Errorf("%s: duplicate rule id %s (also in %s)", name, r.ID, prev)
		}
		seen[r.ID] = name
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b *Rule) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

func (r *Rule) validate() error {
	switch {
	case !idRe.MatchString(r.ID):
		return fmt.Errorf("id %q must look like PH-NAME", r.ID)
	case strings.TrimSpace(r.Title) == "" || strings.TrimSpace(r.Explanation) == "" || strings.TrimSpace(r.Fix) == "":
		return fmt.Errorf("%s: title, explanation and fix are required", r.ID)
	case !validSeverity[r.Severity]:
		return fmt.Errorf("%s: bad severity %q", r.ID, r.Severity)
	case r.Confidence != "high" && r.Confidence != "low":
		return fmt.Errorf("%s: confidence must be high or low (low when upstream docs couldn't be verified)", r.ID)
	case len(r.Controls) == 0:
		return fmt.Errorf("%s: at least one control mapping is required", r.ID)
	case len(r.Source) == 0:
		return fmt.Errorf("%s: source: must cite the upstream doc the rule was checked against", r.ID)
	}
	for _, s := range r.Source {
		if !strings.HasPrefix(s, "https://") {
			return fmt.Errorf("%s: source %q must be an https URL", r.ID, s)
		}
	}
	m := r.Match
	if len(m.PythonPackage) == 0 && len(m.Env) == 0 && len(m.EnvPublicURL) == 0 && m.SourceRegex == "" {
		return fmt.Errorf("%s: match needs at least one of python_package, env, env_public_url, source_regex", r.ID)
	}
	var err error
	if m.PythonPackageVersion != "" {
		if len(m.PythonPackage) == 0 {
			return fmt.Errorf("%s: python_package_version needs python_package", r.ID)
		}
		if r.versionSpec, err = parseSpec(m.PythonPackageVersion); err != nil {
			return fmt.Errorf("%s: python_package_version: %w", r.ID, err)
		}
	}
	if m.SourceRegex != "" {
		if r.sourceRe, err = regexp.Compile(m.SourceRegex); err != nil {
			return fmt.Errorf("%s: source_regex: %w", r.ID, err)
		}
	}
	if f := m.UnlessFile; f != nil {
		if r.unlessPathRe, err = regexp.Compile(f.PathRegex); err != nil || f.PathRegex == "" {
			return fmt.Errorf("%s: unless_file.path_regex: %v", r.ID, err)
		}
		if r.unlessContentRe, err = regexp.Compile(f.ContentRegex); err != nil || f.ContentRegex == "" {
			return fmt.Errorf("%s: unless_file.content_regex: %v", r.ID, err)
		}
	}
	for k, vs := range m.Env {
		if len(vs) == 0 {
			return fmt.Errorf("%s: env %s needs at least one value", r.ID, k)
		}
	}
	for k, vs := range m.UnlessEnv {
		if len(vs) == 0 {
			return fmt.Errorf("%s: unless_env %s needs at least one value", r.ID, k)
		}
	}
	return nil
}
