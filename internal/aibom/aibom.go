// Package aibom renders the model scan as a CycloneDX 1.6 AI-BOM
// (aibom.cdx.json, docs/02_SPEC.md §3.4/§3.6).
//
// Output is deterministic (CLAUDE.md rule 6): no timestamps, components in
// path order, properties sorted, and a serialNumber derived from the BOM's
// own content rather than random.
package aibom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/uddeshya-world/gapproof/internal/detid"
	"github.com/uddeshya-world/gapproof/internal/models"
)

// FileName is the AI-BOM's name in the evidence directory.
const FileName = "aibom.cdx.json"

// Disclaimer travels inside the BOM (CLAUDE.md rule 4).
const Disclaimer = "Inventory produced by static analysis. It is not a certification, an ATO or a FIPS 140-3 validation; licences are as declared in the model files."

// Subject is the scanned artefact the BOM describes.
type Subject struct {
	Name         string // e.g. the first repo tag, or the archive file name
	ConfigDigest string // "sha256:<hex>"; "" for a --rootfs scan
	ImageID      string // engine/registry digest (fsscan.Image.ImageID), optional
}

// Input is everything the BOM is built from.
type Input struct {
	ToolVersion string
	Subject     Subject
	Models      *models.Result
}

// BOM is the subset of CycloneDX 1.6 that Gapproof emits. Field order is
// the JSON order.
type BOM struct {
	BOMFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber"`
	Version      int          `json:"version"`
	Metadata     Metadata     `json:"metadata"`
	Components   []Component  `json:"components"`
	Dependencies []Dependency `json:"dependencies,omitempty"`
}

// Metadata is the BOM's metadata block.
type Metadata struct {
	Tools      Tools      `json:"tools"`
	Component  *Component `json:"component,omitempty"`
	Properties []Property `json:"properties,omitempty"`
}

// Tools lists the generating tool (1.6 object form).
type Tools struct {
	Components []Component `json:"components"`
}

// Component is a CycloneDX component.
type Component struct {
	BOMRef     string        `json:"bom-ref,omitempty"`
	Type       string        `json:"type"`
	Name       string        `json:"name"`
	Version    string        `json:"version,omitempty"`
	Hashes     []Hash        `json:"hashes,omitempty"`
	Licenses   []LicenseItem `json:"licenses,omitempty"`
	Properties []Property    `json:"properties,omitempty"`
}

// Hash is a component hash.
type Hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// LicenseItem wraps one licence.
type LicenseItem struct {
	License License `json:"license"`
}

// License is an SPDX id (when recognised) or a free-text name.
type License struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// Property is a name/value pair.
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Dependency links the image to the components found in it.
type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

var hexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// modelFormats are weight/graph formats: CycloneDX "machine-learning-model".
var modelFormats = map[string]bool{
	"safetensors": true, "gguf": true, "onnx": true, "pytorch-zip": true, "torchscript": true,
	"pickle": true, "keras": true, "keras-h5": true, "joblib-compressed": true,
}

// componentType maps a models.Artifact format to a CycloneDX component type.
func componentType(format string) string {
	switch {
	case modelFormats[format]:
		return "machine-learning-model"
	case format == "npy", format == "npz", format == "onnx-external-data":
		return "data"
	default: // hf-config, hf-tokenizer-config, hf-tokenizer, anything new
		return "file"
	}
}

// spdxIDs maps the lowercase licence identifiers Hugging Face and GGUF use
// to SPDX ids. Anything else is emitted as a free-text name, never guessed.
var spdxIDs = map[string]string{
	"apache-2.0": "Apache-2.0", "mit": "MIT", "bsd-2-clause": "BSD-2-Clause", "bsd-3-clause": "BSD-3-Clause",
	"cc0-1.0": "CC0-1.0", "cc-by-4.0": "CC-BY-4.0", "cc-by-sa-4.0": "CC-BY-SA-4.0",
	"cc-by-nc-4.0": "CC-BY-NC-4.0", "cc-by-nc-sa-4.0": "CC-BY-NC-SA-4.0", "gpl-3.0": "GPL-3.0-only",
	"lgpl-3.0": "LGPL-3.0-only", "agpl-3.0": "AGPL-3.0-only", "mpl-2.0": "MPL-2.0", "unlicense": "Unlicense",
	"openrail": "", // not an SPDX id: emitted as a name
}

func license(l string) []LicenseItem {
	l = strings.TrimSpace(l)
	if l == "" {
		return nil
	}
	if id := spdxIDs[strings.ToLower(l)]; id != "" {
		return []LicenseItem{{License{ID: id}}}
	}
	return []LicenseItem{{License{Name: l}}}
}

// parseStatus derives each artefact's parse status from the model findings.
func parseStatus(res *models.Result) map[string]string {
	st := map[string]string{}
	for _, f := range res.Findings {
		switch f.Rule {
		case models.RuleParseFailed:
			st[f.Evidence.Path] = "parse-failed"
		case models.RuleUnscanned:
			if st[f.Evidence.Path] == "" {
				st[f.Evidence.Path] = "unscanned-format"
			}
		}
	}
	return st
}

func props(kv ...string) []Property {
	var ps []Property
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			ps = append(ps, Property{kv[i], kv[i+1]})
		}
	}
	slices.SortStableFunc(ps, func(a, b Property) int { return strings.Compare(a.Name, b.Name) })
	return ps
}

// Build constructs the BOM. It fails if an artefact's hash is not a SHA-256
// hex digest, since an AI-BOM entry without a hash is not evidence.
func Build(in Input) (*BOM, error) {
	if in.Models == nil {
		return nil, fmt.Errorf("aibom: no model scan result")
	}
	if in.Subject.ConfigDigest != "" && !strings.HasPrefix(in.Subject.ConfigDigest, "sha256:") {
		return nil, fmt.Errorf("aibom: config digest %q is not sha256:<hex>", in.Subject.ConfigDigest)
	}
	tool := Component{Type: "application", Name: "gapproof", Version: in.ToolVersion}
	b := &BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Version:     1,
		Metadata: Metadata{
			Tools:      Tools{Components: []Component{tool}},
			Properties: props("gapproof:disclaimer", Disclaimer),
		},
		Components: []Component{},
	}

	subjectRef := "subject"
	name := in.Subject.Name
	if name == "" {
		name = "scanned-artifact"
	}
	subject := Component{BOMRef: subjectRef, Type: "container", Name: name,
		Properties: props("gapproof:image:config_digest", in.Subject.ConfigDigest, "gapproof:image:image_id", in.Subject.ImageID)}
	if d := strings.TrimPrefix(in.Subject.ConfigDigest, "sha256:"); d != "" {
		if !hexRe.MatchString(d) {
			return nil, fmt.Errorf("aibom: config digest %q is not sha256:<hex>", in.Subject.ConfigDigest)
		}
		subject.Hashes = []Hash{{"SHA-256", d}}
	} else {
		subject.Type = "file" // a --rootfs directory, not an image
	}
	b.Metadata.Component = &subject

	status := parseStatus(in.Models)
	dep := Dependency{Ref: subjectRef}
	arts := slices.Clone(in.Models.Artifacts)
	slices.SortFunc(arts, func(a, b models.Artifact) int { return strings.Compare(a.Path, b.Path) })
	for _, a := range arts {
		if !hexRe.MatchString(a.SHA256) {
			return nil, fmt.Errorf("aibom: %s has no SHA-256 (%q)", a.Path, a.SHA256)
		}
		st := status[a.Path]
		if st == "" {
			st = "parsed"
		}
		cname := a.Name
		if cname == "" {
			cname = path.Base(a.Path)
		}
		var params, tensors string
		if a.Parameters > 0 {
			params = strconv.FormatInt(a.Parameters, 10)
		}
		if a.Tensors > 0 {
			tensors = strconv.Itoa(a.Tensors)
		}
		ref := "file:" + a.Path
		c := Component{
			BOMRef:   ref,
			Type:     componentType(a.Format),
			Name:     cname,
			Hashes:   []Hash{{"SHA-256", a.SHA256}},
			Licenses: license(a.License),
			Properties: props(
				"gapproof:path", a.Path,
				"gapproof:format", a.Format,
				"gapproof:size", strconv.FormatInt(a.Size, 10),
				"gapproof:parse_status", st,
				"gapproof:architecture", a.Architecture,
				"gapproof:parameters", params,
				"gapproof:tensors", tensors,
				"gapproof:dtypes", strings.Join(a.DTypes, ","),
				"gapproof:pickle_imports", strings.Join(a.Imports, ","),
			),
		}
		b.Components = append(b.Components, c)
		dep.DependsOn = append(dep.DependsOn, ref)
	}
	b.Dependencies = []Dependency{dep}

	raw, err := marshal(b)
	if err != nil {
		return nil, err
	}
	b.SerialNumber = "urn:uuid:" + detid.UUID("gapproof/aibom", string(raw))
	return b, nil
}

// Marshal renders the BOM as indented JSON with a trailing newline.
func Marshal(b *BOM) ([]byte, error) { return marshal(b) }

func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// AllModelsHashed reports whether every artefact in arts appears in the BOM
// with a matching SHA-256 hash: the AI-BOM condition of AGR-3
// (docs/AGR_SPEC.md §1). An empty artefact list is trivially hashed.
func AllModelsHashed(b *BOM, arts []models.Artifact) bool {
	if b == nil {
		return false
	}
	have := map[string]string{}
	for _, c := range b.Components {
		p, ok := strings.CutPrefix(c.BOMRef, "file:")
		if !ok {
			continue
		}
		for _, h := range c.Hashes {
			if h.Alg == "SHA-256" && hexRe.MatchString(h.Content) {
				have[p] = h.Content
			}
		}
	}
	for _, a := range arts {
		if h, ok := have[a.Path]; !ok || h != a.SHA256 {
			return false
		}
	}
	return true
}
