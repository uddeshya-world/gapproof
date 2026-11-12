package agents

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"

	"go.yaml.in/yaml/v3"
)

// Limits on a vendor-supplied manifest. Exceeding one is an error, never a
// silent truncation.
const (
	MaxManifestBytes    = 1 << 20 // 1 MiB
	MaxAgents           = 100
	MaxTools            = 500
	MaxHandoffsPerAgent = 100
	MaxNodes            = 5000 // total agent-tool memberships
	MaxLabelsPerTool    = 8
	MaxTargetsPerTool   = 64
	MaxTargetLen        = 256
)

// Labels.
const (
	ReadSensitive    = "sensitive" // P=3: regulated/customer data
	ReadInternal     = "internal"  // P=2: internal data
	ReadPublic       = "public"    // U=2: anonymous-external input
	ReadUntrusted    = "untrusted" // U=3: public-writable input (web, email, issues, user content)
	SinkBoundary     = "boundary_crossing"
	SinkExec         = "exec"
	SinkInternal     = "internal"
	GateHumanApprove = "human_approval"
)

var (
	validReads = map[string]bool{ReadSensitive: true, ReadInternal: true, ReadPublic: true, ReadUntrusted: true}
	validSinks = map[string]bool{SinkBoundary: true, SinkExec: true, SinkInternal: true}
	validGates = map[string]bool{GateHumanApprove: true}
	// MCP tool-name charset; also keeps names safe in YAML, Markdown and
	// the "agent:tool" node notation.
	nameRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.\-]{0,127}$`)
)

// Manifest is a validated agents.yaml.
type Manifest struct {
	Agents []Agent           `yaml:"agents" json:"agents"`
	Tools  map[string]Tool   `yaml:"tools" json:"tools"`
	Gates  map[string]string `yaml:"gates" json:"gates"`
}

// Agent is one agent: the tools it holds and the agents it hands off to.
type Agent struct {
	Name     string   `yaml:"name" json:"name"`
	Tools    []string `yaml:"tools" json:"tools"`
	Handoffs []string `yaml:"handoffs" json:"handoffs"`
}

// Tool carries a tool's data-flow labels.
type Tool struct {
	Reads   []string `yaml:"reads" json:"reads,omitempty"`
	Sinks   []string `yaml:"sinks" json:"sinks,omitempty"`
	Targets []string `yaml:"targets" json:"targets,omitempty"` // non-empty: boundary_crossing is E=2, not 3
}

type rawManifest struct {
	Agents *[]Agent          `yaml:"agents"`
	Tools  map[string]Tool   `yaml:"tools"`
	Gates  map[string]string `yaml:"gates"`
	// Declared only to give a precise error: a manifest that picks its own
	// zone or thresholds could make any finding disappear (D-032).
	Zone       yaml.Node `yaml:"zone"`
	Thresholds yaml.Node `yaml:"thresholds"`
}

// ReadManifestFile reads a manifest file, refusing anything over
// MaxManifestBytes, and returns its bytes for hashing and parsing.
func ReadManifestFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxManifestBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxManifestBytes {
		return nil, fmt.Errorf("%s: manifest larger than %d bytes", path, MaxManifestBytes)
	}
	return b, nil
}

// ParseManifest decodes and validates agents.yaml strictly. `agents: []` is
// valid and declares no agentic tool use; a missing `agents:` key is not.
func ParseManifest(data []byte) (*Manifest, error) {
	if len(data) > MaxManifestBytes {
		return nil, fmt.Errorf("agents manifest: larger than %d bytes", MaxManifestBytes)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // a typo must fail, not silently drop a label
	var raw rawManifest
	if err := dec.Decode(&raw); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("agents manifest: empty")
		}
		return nil, fmt.Errorf("agents manifest: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("agents manifest: exactly one YAML document expected")
	}
	if raw.Zone.Kind != 0 || raw.Thresholds.Kind != 0 {
		return nil, errors.New("agents manifest: `zone` and `thresholds` can't be set; INV-01 always uses MESA's production threshold (P=2, U=2, E=2)")
	}
	if raw.Agents == nil {
		return nil, errors.New("agents manifest: `agents:` is required (use `agents: []` to declare no agentic tool use)")
	}
	m := &Manifest{Agents: *raw.Agents, Tools: raw.Tools, Gates: raw.Gates}
	if m.Tools == nil {
		m.Tools = map[string]Tool{}
	}
	if m.Gates == nil {
		m.Gates = map[string]string{}
	}
	if err := m.validate(); err != nil {
		return nil, fmt.Errorf("agents manifest: %w", err)
	}
	return m, nil
}

func (m *Manifest) validate() error {
	if len(m.Agents) > MaxAgents {
		return fmt.Errorf("%d agents (max %d)", len(m.Agents), MaxAgents)
	}
	if len(m.Tools) > MaxTools {
		return fmt.Errorf("%d tools (max %d)", len(m.Tools), MaxTools)
	}
	for _, name := range sortedKeys(m.Tools) {
		t := m.Tools[name]
		if !nameRe.MatchString(name) {
			return fmt.Errorf("tool name %q: want 1-128 of [A-Za-z0-9_.-]", trunc(name))
		}
		if err := checkLabels(name, "reads", t.Reads, validReads); err != nil {
			return err
		}
		if err := checkLabels(name, "sinks", t.Sinks, validSinks); err != nil {
			return err
		}
		if len(t.Targets) > MaxTargetsPerTool {
			return fmt.Errorf("tool %s: %d targets (max %d)", name, len(t.Targets), MaxTargetsPerTool)
		}
		for _, tg := range t.Targets {
			if len(tg) > MaxTargetLen {
				return fmt.Errorf("tool %s: target longer than %d bytes", name, MaxTargetLen)
			}
		}
	}
	for _, name := range sortedKeys(m.Gates) {
		if _, ok := m.Tools[name]; !ok {
			return fmt.Errorf("gate on unknown tool %q", trunc(name))
		}
		if kind := m.Gates[name]; !validGates[kind] {
			return fmt.Errorf("gate on %s: unknown kind %q (want %s)", name, trunc(kind), GateHumanApprove)
		}
	}
	agents := map[string]bool{}
	nodes := 0
	for i, a := range m.Agents {
		if !nameRe.MatchString(a.Name) {
			return fmt.Errorf("agent #%d: name %q: want 1-128 of [A-Za-z0-9_.-]", i+1, trunc(a.Name))
		}
		if agents[a.Name] {
			return fmt.Errorf("duplicate agent %s", a.Name)
		}
		agents[a.Name] = true
		if len(a.Tools) > MaxTools {
			return fmt.Errorf("agent %s: %d tools (max %d)", a.Name, len(a.Tools), MaxTools)
		}
		if len(a.Handoffs) > MaxHandoffsPerAgent {
			return fmt.Errorf("agent %s: %d handoffs (max %d)", a.Name, len(a.Handoffs), MaxHandoffsPerAgent)
		}
		nodes += len(a.Tools)
		if nodes > MaxNodes {
			return fmt.Errorf("more than %d agent-tool memberships", MaxNodes)
		}
		seen := map[string]bool{}
		for _, t := range a.Tools {
			if _, ok := m.Tools[t]; !ok {
				return fmt.Errorf("agent %s: unknown tool %q (declare it under tools:)", a.Name, trunc(t))
			}
			if seen[t] {
				return fmt.Errorf("agent %s: tool %s listed twice", a.Name, t)
			}
			seen[t] = true
		}
	}
	for _, a := range m.Agents {
		seen := map[string]bool{}
		for _, h := range a.Handoffs {
			if !agents[h] {
				return fmt.Errorf("agent %s: handoff to unknown agent %q", a.Name, trunc(h))
			}
			if seen[h] {
				return fmt.Errorf("agent %s: handoff to %s listed twice", a.Name, h)
			}
			seen[h] = true
		}
	}
	return nil
}

func checkLabels(tool, field string, labels []string, valid map[string]bool) error {
	if len(labels) > MaxLabelsPerTool {
		return fmt.Errorf("tool %s: %d %s labels (max %d)", tool, len(labels), field, MaxLabelsPerTool)
	}
	for _, l := range labels {
		if !valid[l] {
			return fmt.Errorf("tool %s: unknown %s label %q (want one of %v)", tool, field, trunc(l), sortedKeys(valid))
		}
	}
	return nil
}

// trunc keeps hostile names short in error messages (%q escapes the rest).
func trunc(s string) string {
	if len(s) > 64 {
		return s[:64] + "..."
	}
	return s
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}
