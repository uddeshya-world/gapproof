package diff

import (
	"bytes"
	"strings"
	"testing"

	"github.com/uddeshya-world/gapproof/internal/evidence"
)

func f(id, rule, path string, sev evidence.Severity, st evidence.Status) evidence.Finding {
	return evidence.Finding{ID: id, Rule: rule, Severity: sev, Status: st, Title: rule + " " + path, Evidence: evidence.Evidence{Path: path}}
}

func TestCompare(t *testing.T) {
	old := &evidence.Bundle{
		AGR:      evidence.AGR{Level: evidence.LevelAGR1},
		Findings: []evidence.Finding{f("PH-0001", "PH-X", "a.py", evidence.High, "open"), f("CR-0001", "CRYPTO-Y", "lib.so", evidence.Medium, "open"), f("MD-0001", "MODEL-Z", "m.pt", evidence.Critical, "open")},
		Egress:   &evidence.EgressSection{Attempts: []evidence.EgressAttempt{{Kind: "dns", Name: "a.example"}, {Kind: "dns", Name: "b.example"}}},
		Models:   &evidence.ModelsSection{Artifacts: []evidence.ModelArtifact{{Path: "m.pt", SHA256: "aaaa"}, {Path: "keep.bin", SHA256: "k"}}},
		Crypto:   &evidence.CryptoSection{Modules: []evidence.CryptoModule{{Path: "lib.so", SHA256: "c1"}}},
	}
	new := &evidence.Bundle{
		AGR: evidence.AGR{Level: evidence.LevelAGR3},
		// PH renumbered but same rule+evidence: not new. CR waived: changed. MD resolved. New AG.
		Findings: []evidence.Finding{f("PH-0002", "PH-X", "a.py", evidence.High, "open"), f("CR-0001", "CRYPTO-Y", "lib.so", evidence.Medium, "waived"), f("AG-0001", "AGENT-INV01-PATH", "agents.yaml", evidence.High, "open")},
		Egress:   &evidence.EgressSection{Attempts: []evidence.EgressAttempt{{Kind: "dns", Name: "b.example"}, {Kind: "dns", Name: "c.example"}}},
		Models:   &evidence.ModelsSection{Artifacts: []evidence.ModelArtifact{{Path: "m.safetensors", SHA256: "bbbb"}, {Path: "keep.bin", SHA256: "k2"}}},
	}
	r := Compare(old, new)
	if len(r.Added) != 1 || r.Added[0].Rule != "AGENT-INV01-PATH" {
		t.Errorf("added = %+v", r.Added)
	}
	if len(r.Removed) != 1 || r.Removed[0].Rule != "MODEL-Z" {
		t.Errorf("removed = %+v", r.Removed)
	}
	if len(r.Changed) != 1 || r.Changed[0].New.Status != "waived" {
		t.Errorf("changed = %+v", r.Changed)
	}
	if len(r.EgressAdded) != 1 || r.EgressAdded[0].Name != "c.example" || len(r.EgressRemoved) != 1 {
		t.Errorf("egress = %+v / %+v", r.EgressAdded, r.EgressRemoved)
	}
	if len(r.Models) != 3 || len(r.Crypto) != 1 || r.Crypto[0].NewSHA != "" {
		t.Errorf("hashes = %+v / %+v", r.Models, r.Crypto)
	}
	if !r.Regressed() {
		t.Error("a new open finding is a regression even when the level improves")
	}
	var full, sum bytes.Buffer
	r.WriteFull(&full)
	r.WriteSummary(&sum)
	for _, want := range []string{"AGR-1 → (improved) AGR-3", "+ AG-0001", "- MD-0001", "~ CR-0001 → CR-0001", "+ dns c.example", "~ keep.bin  k → k2", "- lib.so"} {
		if !strings.Contains(full.String(), want) {
			t.Errorf("full diff missing %q:\n%s", want, full.String())
		}
	}
	if strings.Contains(sum.String(), "AG-0001") || len(strings.Split(strings.TrimSpace(sum.String()), "\n")) != 3 {
		t.Errorf("summary should be 3 count lines:\n%s", sum.String())
	}

	same := Compare(new, new)
	if same.Regressed() || len(same.Added)+len(same.Removed)+len(same.Changed) != 0 {
		t.Errorf("self-diff not empty: %+v", same)
	}
	var s bytes.Buffer
	same.WriteSummary(&s)
	if !strings.Contains(s.String(), "(unchanged)") {
		t.Error(s.String())
	}
	down := Compare(new, old)
	if !down.Regressed() {
		t.Error("level drop must regress")
	}
	s.Reset()
	down.WriteSummary(&s)
	if !strings.Contains(s.String(), "REGRESSED") {
		t.Error(s.String())
	}
}
