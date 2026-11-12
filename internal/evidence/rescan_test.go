package evidence

import (
	"slices"
	"strings"
	"testing"
)

func rfnd(id, rule, path, sha string, sev Severity) Finding {
	return Finding{ID: id, Rule: rule, Severity: sev, Title: "t", Evidence: Evidence{Path: path, SHA256: sha}, Status: StatusOpen}
}

func TestCompareStatic(t *testing.T) {
	static := []string{ModPhoneHome, ModCrypto, ModModels, ModAgents}
	base := func() *Bundle {
		return &Bundle{
			Modules: []ModuleStatus{{Name: ModPhoneHome, Status: ModuleRan}, {Name: ModCrypto, Status: ModuleRan}},
			Findings: []Finding{
				rfnd("PH-0001", "PH-X", "a", "h1", High),
				rfnd("EG-0001", RuleEgressAttempt, "", "", High),
			},
			Crypto: &CryptoSection{SnapshotDate: "2026-01-01", Modules: []CryptoModule{{Path: "lib.so", Library: "openssl", Version: "3"}}, Configs: []string{}},
			Models: &ModelsSection{Artifacts: []ModelArtifact{{Path: "m.gguf", SHA256: "x"}, {Path: "(--models)/e.gguf", SHA256: "y"}}},
		}
	}
	tests := []struct {
		name   string
		mut    func(b *Bundle)
		expect []string // exact DiffEntry strings, in output order
	}{
		{"identical", func(*Bundle) {}, nil},
		{"egress and warnings ignored", func(b *Bundle) {
			b.Findings[1].Severity = Low
			b.Findings = append(b.Findings, rfnd("EG-0002", RuleEgressAttempt, "z", "", High))
			b.Warnings = []string{"w"}
			b.Egress = &EgressSection{}
		}, nil},
		{"finding only in rescan", func(b *Bundle) { b.Findings = b.Findings[1:] }, []string{"added findings: PH-0001 PH-X|a||h1||"}},
		{"finding added", func(b *Bundle) { b.Findings = append(b.Findings, rfnd("PH-0002", "PH-X", "b", "h2", Low)) },
			[]string{"added findings: PH-0002 PH-X|b||h2||"}},
		{"evidence hash changed is remove plus add", func(b *Bundle) { b.Findings[0].Evidence.SHA256 = "h9" },
			[]string{"removed findings: PH-0001 PH-X|a||h1||", "added findings: PH-0001 PH-X|a||h9||"}},
		{"severity changed", func(b *Bundle) { b.Findings[0].Severity = Low },
			[]string{"changed findings: PH-0001 PH-X|a||h1|| (severity)"}},
		{"status waived", func(b *Bundle) { b.Findings[0].Status = StatusWaived },
			[]string{"changed findings: PH-0001 PH-X|a||h1|| (status)"}},
		{"crypto module changed", func(b *Bundle) { b.Crypto.Modules[0].Status = "unvalidated" },
			[]string{"changed crypto: lib.so|openssl|3 (record differs)"}},
		{"crypto module added", func(b *Bundle) {
			b.Crypto.Modules = append(b.Crypto.Modules, CryptoModule{Path: "n.so", Library: "nss"})
		},
			[]string{"added crypto: n.so|nss|"}},
		{"snapshot date", func(b *Bundle) { b.Crypto.SnapshotDate = "2026-02-01" },
			[]string{"changed crypto: cmvp snapshot date (2026-01-01 -> 2026-02-01)"}},
		{"model sha changed", func(b *Bundle) { b.Models.Artifacts[0].SHA256 = "z" },
			[]string{"changed models: m.gguf (artifact record differs)"}},
		{"--models extras ignored", func(b *Bundle) { b.Models.Artifacts[1].SHA256 = "q" }, nil},
		{"agents section", func(b *Bundle) { b.Agents = &AgentsSection{Violations: 2} },
			[]string{"added agents: agents section"}},
		{"module state", func(b *Bundle) { b.Modules[0].Status = ModuleFailed },
			[]string{"changed modules: phonehome (ran -> failed)"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, now := base(), base()
			if tc.name == "finding only in rescan" {
				// "removed" is from the signed evidence's side: the rescan
				// found one more, so mutate the recorded side instead.
				tc.mut(rec)
			} else {
				tc.mut(now)
			}
			var got []string
			for _, d := range CompareStatic(rec, now, CompareOpts{Modules: static, IgnorePathPrefix: "(--models)/"}) {
				got = append(got, d.String())
			}
			if !slices.Equal(got, tc.expect) {
				t.Errorf("got\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(tc.expect, "\n  "))
			}
		})
	}

	// A finding the rescan did not reproduce is reported as removed.
	rec, now := base(), base()
	now.Findings = now.Findings[1:]
	d := CompareStatic(rec, now, CompareOpts{Modules: static})
	if len(d) != 1 || d[0].Kind != DiffRemoved {
		t.Errorf("want one removed finding, got %v", d)
	}
	// Module filter: a module not listed is not compared.
	if d := CompareStatic(rec, now, CompareOpts{Modules: []string{ModCrypto}}); len(d) != 0 {
		t.Errorf("unlisted module compared: %v", d)
	}
}
