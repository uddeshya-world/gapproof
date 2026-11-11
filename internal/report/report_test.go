package report

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/uddeshya-world/gapproof/internal/evidence"
)

// Regenerate with: go test ./internal/report -run TestGolden -update
var update = flag.Bool("update", false, "rewrite testdata/golden")

const hostile = `<script>alert("x")</script> [click](https://evil.example/x) | ![img](http://evil.example/i.png) www.evil.example`

// fixture builds a bundle through the evidence API, writes it and loads it
// back, so the report is rendered from exactly what Load returns.
func fixture(t *testing.T) *evidence.Bundle {
	t.Helper()
	scope, err := evidence.ParseScope([]byte("scope_version: 1\ninternal_names: [vectordb]\ninternal_cidrs: [10.20.0.0/16]\n"))
	if err != nil {
		t.Fatal(err)
	}
	w, err := evidence.ParseWaivers([]byte(`waivers_version: 1
waivers:
  - rule: CRYPTO-UNVALIDATED-MODULE
    match: {path: "site-packages/cryptography/_rust.abi3.so"}
    justification: "TLS to the in-cluster DB only <b>bold</b>"
    owner: security@vendor.example
    expires: 2027-03-31
  - rule: CRYPTO-UNKNOWN-MODULE
    match: {path: usr/lib/libnettle.so.8}
    justification: base image
    owner: security@vendor.example
    expires: 2026-10-01
  - rule: PH-GRADIO-ANALYTICS
    match: {path: app/ui.py}
    justification: removed
    owner: security@vendor.example
    expires: 2027-03-31
`))
	if err != nil {
		t.Fatal(err)
	}
	attempts := scope.Mark([]evidence.EgressAttempt{
		{Kind: evidence.KindDNS, Name: "vectordb"},
		{Kind: evidence.KindTCP, Name: "us.i.posthog.com", OrigDstIP: "198.18.0.2", Port: 443, ProtoHint: "tls", SNI: "us.i.posthog.com", ALPN: []string{"h2"}},
		{Kind: evidence.KindTCP, Name: "evil<script>.example", OrigDstIP: "198.18.0.3", Port: 80, ProtoHint: "http", HTTPHost: "a|b"},
	}, "rag-app")
	raw := append(evidence.EgressFindings(attempts),
		evidence.Finding{Rule: "PH-SENTRY-DSN", Severity: evidence.High, Title: hostile,
			Explanation: "Sentry sends events to sentry.io. Source: https://docs.sentry.io/", Fix: "Remove sentry_sdk.init.\nSecond line is not shown in the fix-first list.",
			Evidence: evidence.Evidence{Path: "app/main.py", SHA256: strings.Repeat("a", 64), Offset: evidence.Off(10), Detail: "sentry_sdk.init(`dsn`)"},
			Controls: []string{"CM-7", "SC-7"}},
		evidence.Finding{Rule: "CRYPTO-UNVALIDATED-MODULE", Severity: evidence.High, Title: "Bundled OpenSSL 3.4.1",
			Explanation: "Bundled copies are always unvalidated.", Fix: "Build against a FIPS-enabled system OpenSSL.",
			Evidence: evidence.Evidence{Path: "site-packages/cryptography/_rust.abi3.so", SHA256: strings.Repeat("b", 64)}, Controls: []string{"SC-13"}},
		evidence.Finding{Rule: "CRYPTO-UNKNOWN-MODULE", Severity: evidence.High, Title: "nettle 3.9",
			Explanation: "Vendor builds may be validated.", Fix: "Remove nettle.",
			Evidence: evidence.Evidence{Path: "usr/lib/libnettle.so.8", SHA256: strings.Repeat("c", 64)}, Controls: []string{"SC-13"}},
		evidence.Finding{Rule: "MODEL-PICKLE-CODE-EXEC", Severity: evidence.Critical, Title: "Pickle imports builtins.print",
			Explanation: "Loading this file runs code.", Fix: "Convert the model to safetensors.",
			Evidence: evidence.Evidence{Path: "models/reranker.pt", Member: "reranker/data.pkl", SHA256: strings.Repeat("e", 64), Offset: evidence.Off(42), Detail: "STACK_GLOBAL builtins.print"},
			Controls: []string{"SI-3", "SI-7"}},
		evidence.Finding{Rule: "CRYPTO-WEAK-HASH", Severity: evidence.Medium, Title: "hashlib.md5",
			Explanation: "MD5.", Fix: "Use sha256.", Evidence: evidence.Evidence{Path: "app/cache.py"}, Controls: []string{"SC-13"}},
		evidence.Finding{Rule: "WEIRD-RULE", Severity: evidence.Low, Title: "unclassified", Fix: "n/a", Controls: []string{}},
	)
	fs, wr, err := evidence.Finalize(raw, w, time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	b := evidence.Bundle{
		ToolVersion: "0.1.0-test", RulePackVersion: "2026.11.09", CMVPSnapshotDate: "2026-11-01",
		Target: evidence.Target{Image: "leaky-rag.tar", ConfigDigest: "sha256:" + strings.Repeat("1", 64), Hostname: "rag-app"},
		Modules: []evidence.ModuleStatus{
			{Name: evidence.ModEgress, Status: evidence.ModuleRan}, {Name: evidence.ModPhoneHome, Status: evidence.ModuleRan},
			{Name: evidence.ModCrypto, Status: evidence.ModuleRan}, {Name: evidence.ModModels, Status: evidence.ModuleRan},
			{Name: evidence.ModAgents, Status: evidence.ModuleRan},
		},
		Scope: scope, Waivers: wr,
		Egress: &evidence.EgressSection{TargetStarted: true, WorkloadPassed: true, ObservedWindowS: 600, Attempts: attempts},
		Crypto: &evidence.CryptoSection{SnapshotDate: "2026-11-01",
			Modules: []evidence.CryptoModule{
				{Path: "site-packages/cryptography/_rust.abi3.so", SHA256: strings.Repeat("b", 64), Library: "openssl", Version: "3.4.1", Origin: "python-wheel", Package: "cryptography", Status: "unvalidated"},
				{Path: "usr/lib/libnettle.so.8", SHA256: strings.Repeat("c", 64), Library: "nettle", Version: "3.9", Origin: "system", Status: "unknown"},
			},
			FIPSProviders: []evidence.FIPSProvider{{Path: "usr/lib/ossl-modules/fips.so", Version: "3.0.9"}}},
		Models: &evidence.ModelsSection{Artifacts: []evidence.ModelArtifact{
			{Path: "models/reranker.pt", Format: "pytorch-zip", Size: 3 << 20, SHA256: strings.Repeat("e", 64)},
			{Path: "models/tiny.safetensors", Format: "safetensors", Size: 512, SHA256: strings.Repeat("f", 64)},
		}},
		Agents:   &evidence.AgentsSection{Manifest: "agents.yaml", ManifestSHA256: strings.Repeat("9", 64), DeclaredNoAgents: true},
		Findings: fs,
		Run:      evidence.RunMeta{ID: "run-0001", RunDate: "2026-11-09", StartedAt: time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)},
	}
	b.AGR = evidence.Compute(b.AGRInput())
	dir := t.TempDir()
	if err := evidence.WriteEvidence(dir, b); err != nil {
		t.Fatal(err)
	}
	loaded, err := evidence.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return loaded
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (run with -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from golden; run with -update and review the diff", name)
	}
}

func render(t *testing.T, b *evidence.Bundle) (html, md string) {
	t.Helper()
	h, err := HTML(b)
	if err != nil {
		t.Fatal(err)
	}
	m, err := Markdown(b)
	if err != nil {
		t.Fatal(err)
	}
	return string(h), string(m)
}

func TestGolden(t *testing.T) {
	b := fixture(t)
	h, m := render(t, b)
	golden(t, "report.html", []byte(h))
	golden(t, "report.md", []byte(m))
	h2, m2 := render(t, fixture(t))
	if h != h2 || m != m2 {
		t.Error("rendering is not deterministic")
	}
}

func TestHTMLSelfContained(t *testing.T) {
	h, _ := render(t, fixture(t))
	for _, re := range []string{
		`(?i)<script`, `(?i)\bsrc\s*=`, `(?i)\bhref\s*=`, `(?i)url\s*\(`, `(?i)@import`,
		`(?i)<(link|img|iframe|object|embed|base|form|meta http-equiv)`, `(?i)\bon[a-z]+\s*=`,
	} {
		if loc := regexp.MustCompile(re).FindStringIndex(h); loc != nil {
			t.Errorf("report.html matches %s at %q", re, h[max(0, loc[0]-40):min(len(h), loc[1]+40)])
		}
	}
	if !strings.Contains(h, "&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt;") {
		t.Error("hostile finding title must be HTML-escaped")
	}
	if !strings.Contains(h, "TLS to the in-cluster DB only &lt;b&gt;bold&lt;/b&gt;") {
		t.Error("waiver justification must be escaped")
	}
	if !strings.Contains(h, "@media print") {
		t.Error("print CSS missing")
	}
}

func TestOrderAndContent(t *testing.T) {
	b := fixture(t)
	h, m := render(t, b)
	for name, doc := range map[string]string{"html": h, "md": m} {
		order := []string{"AGR-1 (observed 10m)", "Accepted risks", "What to fix first", "Declared scope",
			"Egress (observed)", "Phone-home (static rules)", "Crypto inventory", "Model artefacts", "Agent containment",
			"Other findings", "Appendix: raw evidence", "Coverage", "What this report is not"}
		last := -1
		for _, s := range order {
			i := strings.Index(doc, s)
			if i < 0 {
				t.Errorf("%s: missing %q", name, s)
				continue
			}
			if i < last {
				t.Errorf("%s: %q is out of order", name, s)
			}
			last = i
		}
		for _, want := range []string{
			"CMVP snapshot date", "2026-11-01", AgentsManifestLabel, NoAgentsLabel,
			"FIPS 140-3 validation", "IPv6-only behaviour", "Control mappings are informative",
			"expired", "matches no finding", "vectordb", "10.20.0.0/16", "in scope (declared)", "OUT OF SCOPE",
			"Remove sentry", "3.0 MiB", "512 B",
		} {
			if !strings.Contains(doc, want) {
				t.Errorf("%s: missing %q", name, want)
			}
		}
		if strings.Contains(doc, "Second line is not shown") && strings.Index(doc, "Second line is not shown") < strings.Index(doc, "Declared scope") {
			t.Errorf("%s: fix-first must show one line only", name)
		}
		for _, banned := range []string{"compliant", "Compliant", "certified", "Certified"} {
			if strings.Contains(doc, banned) {
				t.Errorf("%s: contains %q (rule 4)", name, banned)
			}
		}
	}
	// Critical comes before high in "What to fix first".
	fix := m[strings.Index(m, "What to fix first"):strings.Index(m, "Declared scope")]
	if c, hi := strings.Index(fix, "critical"), strings.Index(fix, "**high**"); c < 0 || hi < 0 || c > hi {
		t.Errorf("fix-first order:\n%s", fix)
	}
}

func TestMarkdownEscaping(t *testing.T) {
	_, m := render(t, fixture(t))
	for _, bad := range []string{"<script", "](https://", "![img]", "https://evil", "www.evil", "<b>"} {
		if strings.Contains(m, bad) {
			t.Errorf("markdown contains unescaped %q", bad)
		}
	}
	if !strings.Contains(m, `&lt;script&gt;`) || !strings.Contains(m, `\[click\]`) || !strings.Contains(m, `a\|b`) {
		t.Error("expected escaped forms")
	}
	if got := mdCode("a`b"); got != "a\\`b" {
		t.Errorf("mdCode fallback %q", got)
	}
	if mdCode("") != "" || md("line1\nline2") != "line1 line2" {
		t.Error("mdCode/md")
	}
}

func TestVariants(t *testing.T) {
	b := fixture(t)
	b.Waivers, b.Scope, b.Agents = nil, nil, nil
	b.Modules[4].Status = evidence.ModuleNotRun
	b.Egress = &evidence.EgressSection{HarnessFailed: true}
	b.Modules[0].Status = evidence.ModuleFailed
	b.Crypto = &evidence.CryptoSection{SnapshotDate: "2026-11-01"}
	b.Models = &evidence.ModelsSection{}
	b.Warnings = []string{"case collision: a vs A"}
	b.Findings = nil
	b.AGR = evidence.Compute(b.AGRInput())
	b.Target.Image = ""
	h, m := render(t, b)
	for name, doc := range map[string]string{"html": h, "md": m} {
		for _, want := range []string{
			"unassessed (static-only report)", "No waivers file was supplied", "No scope file was supplied",
			"maximum level is AGR-3", "No crypto modules found", "No model artefacts found",
			"harness failed", "case collision", "(unnamed)", "No open critical or high findings", "failed (no result)", "did not run",
		} {
			if !strings.Contains(doc, want) {
				t.Errorf("%s: missing %q", name, want)
			}
		}
	}
	if !strings.Contains(h, "lvl-unassessed") {
		t.Error("badge class")
	}

	b2 := fixture(t)
	b2.Agents = &evidence.AgentsSection{Manifest: "agents.yaml", Agents: []string{"analyst", "reporter"}, Violations: 2}
	b2.Waivers = &evidence.WaiverResult{SHA256: "x"}
	b2.Egress.Attempts = nil
	b2.Modules[1].Status = evidence.ModuleSkipped
	h, m = render(t, b2)
	for name, doc := range map[string]string{"html": h, "md": m} {
		for _, want := range []string{"INV-01 violations: 2", "analyst", "no waiver applies", "No egress attempts were observed", "skipped (--skip)"} {
			if !strings.Contains(doc, want) {
				t.Errorf("%s: missing %q", name, want)
			}
		}
	}

	b3 := fixture(t)
	b3.AGR = evidence.AGR{Level: evidence.LevelAGR4, SpecVersion: evidence.AGRSpecVersion, ObservedWindowS: 600}
	b3.Crypto.FIPSProviders[0].Configured = true
	h, m = render(t, b3)
	if !strings.Contains(h, "lvl-4") || !strings.Contains(h, "Nothing blocks a higher level") || !strings.Contains(m, "activated by configuration") {
		t.Error("AGR-4 variant")
	}
}

func TestHelpers(t *testing.T) {
	if got := oneLine("  a\r\nb"); got != "a" {
		t.Error(got)
	}
	if got := oneLine(strings.Repeat("x", 300)); len([]rune(got)) != 240 {
		t.Errorf("cap: %d", len([]rune(got)))
	}
	if sizeText(5<<30) != "5.0 GiB" || sizeText(1536) != "1.5 KiB" {
		t.Error(sizeText(5<<30), sizeText(1536))
	}
	if orNone("") != "(none)" {
		t.Error("orNone")
	}
}
