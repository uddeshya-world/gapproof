package evidence

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// Regenerate with: go test ./internal/evidence -run TestGolden -update
var update = flag.Bool("update", false, "rewrite testdata/golden")

const goldenScope = `scope_version: 1
internal_names: [vectordb, "*.corp.internal"]
internal_cidrs: [10.20.0.0/16]
`

const goldenWaivers = `waivers_version: 1
waivers:
  - rule: CRYPTO-UNVALIDATED-MODULE
    match: { path: "usr/lib/python3.12/site-packages/cryptography/hazmat/bindings/_rust.abi3.so" }
    justification: "Used only for TLS to the in-cluster vector DB; customer terminates TLS at their FIPS proxy."
    owner: "security@vendor.example"
    expires: 2027-03-31
  - rule: CRYPTO-UNKNOWN-MODULE
    match: { path: "usr/lib/x86_64-linux-gnu/libnettle.so.8" }
    justification: "Base image library, not used by the app."
    owner: "security@vendor.example"
    expires: 2026-10-01
  - rule: PH-GRADIO-ANALYTICS
    match: { path: "app/ui.py" }
    justification: "UI removed in this release."
    owner: "security@vendor.example"
    expires: 2027-03-31
`

// goldenBundle is a run with every section populated. reverse feeds every
// input list in the opposite order, which must not change the output.
func goldenBundle(t *testing.T, reverse bool) Bundle {
	t.Helper()
	rev := func(s []EgressAttempt) []EgressAttempt {
		if reverse {
			s = slices.Clone(s)
			slices.Reverse(s)
		}
		return s
	}
	scope, err := ParseScope([]byte(goldenScope))
	if err != nil {
		t.Fatal(err)
	}
	w, err := ParseWaivers([]byte(goldenWaivers))
	if err != nil {
		t.Fatal(err)
	}
	attempts := scope.Mark(rev([]EgressAttempt{
		{Kind: KindDNS, Name: "vectordb", OrigDstIP: "127.0.0.11", Port: 53, ProtoHint: "dns"},
		{Kind: KindTCP, Name: "vectordb", OrigDstIP: "198.18.0.1", Port: 8000, ProtoHint: "http", HTTPHost: "vectordb:8000"},
		{Kind: KindDNS, Name: "us.i.posthog.com", OrigDstIP: "127.0.0.11", Port: 53, ProtoHint: "dns"},
		{Kind: KindTCP, Name: "us.i.posthog.com", OrigDstIP: "198.18.0.2", Port: 443, ProtoHint: "tls", SNI: "us.i.posthog.com", ALPN: []string{"http/1.1"}},
		{Kind: KindUDP, OrigDstIP: "8.8.8.8", Port: 53, ProtoHint: "dns", Name: "huggingface.co"},
		{Kind: KindTCP, Name: "us.i.posthog.com", OrigDstIP: "198.18.0.2", Port: 443, ProtoHint: "tls", SNI: "us.i.posthog.com", ALPN: []string{"h2"}},
	}), "rag-app")
	raw := append(EgressFindings(attempts),
		Finding{Rule: "PH-CHROMA-TELEMETRY", Severity: High, Title: "ChromaDB anonymized telemetry is on",
			Explanation: "chromadb sends anonymized telemetry by default.", Fix: "Set ANONYMIZED_TELEMETRY=False in the image environment.",
			Evidence: Evidence{Path: "usr/lib/python3.12/site-packages/chromadb-0.5.0.dist-info/METADATA", SHA256: strings.Repeat("a", 64)},
			Controls: []string{"CM-7", "SC-7"}},
		Finding{Rule: "CRYPTO-UNVALIDATED-MODULE", Severity: High, Title: "Bundled OpenSSL 3.4.1 (cryptography wheel)",
			Explanation: "Copies bundled in wheels are always unvalidated.", Fix: "Build cryptography against a FIPS-enabled system OpenSSL.",
			Evidence: Evidence{Path: "usr/lib/python3.12/site-packages/cryptography/hazmat/bindings/_rust.abi3.so", SHA256: strings.Repeat("b", 64), Detail: "OpenSSL 3.4.1 11 Feb 2025"},
			Controls: []string{"SC-12", "SC-13"}},
		Finding{Rule: "CRYPTO-UNKNOWN-MODULE", Severity: High, Title: "nettle 3.9 <script>alert(1)</script>",
			Explanation: "Vendor builds may be validated.", Fix: "Remove nettle or document its status.",
			Evidence: Evidence{Path: "usr/lib/x86_64-linux-gnu/libnettle.so.8", SHA256: strings.Repeat("c", 64)},
			Controls: []string{"SC-13"}},
		Finding{Rule: "CRYPTO-WEAK-HASH", Severity: Medium, Title: "hashlib.md5 without usedforsecurity=False",
			Explanation: "MD5 is not an approved hash.", Fix: "Use hashlib.sha256 or pass usedforsecurity=False.",
			Evidence: Evidence{Path: "app/cache.py", SHA256: strings.Repeat("d", 64), Offset: Off(120), Detail: "hashlib.md5("},
			Controls: []string{"SC-13"}},
		Finding{Rule: "MODEL-PICKLE-CODE-EXEC", Severity: Critical, Title: "Pickle imports builtins.print",
			Explanation: "Loading this file runs code.", Fix: "Convert the model to safetensors.",
			Evidence: Evidence{Path: "models/reranker.pt", Member: "reranker/data.pkl", SHA256: strings.Repeat("e", 64), Offset: Off(42), Detail: "STACK_GLOBAL builtins.print"},
			Controls: []string{"SI-3", "SI-7"}},
	)
	if reverse {
		slices.Reverse(raw)
	}
	fs, wr, err := Finalize(raw, w, time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	modules := []ModuleStatus{
		{Name: ModAgents, Status: ModuleRan},
		{Name: ModModels, Status: ModuleRan},
		{Name: ModCrypto, Status: ModuleRan},
		{Name: ModPhoneHome, Status: ModuleRan},
		{Name: ModEgress, Status: ModuleRan},
	}
	if !reverse {
		slices.Reverse(modules)
	}
	b := Bundle{
		ToolVersion: "0.1.0-test", RulePackVersion: "2026.11.09", CMVPSnapshotDate: "2026-11-01",
		Target: Target{Image: "leaky-rag.tar", ConfigDigest: "sha256:" + strings.Repeat("1", 64),
			ArtifactDigest: "sha256:" + strings.Repeat("2", 64), Hostname: "rag-app"},
		Modules: modules, Scope: scope, Waivers: wr,
		Egress: &EgressSection{TargetStarted: true, WorkloadPassed: true, ObservedWindowS: 180, Attempts: attempts},
		Crypto: &CryptoSection{SnapshotDate: "2026-11-01",
			Modules: []CryptoModule{
				{Path: "usr/lib/x86_64-linux-gnu/libnettle.so.8", SHA256: strings.Repeat("c", 64), Library: "nettle", Version: "3.9", Origin: "system", Status: "unknown"},
				{Path: "usr/lib/python3.12/site-packages/cryptography/hazmat/bindings/_rust.abi3.so", SHA256: strings.Repeat("b", 64), Library: "openssl", Version: "3.4.1", Origin: "python-wheel", Package: "cryptography", Status: "unvalidated"},
			},
			FIPSProviders: []FIPSProvider{}},
		Models: &ModelsSection{Artifacts: []ModelArtifact{
			{Path: "models/reranker.pt", Format: "pytorch-zip", Size: 1024, SHA256: strings.Repeat("e", 64), Imports: []string{"builtins.print"}},
			{Path: "models/embed.safetensors", Format: "safetensors", Size: 2048, SHA256: strings.Repeat("f", 64), Tensors: 3, DTypes: []string{"F32"}, Metadata: map[string]string{"z": "1", "a": "2"}},
		}},
		Agents:   &AgentsSection{Manifest: "agents.yaml", ManifestSHA256: strings.Repeat("9", 64), DeclaredNoAgents: true},
		Findings: fs,
		Warnings: []string{"z warning", "a warning", "z warning"},
		Run: RunMeta{ID: "run-0001", RunDate: "2026-11-09",
			StartedAt:  time.Date(2026, 11, 9, 12, 0, 0, 0, time.FixedZone("IST", 19800)),
			FinishedAt: time.Date(2026, 11, 9, 12, 3, 30, 0, time.UTC)},
	}
	if reverse {
		b.Crypto.Modules = slices.Clone(b.Crypto.Modules)
		slices.Reverse(b.Crypto.Modules)
		slices.Reverse(b.Models.Artifacts)
	}
	b.AGR = Compute(b.AGRInput())
	return b
}

func TestGolden(t *testing.T) {
	dir := t.TempDir()
	if err := WriteEvidence(dir, goldenBundle(t, false)); err != nil {
		t.Fatal(err)
	}
	dir2 := t.TempDir()
	if err := WriteEvidence(dir2, goldenBundle(t, true)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{EvidenceFile, SummaryFile} {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		got2, _ := os.ReadFile(filepath.Join(dir2, name))
		if !bytes.Equal(got, got2) {
			t.Errorf("%s depends on input order", name)
		}
		golden := filepath.Join("testdata", "golden", name)
		if *update {
			if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(golden, got, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatalf("%v (run with -update)", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs from %s; run with -update and review the diff", name, golden)
		}
	}
	ev, _ := os.ReadFile(filepath.Join(dir, EvidenceFile))
	for _, bad := range []string{"started_at", "2026-11-09T", "run-0001"} {
		if bytes.Contains(ev, []byte(bad)) {
			t.Errorf("evidence.json contains run metadata %q (rule 6)", bad)
		}
	}
	if !bytes.HasSuffix(ev, []byte("}\n")) || !bytes.Contains(ev, []byte("\n  \"agr\": {")) {
		t.Error("expected 2-space indent and a trailing newline")
	}
}

func TestGoldenLevel(t *testing.T) {
	b := goldenBundle(t, false)
	if b.AGR.Level != LevelAGR1 {
		t.Fatalf("level %s", b.AGR.Level)
	}
	if len(b.AGR.Blocking) != 1 || b.AGR.Blocking[0].Reason != "3 out-of-scope egress attempts" {
		t.Errorf("blocking %+v", b.AGR.Blocking)
	}
	s := b.Summarize()
	if c := s.Counts[ModEgress]; *c.Attempts != 5 || *c.OutOfScope != 3 || c.Open != 3 {
		t.Errorf("egress counts %+v attempts=%d", c, *c.Attempts)
	}
	if c := s.Counts[ModCrypto]; c.Findings != 3 || c.Waived != 1 || c.OpenBySeverity["high"] != 1 || c.OpenBySeverity["medium"] != 1 {
		t.Errorf("crypto counts %+v", c)
	}
	if s.Run.StartedAt.Location() != time.UTC {
		t.Error("timestamps are written in UTC")
	}
}

func TestLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := WriteEvidence(dir, goldenBundle(t, false)); err != nil {
		t.Fatal(err)
	}
	ev, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Run.ID != "run-0001" || ev.Scope == nil || len(ev.Scope.InternalCIDRs) != 1 || ev.Waivers == nil || len(ev.Waivers.Applied) != 1 {
		t.Fatalf("loaded %+v", ev)
	}
	dir2 := t.TempDir()
	if err := WriteEvidence(dir2, *ev); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{EvidenceFile, SummaryFile} {
		a, _ := os.ReadFile(filepath.Join(dir, name))
		b, _ := os.ReadFile(filepath.Join(dir2, name))
		if !bytes.Equal(a, b) {
			t.Errorf("%s changes on load + write", name)
		}
	}
	if got := Compute(ev.AGRInput()); got.Level != ev.AGR.Level {
		t.Errorf("recomputed level %s, stored %s", got.Level, ev.AGR.Level)
	}
}

func TestLoadErrors(t *testing.T) {
	write := func(t *testing.T, ev, sum string) string {
		dir := t.TempDir()
		if ev != "" {
			os.WriteFile(filepath.Join(dir, EvidenceFile), []byte(ev), 0o644)
		}
		if sum != "" {
			os.WriteFile(filepath.Join(dir, SummaryFile), []byte(sum), 0o644)
		}
		return dir
	}
	ok := `{"schema_version":"` + SchemaVersion + `","agr":{"level":"AGR-1"}}`
	tests := []struct{ name, ev, sum, want string }{
		{"missing", "", "", "no such file"},
		{"unknown field", `{"schema_version":"x","bogus":1}`, ok, "unknown field"},
		{"evidence schema", `{"schema_version":"other"}`, ok, "schema"},
		{"no summary", ok, "", "no such file"},
		{"summary schema", ok, `{"schema_version":"other"}`, "schema"},
		{"level mismatch", ok, `{"schema_version":"` + SchemaVersion + `","agr":{"level":"AGR-4"}}`, "says AGR-4"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(write(t, tt.ev, tt.sum))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
	if _, err := Load(write(t, ok, ok)); err != nil {
		t.Errorf("minimal: %v", err)
	}
}

func TestFormatWindowAndLabel(t *testing.T) {
	for in, want := range map[int64]string{0: "0s", 45: "45s", 90: "1m30s", 180: "3m", 600: "10m", 3600: "1h", 3725: "1h2m5s"} {
		if got := FormatWindow(in); got != want {
			t.Errorf("FormatWindow(%d) = %s, want %s", in, got, want)
		}
	}
	if got := (AGR{Level: LevelUnassessed}).LevelLabel(); got != "unassessed (static-only report)" {
		t.Error(got)
	}
	if got := (AGR{Level: LevelAGR2, ObservedWindowS: 600}).LevelLabel(); got != "AGR-2 (observed 10m)" {
		t.Error(got)
	}
}

func TestModelsAllHashed(t *testing.T) {
	var none *ModelsSection
	if none.AllHashed() {
		t.Error("no models section: not hashed")
	}
	if !(&ModelsSection{}).AllHashed() {
		t.Error("no artefacts: vacuously hashed")
	}
	if (&ModelsSection{Artifacts: []ModelArtifact{{Path: "m", SHA256: "short"}}}).AllHashed() {
		t.Error("bad hash")
	}
	b := Bundle{}
	if b.ModuleState(ModAgents) != ModuleNotRun {
		t.Error("unrecorded module")
	}
}
