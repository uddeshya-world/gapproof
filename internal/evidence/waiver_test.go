package evidence

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

var runDate = time.Date(2026, 11, 9, 15, 0, 0, 0, time.UTC)

const waiverHead = "waivers_version: 1\nwaivers:\n"

func waiverYAML(rule, match, expires string) string {
	return "  - rule: " + rule + "\n    match: " + match + "\n    justification: accepted in writing\n    owner: sec@vendor.example\n    expires: " + expires + "\n"
}

func TestParseWaiversErrors(t *testing.T) {
	tests := []struct{ name, body, want string }{
		{"unwaivable egress", waiverYAML(RuleEgressAttempt, "{detail: x}", "2027-01-01"), "can't be waived"},
		{"unwaivable pickle", waiverYAML("MODEL-PICKLE-CODE-EXEC", "{path: m.pt}", "2027-01-01"), "can't be waived"},
		{"unwaivable remote code", waiverYAML("MODEL-REMOTE-CODE", "{path: config.json}", "2027-01-01"), "can't be waived"},
		{"unwaivable INV-01", waiverYAML("AGENT-INV01-READ-TO-SINK", "{detail: x}", "2027-01-01"), "can't be waived"},
		{"no rule", waiverYAML(`""`, "{path: a}", "2027-01-01"), "rule is required"},
		{"empty match", waiverYAML("PH-X", "{}", "2027-01-01"), "at least one of"},
		{"bad date", waiverYAML("PH-X", "{path: a}", "2027-02-30"), "YYYY-MM-DD"},
		{"bad date format", waiverYAML("PH-X", "{path: a}", "31/03/2027"), "YYYY-MM-DD"},
		{"unknown match key", waiverYAML("PH-X", "{file: a}", "2027-01-01"), "not found"},
		{"duplicate", waiverYAML("PH-X", "{path: a}", "2027-01-01") + waiverYAML("PH-X", "{path: a}", "2028-01-01"), "identical"},
		{"no justification", "  - rule: PH-X\n    match: {path: a}\n    owner: o\n    expires: 2027-01-01\n", "justification is required"},
		{"no owner", "  - rule: PH-X\n    match: {path: a}\n    justification: j\n    expires: 2027-01-01\n", "owner is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseWaivers([]byte(waiverHead + tt.body))
			if err == nil || !isUsage(err) || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want UsageError containing %q", err, tt.want)
			}
		})
	}
	if _, err := ParseWaivers([]byte("waivers_version: 2\n")); !isUsage(err) {
		t.Errorf("version: %v", err)
	}
	if _, err := LoadWaivers(filepath.Join(t.TempDir(), "nope.yaml")); !isUsage(err) {
		t.Errorf("missing: %v", err)
	}
}

func findingsFixture() []Finding {
	return []Finding{
		{Rule: "CRYPTO-UNVALIDATED-MODULE", Severity: High, Title: "bundled OpenSSL", Evidence: Evidence{Path: "site-packages/cryptography/_rust.abi3.so"}},
		{Rule: "CRYPTO-UNVALIDATED-MODULE", Severity: High, Title: "system OpenSSL", Evidence: Evidence{Path: "usr/lib/libcrypto.so.3"}},
		{Rule: "PH-SENTRY-DSN", Severity: High, Title: "sentry", Evidence: Evidence{Path: "app/main.py", Detail: "line 3"}},
		{Rule: "PH-SENTRY-DSN", Severity: High, Title: "sentry", Evidence: Evidence{Path: "app/main.py", Detail: "line 9"}},
		{Rule: "MODEL-PARSE-FAILED", Severity: High, Title: "zip", Evidence: Evidence{Path: "models/a.pt", Member: "a/data.pkl"}},
	}
}

func TestFinalizeWaivers(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "gapproof.waivers.yaml")
	body := waiverHead +
		waiverYAML("CRYPTO-UNVALIDATED-MODULE", `{path: "site-packages/cryptography/_rust.abi3.so"}`, "2026-11-09") + // valid through the run date
		waiverYAML("CRYPTO-UNVALIDATED-MODULE", `{path: "usr/lib/libcrypto.so.3"}`, "2026-11-08") + // expired
		waiverYAML("PH-SENTRY-DSN", `{path: app/main.py, detail: "line 9"}`, "2027-01-01") +
		waiverYAML("PH-GRADIO-ANALYTICS", `{path: app/ui.py}`, "2027-01-01") + // stale
		waiverYAML("MODEL-PARSE-FAILED", `{member: a/data.pkl}`, "2027-01-01")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	w, err := LoadWaivers(p)
	if err != nil {
		t.Fatal(err)
	}
	in := findingsFixture()
	fs, res, err := Finalize(in, w, runDate)
	if err != nil {
		t.Fatal(err)
	}
	if in[0].Status != "" || in[0].ID != "" {
		t.Error("Finalize must not modify its input")
	}
	byTitle := map[string]Finding{}
	for _, f := range fs {
		byTitle[f.Title+f.Evidence.Detail] = f
	}
	wantStatus := map[string]Status{
		"bundled OpenSSL": StatusWaived, "system OpenSSL": StatusOpen,
		"sentryline 3": StatusOpen, "sentryline 9": StatusWaived, "zip": StatusWaived,
	}
	for k, st := range wantStatus {
		f := byTitle[k]
		if f.Status != st {
			t.Errorf("%s: status %s, want %s", k, f.Status, st)
		}
		if (f.Waiver != nil) != (st == StatusWaived) {
			t.Errorf("%s: waiver ref %+v", k, f.Waiver)
		}
	}
	if len(fs) != len(in) {
		t.Fatal("waived findings must never be deleted")
	}
	if got := byTitle["sentryline 9"].Waiver; got.Index != 3 || got.Owner != "sec@vendor.example" || got.Expires != "2027-01-01" {
		t.Errorf("waiver ref %+v", got)
	}
	if len(res.Applied) != 3 || len(res.Stale) != 1 || len(res.Expired) != 1 || res.SHA256 != sha256Hex([]byte(body)) {
		t.Fatalf("result %+v", res)
	}
	if res.Stale[0].Rule != "PH-GRADIO-ANALYTICS" || res.Expired[0].Index != 2 {
		t.Errorf("stale/expired %+v %+v", res.Stale, res.Expired)
	}
	warn := res.Warnings()
	if len(warn) != 2 || !strings.Contains(warn[0], "expired on 2026-11-08") || !strings.Contains(warn[1], "is stale") {
		t.Errorf("warnings %q", warn)
	}
	// IDs follow module order, then path.
	var ids []string
	for _, f := range fs {
		ids = append(ids, f.ID+" "+f.Rule)
	}
	want := []string{"PH-0001 PH-SENTRY-DSN", "PH-0002 PH-SENTRY-DSN", "CR-0001 CRYPTO-UNVALIDATED-MODULE", "CR-0002 CRYPTO-UNVALIDATED-MODULE", "MD-0001 MODEL-PARSE-FAILED"}
	if !slices.Equal(ids, want) {
		t.Errorf("ids %q", ids)
	}
	if res.Applied[0].FindingID != "CR-0001" {
		t.Errorf("applied %+v", res.Applied[0])
	}
}

func TestFinalizeWaiverConflicts(t *testing.T) {
	multi, err := ParseWaivers([]byte(waiverHead + waiverYAML("PH-SENTRY-DSN", "{path: app/main.py}", "2027-01-01")))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Finalize(findingsFixture(), multi, runDate); !isUsage(err) || !strings.Contains(err.Error(), "matches 2 findings (PH-0001, PH-0002)") {
		t.Errorf("multiple match: %v", err)
	}
	// An expired waiver is held to the same exactly-one rule (review P1).
	expMulti, err := ParseWaivers([]byte(waiverHead + waiverYAML("PH-SENTRY-DSN", "{path: app/main.py}", "2026-01-01")))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Finalize(findingsFixture(), expMulti, runDate); !isUsage(err) || !strings.Contains(err.Error(), "matches 2 findings") {
		t.Errorf("expired multiple match: %v", err)
	}
	overlap, err := ParseWaivers([]byte(waiverHead +
		waiverYAML("PH-SENTRY-DSN", `{detail: "line 3"}`, "2027-01-01") +
		waiverYAML("PH-SENTRY-DSN", `{path: app/main.py, detail: "line 3"}`, "2027-01-01")))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Finalize(findingsFixture(), overlap, runDate); !isUsage(err) || !strings.Contains(err.Error(), "both match finding PH-0001") {
		t.Errorf("overlap: %v", err)
	}
	if _, _, err := Finalize(findingsFixture(), overlap, time.Time{}); err == nil {
		t.Error("zero run date must fail")
	}
	fs, res, err := Finalize(findingsFixture(), nil, time.Time{})
	if err != nil || res != nil || fs[0].Status != StatusOpen {
		t.Errorf("no waivers: %v %+v", err, res)
	}
	if (*WaiverResult)(nil).Warnings() != nil {
		t.Error("nil result has no warnings")
	}
}

func TestEgressFindingsAndDedupe(t *testing.T) {
	in := []EgressAttempt{
		{Kind: KindTCP, Name: "api.example.com", OrigDstIP: "198.18.0.2", Port: 443, ProtoHint: "unknown", SNI: "api.example.com", ALPN: []string{"http/1.1"}},
		{Kind: KindTCP, Name: "api.example.com", OrigDstIP: "198.18.0.2", Port: 443, ProtoHint: "tls", SNI: "api.example.com", ALPN: []string{"h2", "http/1.1"}},
		{Kind: KindDNS, Name: "api.example.com", OrigDstIP: "127.0.0.11", Port: 53, ProtoHint: "dns"},
		{Kind: KindDNS, Name: "db", InScope: true},
		{Kind: KindUDP, OrigDstIP: "8.8.8.8", Port: 123, ProtoHint: "ntp"},
		{Kind: KindICMP, OrigDstIP: "1.1.1.1"},
		{Kind: KindTCP, Name: "weird name\n<x>", Port: 80, HTTPHost: "a b"},
		{Kind: KindDNS, Name: "db", InScope: false}, // same key, one copy out of scope: fail closed
		{Kind: KindIP},
	}
	set := DedupeAttempts(in)
	if len(set) != 7 {
		t.Fatalf("set has %d entries: %+v", len(set), set)
	}
	for i := 1; i < len(set); i++ {
		if compareAttempts(set[i-1], set[i]) >= 0 {
			t.Fatal("set not sorted")
		}
	}
	tcp := set[slices.IndexFunc(set, func(a EgressAttempt) bool { return a.Kind == KindTCP && a.Port == 443 })]
	if tcp.ProtoHint != "tls" || !slices.Equal(tcp.ALPN, []string{"h2", "http/1.1"}) {
		t.Errorf("merge: %+v", tcp)
	}
	if db := set[slices.IndexFunc(set, func(a EgressAttempt) bool { return a.Name == "db" })]; db.InScope {
		t.Error("merged entry must be out of scope if any copy was")
	}
	if betterHint("", "unknown") != "unknown" || betterHint("tls", "http") != "http" || betterHint("tls", "") != "tls" {
		t.Error("betterHint")
	}
	fs := EgressFindings(in)
	if len(fs) != 7 {
		t.Fatalf("got %d findings", len(fs))
	}
	var titles, details []string
	for _, f := range fs {
		if f.Rule != RuleEgressAttempt || f.Severity != High || !slices.Equal(f.Controls, []string{"SC-7", "AC-4"}) || Waivable(f.Rule) {
			t.Errorf("finding shape %+v", f)
		}
		titles = append(titles, f.Title)
		details = append(details, f.Evidence.Detail)
	}
	wantDetails := []string{
		"kind=dns name=api.example.com ip=127.0.0.11 port=53 proto=dns",
		"kind=dns name=db",
		"kind=icmp ip=1.1.1.1",
		"kind=ip",
		"kind=tcp name=api.example.com ip=198.18.0.2 port=443 proto=tls sni=api.example.com alpn=h2,http/1.1",
		`kind=tcp name="weird name\n<x>" port=80 host="a b"`,
		"kind=udp ip=8.8.8.8 port=123 proto=ntp",
	}
	if !slices.Equal(details, wantDetails) {
		t.Errorf("details:\n%s", strings.Join(details, "\n"))
	}
	wantTitles := []string{
		"Out-of-scope egress attempt: dns api.example.com",
		"Out-of-scope egress attempt: dns db",
		"Out-of-scope egress attempt: icmp 1.1.1.1",
		"Out-of-scope egress attempt: ip (unknown destination)",
		"Out-of-scope egress attempt: tcp api.example.com (198.18.0.2):443",
		"Out-of-scope egress attempt: tcp weird name\n<x>:80",
		"Out-of-scope egress attempt: udp 8.8.8.8:123",
	}
	if !slices.Equal(titles, wantTitles) {
		t.Errorf("titles:\n%s", strings.Join(titles, "\n"))
	}
	if d := (EgressAttempt{Kind: KindTCP, SNI: "s.example", Port: 443}).Destination(); d != "tcp s.example:443" {
		t.Error(d)
	}
	if d := (EgressAttempt{Kind: KindTCP, HTTPHost: "h.example:8080", Port: 8080}).Destination(); d != "tcp h.example:8080" {
		t.Error(d)
	}
	if len(DedupeAttempts(nil)) != 0 {
		t.Error("empty set")
	}
}

func TestAssignIDsIgnoresInputOrder(t *testing.T) {
	fs := []Finding{
		{Rule: "AGENT-INV01-READ-TO-SINK", Severity: High, Evidence: Evidence{Detail: "a"}},
		{Rule: "MODEL-PICKLE-CODE-EXEC", Severity: Critical, Evidence: Evidence{Path: "m.pt", Offset: Off(9)}},
		{Rule: "WEIRD-RULE", Severity: Low},
		{Rule: RuleEgressAttempt, Severity: High, Evidence: Evidence{Detail: "kind=dns name=x"}},
		{Rule: "PH-X", Severity: High, Title: "b"},
		{Rule: "PH-X", Severity: High, Title: "a"},
		{Rule: "CRYPTO-WEAK-HASH", Severity: Medium, Evidence: Evidence{Path: "app.py"}},
	}
	want := []string{"EG-0001", "PH-0001", "PH-0002", "CR-0001", "MD-0001", "AG-0001", "OT-0001"}
	for range 5 {
		got := slices.Clone(fs)
		slices.Reverse(fs)
		AssignIDs(got)
		var ids []string
		for _, f := range got {
			ids = append(ids, f.ID)
		}
		if !slices.Equal(ids, want) || got[1].Title != "a" {
			t.Fatalf("ids %q (titles %s,%s)", ids, got[1].Title, got[2].Title)
		}
	}
}

// Regression (demo determinism): a teardown connection seen only by NFLOG
// (no SNI, hint unknown) to an endpoint already seen with full detail must
// not add an entry; whether it happens is a race. Scope stays fail-closed,
// and a bare entry with no detailed twin is kept.
func TestDedupeFoldsBareTeardownFlows(t *testing.T) {
	tls := EgressAttempt{Kind: KindTCP, Name: "o0.ingest.sentry.io", OrigDstIP: "198.18.0.2", Port: 443, ProtoHint: "tls", SNI: "o0.ingest.sentry.io", InScope: true}
	bare := EgressAttempt{Kind: KindTCP, Name: "o0.ingest.sentry.io", OrigDstIP: "198.18.0.2", Port: 443, ProtoHint: "unknown"}
	lone := EgressAttempt{Kind: KindTCP, Name: "x.example", OrigDstIP: "198.18.0.3", Port: 443, ProtoHint: "unknown"}
	with := DedupeAttempts([]EgressAttempt{tls, bare, lone})
	without := DedupeAttempts([]EgressAttempt{tls, lone})
	if len(with) != 2 || with[0].SNI != "o0.ingest.sentry.io" || with[1].Name != "x.example" {
		t.Fatalf("got %+v", with)
	}
	if with[0].InScope {
		t.Error("folded entry must inherit the bare copy's out-of-scope status")
	}
	without[0].InScope = false
	if !reflect.DeepEqual(with, without) {
		t.Errorf("set depends on the teardown race:\n%+v\n%+v", with, without)
	}
}
