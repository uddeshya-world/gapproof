package evidence

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func isUsage(err error) bool {
	var ue *UsageError
	return errors.As(err, &ue)
}

func TestParseScopeErrors(t *testing.T) {
	tests := []struct{ name, yaml, want string }{
		{"public CIDR", "scope_version: 1\ninternal_cidrs: [8.8.8.0/24]\n", "is not private"},
		{"public v6 CIDR", "scope_version: 1\ninternal_cidrs: [\"2001:db8::/32\"]\n", "is not private"},
		{"too wide", "scope_version: 1\ninternal_cidrs: [10.0.0.0/7]\n", "is not private"},
		{"bad CIDR", "scope_version: 1\ninternal_cidrs: [10.0.0.1]\n", "is not a CIDR"},
		{"unknown key", "scope_version: 1\ninternal_hosts: [db]\n", "not found"},
		{"version", "scope_version: 2\n", "scope_version must be 1"},
		{"empty", "", "is empty"},
		{"two docs", "scope_version: 1\n---\nscope_version: 1\n", "exactly one YAML document"},
		{"mid wildcard", "scope_version: 1\ninternal_names: [\"a.*.b\"]\n", "wildcard"},
		{"bare wildcard", "scope_version: 1\ninternal_names: [\"*.\"]\n", "wildcard"},
		{"bad char", "scope_version: 1\ninternal_names: [\"a b\"]\n", "contains"},
		{"wildcard TLD com", "scope_version: 1\ninternal_names: [\"*.com\"]\n", "too broad"},
		{"wildcard TLD io", "scope_version: 1\ninternal_names: [\"*.IO.\"]\n", "too broad"},
		{"wildcard TLD uk", "scope_version: 1\ninternal_names: [\"*.uk\"]\n", "too broad"},
		{"empty label", "scope_version: 1\ninternal_names: [\"*..corp\"]\n", "empty label"},
		{"not yaml", "scope_version: [\n", "scope file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseScope([]byte(tt.yaml))
			if err == nil || !isUsage(err) || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want UsageError containing %q", err, tt.want)
			}
		})
	}
}

func TestLoadScope(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "gapproof.scope.yaml")
	body := "scope_version: 1\ninternal_names: [Redis, db, \"*.Corp.Internal.\", db]\ninternal_cidrs: [10.20.0.0/16, 100.64.1.7/24, \"fd00::/8\", 192.168.1.0/24, 172.16.0.0/12]\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := LoadScope(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(s.InternalNames, ","); got != "*.corp.internal,db,redis" {
		t.Errorf("names %s", got)
	}
	var cidrs []string
	for _, c := range s.InternalCIDRs {
		cidrs = append(cidrs, c.String())
	}
	if got := strings.Join(cidrs, ","); got != "10.20.0.0/16,100.64.1.0/24,172.16.0.0/12,192.168.1.0/24,fd00::/8" {
		t.Errorf("cidrs %s", got)
	}
	if s.SHA256 != sha256Hex([]byte(body)) || string(s.Raw) != body {
		t.Error("raw bytes and hash must be kept")
	}
	if s.String() != "3 internal names, 5 internal CIDRs" || (*Scope)(nil).String() != "no scope file" {
		t.Error("String")
	}
	if _, err := LoadScope(filepath.Join(dir, "missing.yaml")); !isUsage(err) {
		t.Errorf("missing file: %v", err)
	}
	big := filepath.Join(dir, "big.yaml")
	if err := os.WriteFile(big, make([]byte, maxConfigFile+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadScope(big); !isUsage(err) {
		t.Errorf("oversized file: %v", err)
	}
}

func TestScopeContains(t *testing.T) {
	s, err := ParseScope([]byte("scope_version: 1\ninternal_names: [db, \"*.corp.internal\"]\ninternal_cidrs: [10.20.0.0/16]\n"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		a    EgressAttempt
		want bool
	}{
		{"exact name", EgressAttempt{Kind: KindDNS, Name: "db"}, true},
		{"exact name case and dot", EgressAttempt{Kind: KindDNS, Name: "DB."}, true},
		{"wildcard", EgressAttempt{Kind: KindDNS, Name: "vec.corp.internal"}, true},
		{"wildcard deep", EgressAttempt{Kind: KindDNS, Name: "a.b.corp.internal"}, true},
		{"wildcard excludes apex", EgressAttempt{Kind: KindDNS, Name: "corp.internal"}, false},
		{"wildcard suffix trick", EgressAttempt{Kind: KindDNS, Name: "evilcorp.internal"}, false},
		{"undeclared name", EgressAttempt{Kind: KindDNS, Name: "api.example.com"}, false},
		{"localhost", EgressAttempt{Kind: KindDNS, Name: "localhost"}, true},
		{"target hostname", EgressAttempt{Kind: KindDNS, Name: "App-Host"}, true},
		{"dns via undeclared private resolver", EgressAttempt{Kind: KindDNS, Name: "db", OrigDstIP: "172.17.0.1", Port: 53}, false},
		{"dns via undeclared link-local resolver", EgressAttempt{Kind: KindDNS, Name: "db", OrigDstIP: "169.254.169.254", Port: 53}, false},
		{"dns via declared-CIDR resolver", EgressAttempt{Kind: KindDNS, Name: "db", OrigDstIP: "10.20.0.53", Port: 53}, true},
		{"dns via loopback resolver", EgressAttempt{Kind: KindDNS, Name: "db", OrigDstIP: "127.0.0.11", Port: 53}, true},
		{"dns via public resolver", EgressAttempt{Kind: KindDNS, Name: "db", OrigDstIP: "8.8.8.8", Port: 53}, false},
		{"dns without name", EgressAttempt{Kind: KindDNS, OrigDstIP: "10.20.0.1"}, false},
		{"tcp to synthetic for in-scope name", EgressAttempt{Kind: KindTCP, Name: "db", OrigDstIP: "198.18.0.1", Port: 5432}, true},
		{"tcp to synthetic without name", EgressAttempt{Kind: KindTCP, OrigDstIP: "198.18.0.9", Port: 443}, false},
		{"tcp to declared CIDR", EgressAttempt{Kind: KindTCP, OrigDstIP: "10.20.3.4", Port: 6379}, true},
		{"tcp to undeclared private IP", EgressAttempt{Kind: KindTCP, OrigDstIP: "10.21.0.1", Port: 6379}, false},
		{"tcp to public IP", EgressAttempt{Kind: KindTCP, OrigDstIP: "1.1.1.1", Port: 443}, false},
		{"tcp to loopback", EgressAttempt{Kind: KindTCP, OrigDstIP: "127.0.0.1", Port: 8080}, true},
		{"in-scope IP but foreign SNI", EgressAttempt{Kind: KindTCP, OrigDstIP: "10.20.0.5", Port: 443, SNI: "api.example.com"}, false},
		{"in-scope name but foreign Host", EgressAttempt{Kind: KindTCP, Name: "db", OrigDstIP: "198.18.0.1", Port: 80, HTTPHost: "evil.example:80"}, false},
		{"host with port in scope", EgressAttempt{Kind: KindTCP, OrigDstIP: "10.20.0.5", Port: 80, HTTPHost: "db:80"}, true},
		{"literal loopback host", EgressAttempt{Kind: KindTCP, OrigDstIP: "10.20.0.5", Port: 80, HTTPHost: "[::1]:80"}, true},
		{"literal public host", EgressAttempt{Kind: KindTCP, OrigDstIP: "10.20.0.5", Port: 80, HTTPHost: "1.2.3.4"}, false},
		{"name only", EgressAttempt{Kind: KindTCP, Name: "db", Port: 5432}, true},
		{"nothing at all", EgressAttempt{Kind: KindICMP}, false},
		{"icmp public", EgressAttempt{Kind: KindICMP, OrigDstIP: "8.8.8.8"}, false},
		{"unparseable IP", EgressAttempt{Kind: KindTCP, Name: "db", OrigDstIP: "nope"}, false},
		{"v4-mapped v6 in CIDR", EgressAttempt{Kind: KindUDP, OrigDstIP: "::ffff:10.20.0.1", Port: 8125}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := s.Contains(tt.a, "app-host"); got != tt.want {
				t.Fatalf("Contains(%+v) = %v, want %v", tt.a, got, tt.want)
			}
		})
	}
	var none *Scope
	if !none.Contains(EgressAttempt{Kind: KindDNS, Name: "localhost"}, "") {
		t.Error("localhost is always in scope")
	}
	if !none.Contains(EgressAttempt{Kind: KindDNS, Name: "app"}, "app") {
		t.Error("the target hostname is always in scope")
	}
	if none.Contains(EgressAttempt{Kind: KindDNS, Name: "db"}, "app") || none.Contains(EgressAttempt{Kind: KindTCP, OrigDstIP: "10.20.0.1"}, "") {
		t.Error("no scope file: nothing else is in scope")
	}
	marked := s.Mark([]EgressAttempt{{Kind: KindDNS, Name: "db"}, {Kind: KindDNS, Name: "x.example"}}, "")
	if !marked[0].InScope || marked[1].InScope {
		t.Errorf("Mark: %+v", marked)
	}
}
