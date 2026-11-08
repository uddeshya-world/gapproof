package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// Rule 1: Gapproof never makes a network call. A grep for "net/http" is
// easy to defeat (net.Dial, net.LookupHost, net.Resolver), so this test
// checks the binary's real import graph instead.
//
//  A. No HTTP/TLS/RPC/SMTP client stack anywhere in the binary.
//  B. Any non-standard-library package that imports a std package reaching
//     "net" must be on netAllowed, with a justification.

const modulePath = "github.com/uddeshya-world/gapproof"

// netAllowed: packages permitted to import (something reaching) "net".
var netAllowed = map[string]string{
	modulePath + "/internal/sinkhole": "listens on the harness's private netns only (spec §3.1); never dials out",
	modulePath + "/internal/harness":  "reserved for container-network plumbing; must not dial",
	"github.com/spf13/pflag":          "imports net only for net.IP/net.IPNet flag value types; no sockets",
}

func forbiddenAlways(p string) bool {
	return p == "net/http" || strings.HasPrefix(p, "net/http/") ||
		p == "crypto/tls" || p == "net/rpc" || strings.HasPrefix(p, "net/rpc/") ||
		p == "net/smtp"
}

type goPkg struct {
	ImportPath string
	Standard   bool
	Imports    []string
	Deps       []string
}

// checkNetworkPolicy returns one violation message per offending import.
func checkNetworkPolicy(pkgs []goPkg) []string {
	byPath := map[string]goPkg{}
	for _, p := range pkgs {
		byPath[p.ImportPath] = p
	}
	reachesNet := func(path string) bool {
		if path == "net" {
			return true
		}
		return slices.Contains(byPath[path].Deps, "net")
	}
	var v []string
	for _, p := range pkgs {
		if forbiddenAlways(p.ImportPath) {
			v = append(v, "binary links "+p.ImportPath+" (no HTTP/TLS/RPC/SMTP client stack allowed)")
		}
		if p.Standard {
			continue
		}
		if _, ok := netAllowed[p.ImportPath]; ok {
			continue
		}
		for _, imp := range p.Imports {
			if _, ok := netAllowed[imp]; ok {
				continue // importing an allowed package is fine; it carries its own justification
			}
			if byPath[imp].Standard && reachesNet(imp) {
				v = append(v, p.ImportPath+" imports "+imp+" which reaches package net; add a justified netAllowed entry or remove it")
			}
		}
	}
	slices.Sort(v)
	return slices.Compact(v)
}

func TestNoNetworkImports(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "-json", ".").Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			t.Fatalf("go list: %v\n%s", err, ee.Stderr)
		}
		t.Fatalf("go list: %v", err)
	}
	var pkgs []goPkg
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p goPkg
		if err := dec.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		pkgs = append(pkgs, p)
	}
	if len(pkgs) < 10 {
		t.Fatalf("suspiciously few packages from go list (%d); is the test running in cmd/gapproof?", len(pkgs))
	}
	for _, msg := range checkNetworkPolicy(pkgs) {
		t.Error(msg)
	}
}

// The checker itself must be tested, or a bug in it would pass silently.
func TestCheckNetworkPolicy(t *testing.T) {
	std := func(path string, deps ...string) goPkg {
		return goPkg{ImportPath: path, Standard: true, Deps: deps}
	}
	base := []goPkg{std("net"), std("os"), std("net/netip"), std("log/syslog", "net")}
	tests := []struct {
		name    string
		pkg     goPkg
		wantSub string // "" = no violation
	}{
		{"clean package", goPkg{ImportPath: modulePath + "/internal/models", Imports: []string{"os", "net/netip"}}, ""},
		{"direct net import", goPkg{ImportPath: modulePath + "/internal/report", Imports: []string{"net"}}, "imports net which reaches"},
		{"transitive net via std", goPkg{ImportPath: modulePath + "/internal/crypto", Imports: []string{"log/syslog"}}, "imports log/syslog"},
		{"third party dialing", goPkg{ImportPath: "example.com/telemetry", Imports: []string{"net"}}, "example.com/telemetry imports net"},
		{"allowed sinkhole", goPkg{ImportPath: modulePath + "/internal/sinkhole", Imports: []string{"net"}}, ""},
		{"importing allowed pkg", goPkg{ImportPath: modulePath + "/cmd/gapproof", Imports: []string{modulePath + "/internal/sinkhole"}}, ""},
		{"http client linked", goPkg{ImportPath: modulePath + "/internal/agents", Imports: []string{"net/http"}}, "binary links net/http"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pkgs := append(slices.Clone(base), tc.pkg)
			if slices.Contains(tc.pkg.Imports, "net/http") {
				// go list -deps would list net/http itself once something imports it.
				pkgs = append(pkgs, std("net/http", "net", "crypto/tls"))
			}
			got := strings.Join(checkNetworkPolicy(pkgs), "\n")
			switch {
			case tc.wantSub == "" && got != "":
				t.Errorf("unexpected violation:\n%s", got)
			case tc.wantSub != "" && !strings.Contains(got, tc.wantSub):
				t.Errorf("want violation containing %q, got:\n%s", tc.wantSub, got)
			}
		})
	}
}
