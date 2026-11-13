package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/uddeshya-world/gapproof/internal/evidence"
)

var updateDemoWaivers = flag.Bool("update-demo-waivers", false, "regenerate demo/fixed-rag/gapproof.waivers.amd64.yaml from the arm64 file")

// The fixed-rag waivers match exact paths (D-019), and those paths carry
// the target triple, so each arch needs its own file. The arm64 file is the
// source: it was checked against a real arm64 scan. The amd64 file is
// generated from it by the substitutions below and must stay byte-identical
// to that output (D-038).
//
//	go test ./cmd/gapproof -run TestDemoWaiversAmd64 -update-demo-waivers
var amd64Subst = strings.NewReplacer(
	"aarch64-linux-gnu", "x86_64-linux-gnu", // Debian multiarch dir and CPython EXT_SUFFIX
	"linux/arm64", "linux/amd64",
)

const amd64Header = "# GENERATED from gapproof.waivers.arm64.yaml by TestDemoWaiversAmd64 (D-038); do not edit.\n" +
	"# Regenerate: go test ./cmd/gapproof -run TestDemoWaiversAmd64 -update-demo-waivers\n"

func deriveAmd64Waivers(arm64 []byte) []byte {
	return append([]byte(amd64Header), amd64Subst.Replace(string(arm64))...)
}

func TestDemoWaiversAmd64(t *testing.T) {
	dir := filepath.Join("..", "..", "demo", "fixed-rag")
	armPath, amdPath := filepath.Join(dir, "gapproof.waivers.arm64.yaml"), filepath.Join(dir, "gapproof.waivers.amd64.yaml")
	arm, err := os.ReadFile(armPath)
	if err != nil {
		t.Fatal(err)
	}
	want := deriveAmd64Waivers(arm)
	if *updateDemoWaivers {
		if err := os.WriteFile(amdPath, want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(amdPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is not the generated form of %s; edit the arm64 file and rerun with -update-demo-waivers", amdPath, armPath)
	}

	// Nothing arm-specific may survive the substitution, outside the header.
	body := strings.TrimPrefix(string(got), amd64Header)
	for _, tok := range []string{"aarch64", "arm64", "armv8"} {
		if strings.Contains(body, tok) {
			t.Errorf("generated amd64 waivers still mention %q: add a substitution", tok)
		}
	}

	// Both parse, and they're the same waivers apart from the triple.
	wa, err := evidence.ParseWaivers(arm)
	if err != nil {
		t.Fatalf("arm64: %v", err)
	}
	wd, err := evidence.ParseWaivers(got)
	if err != nil {
		t.Fatalf("amd64: %v", err)
	}
	if len(wa.Waivers) == 0 || len(wa.Waivers) != len(wd.Waivers) {
		t.Fatalf("waiver counts: arm64 %d, amd64 %d", len(wa.Waivers), len(wd.Waivers))
	}
	var paths []string
	for i, a := range wa.Waivers {
		d := wd.Waivers[i]
		if a.Rule != d.Rule || a.Justification != d.Justification || a.Owner != d.Owner || a.Expires != d.Expires ||
			amd64Subst.Replace(a.Match.Path) != d.Match.Path || amd64Subst.Replace(a.Match.Member) != d.Match.Member ||
			amd64Subst.Replace(a.Match.Detail) != d.Match.Detail {
			t.Errorf("waiver %d differs beyond the triple:\n arm64 %+v\n amd64 %+v", i+1, a, d)
		}
		paths = append(paths, d.Match.Path)
	}
	// The amd64 paths, checked by hand against the pinned linux/amd64
	// python:3.12-slim layers and the x86_64 wheels pinned in
	// requirements.txt (D-038). A change here needs that check again.
	verified := []string{
		"usr/lib/x86_64-linux-gnu/libcrypto.so.3",
		"usr/lib/x86_64-linux-gnu/libnettle.so.8.10",
		"usr/local/lib/python3.12/site-packages/cryptography/hazmat/bindings/_rust.abi3.so",
	}
	slices.Sort(paths)
	if !slices.Equal(paths, verified) {
		t.Errorf("amd64 waiver paths changed:\n got  %q\n verified %q\nre-verify them against the amd64 image (D-038) and update this list", paths, verified)
	}
}
