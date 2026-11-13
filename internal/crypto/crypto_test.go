package crypto

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/uddeshya-world/gapproof/internal/inventory"
)

// makeELF builds a minimal ELF64 shared object whose .rodata (or .data,
// when rodata is false) holds content. Real libraries embed version strings
// the same way; nothing here is ever executed.
func makeELF(content string, rodata bool) []byte { return makeELFNeeding(content, rodata, "") }

// makeELFNeeding also adds a .dynamic section with DT_NEEDED=needed.
func makeELFNeeding(content string, rodata bool, needed string) []byte {
	name := ".rodata"
	if !rodata {
		name = ".data\x00\x00"
	}
	shstr := []byte("\x00" + name + "\x00.shstrtab\x00.dynstr\x00.dynamic\x00")
	data := []byte(content)
	dataOff := uint64(64)
	strOff := dataOff + uint64(len(data))
	dynstr := []byte("\x00" + needed + "\x00")
	dynstrOff := strOff + uint64(len(shstr))
	dynOff := (dynstrOff + uint64(len(dynstr)) + 7) &^ 7
	var dyn bytes.Buffer
	binary.Write(&dyn, binary.LittleEndian, []uint64{1, 1, 0, 0}) // DT_NEEDED -> dynstr[1], DT_NULL
	shOff := (dynOff + uint64(dyn.Len()) + 7) &^ 7
	nsec := uint16(3)
	if needed != "" {
		nsec = 5
	}

	var b bytes.Buffer
	le := binary.LittleEndian
	b.Write([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	binary.Write(&b, le, uint16(3))  // ET_DYN
	binary.Write(&b, le, uint16(62)) // x86-64
	binary.Write(&b, le, uint32(1))
	binary.Write(&b, le, uint64(0))  // entry
	binary.Write(&b, le, uint64(0))  // phoff
	binary.Write(&b, le, shOff)      // shoff
	binary.Write(&b, le, uint32(0))  // flags
	binary.Write(&b, le, uint16(64)) // ehsize
	binary.Write(&b, le, uint16(56)) // phentsize
	binary.Write(&b, le, uint16(0))  // phnum
	binary.Write(&b, le, uint16(64)) // shentsize
	binary.Write(&b, le, nsec)       // shnum
	binary.Write(&b, le, uint16(2))  // shstrndx
	b.Write(data)
	b.Write(shstr)
	b.Write(dynstr)
	for uint64(b.Len()) < dynOff {
		b.WriteByte(0)
	}
	b.Write(dyn.Bytes())
	for uint64(b.Len()) < shOff {
		b.WriteByte(0)
	}
	sh := func(nameOff, typ uint32, flags, off, size uint64, link uint32, entsize uint64) {
		binary.Write(&b, le, nameOff)
		binary.Write(&b, le, typ)
		binary.Write(&b, le, flags)
		binary.Write(&b, le, uint64(0)) // addr
		binary.Write(&b, le, off)
		binary.Write(&b, le, size)
		binary.Write(&b, le, link)
		binary.Write(&b, le, uint32(0))
		binary.Write(&b, le, uint64(1))
		binary.Write(&b, le, entsize)
	}
	shstrtab := uint32(1 + len(name) + 1)
	sh(0, 0, 0, 0, 0, 0, 0)
	sh(1, 1, 2, dataOff, uint64(len(data)), 0, 0)
	sh(shstrtab, 3, 0, strOff, uint64(len(shstr)), 0, 0)
	if needed != "" {
		sh(shstrtab+10, 3, 2, dynstrOff, uint64(len(dynstr)), 0, 0)
		sh(shstrtab+18, 6, 2, dynOff, uint64(dyn.Len()), 3, 16) // SHT_DYNAMIC, linked to .dynstr
	}
	return b.Bytes()
}

const sysLib = "usr/lib/x86_64-linux-gnu/"
const site = "usr/local/lib/python3.12/site-packages/"

var configuredCnf = `openssl_conf = openssl_init
.include /usr/local/ssl/fipsmodule.cnf
[openssl_init]
providers = provider_sect
[provider_sect]
fips = fips_sect
base = base_sect
[base_sect]
activate = 1
`

func scan(t *testing.T, files map[string][]byte, exe ...string) *Result {
	t.Helper()
	d := t.TempDir()
	for p, b := range files {
		full := filepath.Join(d, filepath.FromSlash(p))
		os.MkdirAll(filepath.Dir(full), 0o755)
		mode := os.FileMode(0o644)
		for _, e := range exe {
			if e == p {
				mode = 0o755
			}
		}
		if err := os.WriteFile(full, b, mode); err != nil {
			t.Fatal(err)
		}
	}
	root, _ := os.OpenRoot(d)
	defer root.Close()
	inv, err := inventory.Build(context.Background(), root, inventory.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	snap, err := BuiltinSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	res, err := Scan(context.Background(), root, inv, snap, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func module(t *testing.T, r *Result, p string) Module {
	t.Helper()
	for _, m := range r.Modules {
		if m.Path == p {
			return m
		}
	}
	t.Fatalf("no module %s in %+v", p, r.Modules)
	return Module{}
}

func ruleSet(r *Result) map[string][]string {
	out := map[string][]string{}
	for _, f := range r.Findings {
		out[f.Rule] = append(out[f.Rule], f.Evidence.Path)
	}
	return out
}

func TestSystemOpenSSLWithoutProvider(t *testing.T) {
	r := scan(t, map[string][]byte{
		sysLib + "libcrypto.so.3": makeELF("\x00OpenSSL 3.0.13 30 Jan 2024\x00", true),
		sysLib + "libssl.so.3":    makeELF("\x00no version here\x00", true),
	})
	m := module(t, r, sysLib+"libcrypto.so.3")
	if m.Library != "openssl" || m.Version != "3.0.13" || m.Origin != "system" || m.Status != StatusUnvalidated || len(m.SHA256) != 64 {
		t.Errorf("libcrypto: %+v", m)
	}
	if len(r.Modules) != 1 {
		t.Errorf("libssl without its own version string shouldn't be a separate module: %+v", r.Modules)
	}
	if got := ruleSet(r)[RuleUnvalidated]; len(got) != 1 {
		t.Errorf("findings: %v", ruleSet(r))
	}
	if !strings.Contains(r.Findings[0].Evidence.Detail, "CMVP snapshot "+r.SnapshotDate) {
		t.Errorf("finding must state the snapshot date: %s", r.Findings[0].Evidence.Detail)
	}
}

func TestConfiguredValidatedProvider(t *testing.T) {
	r := scan(t, map[string][]byte{
		sysLib + "libcrypto.so.3":       makeELF("OpenSSL 3.0.13 30 Jan 2024", true),
		sysLib + "ossl-modules/fips.so": makeELF("\x00OpenSSL FIPS Provider\x003.1.2\x00", true),
		"usr/lib/ssl/openssl.cnf":       []byte(configuredCnf),
		"etc/ssl/openssl.cnf":           []byte("# fips = fips_sect\n.include x\n"), // commented out: doesn't count
	})
	prov := module(t, r, sysLib+"ossl-modules/fips.so")
	if prov.Version != "3.1.2" || prov.Status != StatusValidated || prov.Certificate != "4985" {
		t.Errorf("provider: %+v", prov)
	}
	lib := module(t, r, sysLib+"libcrypto.so.3")
	if lib.Status != StatusValidated || lib.Certificate != "4985" || !strings.Contains(lib.Note, "via configured FIPS provider") {
		t.Errorf("libcrypto via provider: %+v", lib)
	}
	if len(r.Findings) != 0 || len(r.Configs) != 1 || !r.FIPSProviders[0].Configured {
		t.Errorf("want a clean result, got findings %v configs %v providers %+v", ruleSet(r), r.Configs, r.FIPSProviders)
	}
}

func TestHistoricalAndUnconfiguredProviders(t *testing.T) {
	r := scan(t, map[string][]byte{
		sysLib + "libcrypto.so.3":       makeELF("OpenSSL 3.0.9 30 May 2023", true),
		sysLib + "ossl-modules/fips.so": makeELF("OpenSSL 3.0.9 30 May 2023", true),
		"etc/ssl/openssl.cnf":           []byte(configuredCnf),
	})
	if p := module(t, r, sysLib+"ossl-modules/fips.so"); p.Status != StatusUnvalidated || !strings.Contains(p.Note, "historical") {
		t.Errorf("3.0.9 provider must not count as validated after its 2026-09-21 sunset: %+v", p)
	}
	if l := module(t, r, sysLib+"libcrypto.so.3"); l.Status != StatusUnvalidated {
		t.Errorf("libcrypto: %+v", l)
	}

	r = scan(t, map[string][]byte{sysLib + "ossl-modules/fips.so": makeELF("\x003.1.2\x00", true)})
	if got := ruleSet(r)[RuleProviderOff]; len(got) != 1 {
		t.Errorf("unconfigured provider: %v", ruleSet(r))
	}
}

// The review's P1 #5: the cryptography wheel links OpenSSL statically into
// its Rust extension, with no libssl file to find.
func TestBundledCopies(t *testing.T) {
	r := scan(t, map[string][]byte{
		site + "cryptography/hazmat/bindings/_rust.abi3.so":          makeELF("x\x00OpenSSL 3.3.2 3 Sep 2024\x00y", true),
		site + "psycopg2_binary.libs/libcrypto-de3a0bd1.so.3":        makeELF("OpenSSL 3.1.4 24 Oct 2023", true),
		site + "grpc/_cython/cygrpc.cpython-312-x86_64-linux-gnu.so": makeELF("BoringSSL", true),
		site + "numpy/core/_multiarray_umath.cpython-312.so":         makeELF("no crypto in here", true),
		"app/node_modules/keytar/build/keytar.node":                  makeELF("LibreSSL 3.8.2", true),
	})
	rust := module(t, r, site+"cryptography/hazmat/bindings/_rust.abi3.so")
	if rust.Library != "openssl" || rust.Version != "3.3.2" || rust.Origin != "python-wheel" || rust.Package != "cryptography" || rust.Status != StatusUnvalidated || !strings.Contains(rust.Note, "statically bundled") {
		t.Errorf("cryptography wheel: %+v", rust)
	}
	if m := module(t, r, site+"psycopg2_binary.libs/libcrypto-de3a0bd1.so.3"); m.Package != "psycopg2_binary" {
		t.Errorf(".libs attribution: %+v", m)
	}
	if m := module(t, r, site+"grpc/_cython/cygrpc.cpython-312-x86_64-linux-gnu.so"); m.Library != "boringssl" || m.Status != StatusUnvalidated {
		t.Errorf("boringssl: %+v", m)
	}
	if m := module(t, r, "app/node_modules/keytar/build/keytar.node"); m.Library != "libressl" || m.Origin != "node-module" || m.Package != "keytar" {
		t.Errorf("libressl node addon: %+v", m)
	}
	if len(r.Modules) != 4 {
		t.Errorf("a .so without crypto markers isn't a module: %+v", r.Modules)
	}
}

func TestOtherLibrariesAreUnknown(t *testing.T) {
	r := scan(t, map[string][]byte{
		sysLib + "libgnutls.so.30":    makeELF("gnutls", true),
		sysLib + "libnss3.so":         makeELF("NSS 3.98", true),
		sysLib + "libgcrypt.so.20":    makeELF("x", true),
		sysLib + "libmbedcrypto.so.7": makeELF("mbed TLS 3.5.2", true),
		sysLib + "libwolfssl.so.42":   makeELF("x", true),
		sysLib + "libnettle.so.8":     makeELF("x", true),
		sysLib + "libcrypto.so.1.1":   makeELF("no version", false), // no .rodata: whole file scanned
	})
	if m := module(t, r, sysLib+"libnss3.so"); m.Library != "nss" || m.Version != "3.98" || m.Status != StatusUnknown {
		t.Errorf("nss: %+v", m)
	}
	if m := module(t, r, sysLib+"libmbedcrypto.so.7"); m.Version != "3.5.2" {
		t.Errorf("mbedtls: %+v", m)
	}
	if got := ruleSet(r)[RuleUnknown]; len(got) != 6 {
		t.Errorf("want 6 unknown-status findings, got %v", ruleSet(r))
	}
	if m := module(t, r, sysLib+"libcrypto.so.1.1"); m.Library != "openssl" || m.Version != "" || m.Status != StatusUnvalidated {
		t.Errorf("libcrypto without a version: %+v", m)
	}
}

func TestNoRodataStillScanned(t *testing.T) {
	r := scan(t, map[string][]byte{"opt/app/libcrypto.so.3": makeELF("OpenSSL 3.2.1 30 Jan 2024", false)})
	if m := module(t, r, "opt/app/libcrypto.so.3"); m.Version != "3.2.1" {
		t.Errorf("fallback scan: %+v", m)
	}
}

// /usr/bin/openssl carries a version string but uses the shared libcrypto.
func TestDynamicallyLinkedToolIsNotAModule(t *testing.T) {
	r := scan(t, map[string][]byte{
		"usr/bin/openssl":     makeELFNeeding("OpenSSL 3.5.7 1 Oct 2026", true, "libcrypto.so.3"),
		"usr/bin/static-tool": makeELFNeeding("OpenSSL 3.5.7 1 Oct 2026", true, "libc.so.6"),
	}, "usr/bin/openssl", "usr/bin/static-tool")
	for _, m := range r.Modules {
		if m.Path == "usr/bin/openssl" {
			t.Errorf("dynamically linked CLI reported as a module: %+v", m)
		}
	}
	if m := module(t, r, "usr/bin/static-tool"); m.Version != "3.5.7" {
		t.Errorf("a static copy must still be found: %+v", m)
	}
}

func TestNotELFIgnored(t *testing.T) {
	r := scan(t, map[string][]byte{
		sysLib + "libssl.so.3": []byte("just text pretending to be a library"),
		"usr/bin/run.sh":       []byte("#!/bin/sh\necho hi\n"),
	}, "usr/bin/run.sh")
	if len(r.Modules) != 0 || len(r.Findings) != 0 {
		t.Errorf("non-ELF files: %+v %+v", r.Modules, r.Findings)
	}
}

func TestOversizedELFWarns(t *testing.T) {
	d := t.TempDir()
	os.MkdirAll(filepath.Join(d, "usr/lib"), 0o755)
	os.WriteFile(filepath.Join(d, "usr/lib/libcrypto.so.3"), makeELF("OpenSSL 3.0.13 30 Jan 2024", true), 0o644)
	root, _ := os.OpenRoot(d)
	defer root.Close()
	snap, _ := BuiltinSnapshot()
	opt := DefaultOptions()
	opt.MaxELFSize = 10
	r, _ := Scan(context.Background(), root, nil, snap, opt)
	if len(r.Modules) != 0 || len(r.Warnings) != 1 {
		t.Errorf("oversized ELF: modules %+v warnings %v", r.Modules, r.Warnings)
	}
}

func TestSourceHints(t *testing.T) {
	r := scan(t, map[string][]byte{
		"app/cache.py":    []byte("import hashlib\nkey = hashlib.md5(b).hexdigest()\nk2 = hashlib.sha1(x)\n"),
		"app/ok.py":       []byte("h = hashlib.md5(b, usedforsecurity=False)\n"),
		"app/tokens.py":   []byte("import random\nreset_token = ''.join(random.choice(abc) for _ in range(32))\n"),
		"app/dice.py":     []byte("roll = random.randint(1, 6)\n"),
		site + "lib/x.py": []byte("hashlib.md5(b)\n"),
	})
	got := ruleSet(r)
	if len(got[RuleWeakHash]) != 1 || got[RuleWeakHash][0] != "app/cache.py" {
		t.Errorf("weak hash: %v", got)
	}
	if len(got[RuleInsecureRandom]) != 1 || got[RuleInsecureRandom][0] != "app/tokens.py" {
		t.Errorf("insecure random: %v", got)
	}
	for _, f := range r.Findings {
		if f.Rule == RuleWeakHash && (*f.Evidence.Offset != 15 || f.Evidence.SHA256 == "") {
			t.Errorf("weak hash evidence: %+v", f.Evidence)
		}
	}
}

// goBuild compiles a tiny Linux program with the local toolchain (our own
// test code, not scanned content).
func goBuild(t *testing.T, src, fips string) []byte {
	t.Helper()
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "go.mod"), []byte("module x\n\ngo 1.26\n"), 0o644)
	os.WriteFile(filepath.Join(d, "main.go"), []byte(src), 0o644)
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", "bin")
	cmd.Dir = d
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH, "GOWORK=off", "GOFLAGS=", "GOFIPS140="+fips)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	b, _ := os.ReadFile(filepath.Join(d, "bin"))
	return b
}

func TestGoBinaries(t *testing.T) {
	if testing.Short() {
		t.Skip("builds Go binaries")
	}
	withCrypto := "package main\nimport (\"crypto/sha256\"; \"fmt\"; \"os\")\nfunc main() { fmt.Println(sha256.Sum256([]byte(os.Args[0]))) }\n"
	noCrypto := "package main\nimport \"fmt\"\nfunc main() { fmt.Println(\"hi\") }\n"
	r := scan(t, map[string][]byte{
		"usr/local/bin/fips-app":  goBuild(t, withCrypto, "v1.0.0"),
		"usr/local/bin/plain-app": goBuild(t, withCrypto, "off"),
		"usr/local/bin/no-crypto": goBuild(t, noCrypto, "off"),
	}, "usr/local/bin/fips-app", "usr/local/bin/plain-app", "usr/local/bin/no-crypto")

	f := module(t, r, "usr/local/bin/fips-app")
	if f.Library != "go" || !strings.HasPrefix(f.Version, "v1.0.0-") || f.Status != StatusValidated || f.Certificate != "5247" {
		t.Errorf("GOFIPS140=v1.0.0 binary: %+v", f)
	}
	p := module(t, r, "usr/local/bin/plain-app")
	if p.Version != "" || p.Status != StatusUnvalidated || !strings.Contains(p.Note, "not built with GOFIPS140") {
		t.Errorf("plain Go binary: %+v", p)
	}
	for _, m := range r.Modules {
		if m.Path == "usr/local/bin/no-crypto" {
			t.Errorf("a Go binary without crypto isn't a crypto module: %+v", m)
		}
	}
}

func TestSnapshot(t *testing.T) {
	s, err := BuiltinSnapshot()
	if err != nil || s.SnapshotDate == "" || len(s.Modules) == 0 {
		t.Fatalf("builtin snapshot: %v", err)
	}
	bad := []string{
		`{`,
		`{"snapshot_date":"Nov 2026","modules":[]}`,
		`{"snapshot_date":"2026-11-09","modules":[{"library":"x","versions":["1"]}]}`,
		`{"snapshot_date":"2026-11-09","modules":[{"library":"x","versions":["1"],"source":"https://x","status":"valid"}]}`,
		`{"snapshot_date":"2026-11-09","modules":[{"library":"x","versions":["1"],"source":"https://x","status":"active"}]}`,
	}
	for _, b := range bad {
		if _, err := ParseSnapshot([]byte(b)); err == nil {
			t.Errorf("ParseSnapshot(%s) should fail", b)
		}
	}
}

func TestDeterministicAndStable(t *testing.T) {
	files := map[string][]byte{
		sysLib + "libcrypto.so.3":  makeELF("OpenSSL 3.0.13 30 Jan 2024", true),
		sysLib + "libgnutls.so.30": makeELF("x", true),
		"app/a.py":                 []byte("hashlib.md5(x)\n"),
	}
	a, _ := json.Marshal(scan(t, files))
	b, _ := json.Marshal(scan(t, files))
	if !bytes.Equal(a, b) {
		t.Fatal("crypto scan output isn't deterministic")
	}
	empty, _ := json.Marshal(scan(t, map[string][]byte{"x": nil}))
	if !bytes.Contains(empty, []byte(`"modules":[]`)) || !bytes.Contains(empty, []byte(`"findings":[]`)) {
		t.Errorf("empty slices must marshal as []: %s", empty)
	}
}

func TestOrigin(t *testing.T) {
	cases := map[string][2]string{
		"usr/lib/libcrypto.so.3":                       {"system", ""},
		"opt/venv/lib/python3.11/site-packages/x/y.so": {"python-wheel", "x"},
		"usr/lib/python3/dist-packages/z.libs/a.so":    {"python-wheel", "z"},
		"srv/node_modules/n/b.node":                    {"node-module", "n"},
		"app/bin/tool":                                 {"app", ""},
	}
	for p, want := range cases {
		o, pkg := origin(p)
		if o != want[0] || pkg != want[1] {
			t.Errorf("origin(%s) = %s,%s want %v", p, o, pkg, want)
		}
	}
}

// ELF headers that point outside the file are refused before debug/elf or
// debug/buildinfo size any read from them (FuzzScanELF found a 64-byte file
// that made the stdlib allocate ~40 MB).
func TestValidateELF(t *testing.T) {
	good := makeELFNeeding("OpenSSL 3.0.13 30 Jan 2024", true, "libcrypto.so.3")
	if err := validateELF(bytes.NewReader(good), int64(len(good))); err != nil {
		t.Fatalf("well-formed ELF rejected: %v", err)
	}
	le := binary.LittleEndian
	mut := func(f func(b []byte)) []byte {
		b := append([]byte(nil), good...)
		f(b)
		return b
	}
	cases := map[string][]byte{
		"empty":               nil,
		"magic only":          []byte("\x7fELF"),
		"short header":        good[:40],
		"bad class":           mut(func(b []byte) { b[4] = 9 }),
		"bad byte order":      mut(func(b []byte) { b[5] = 0 }),
		"shoff past EOF":      mut(func(b []byte) { le.PutUint64(b[40:], uint64(len(b))+1) }),
		"shoff huge":          mut(func(b []byte) { le.PutUint64(b[40:], 1<<63) }),
		"shnum past EOF":      mut(func(b []byte) { le.PutUint16(b[60:], 0xfff0) }),
		"shentsize tiny":      mut(func(b []byte) { le.PutUint16(b[58:], 8) }),
		"shstrndx past table": mut(func(b []byte) { le.PutUint16(b[62:], 40) }),
		"phnum past EOF":      mut(func(b []byte) { le.PutUint16(b[56:], 100) }),
		"phentsize tiny":      mut(func(b []byte) { le.PutUint16(b[54:], 4); le.PutUint16(b[56:], 1) }),
		"section off+size overflow": mut(func(b []byte) {
			shoff := le.Uint64(b[40:])
			le.PutUint64(b[shoff+64*2+24:], ^uint64(0)-8) // .shstrtab offset
		}),
		"section size past EOF": mut(func(b []byte) {
			shoff := le.Uint64(b[40:])
			le.PutUint64(b[shoff+64*1+32:], 1<<40) // .rodata size
		}),
	}
	for name, b := range cases {
		if err := validateELF(bytes.NewReader(b), int64(len(b))); err == nil {
			t.Errorf("%s: accepted", name)
		} else if !errors.Is(err, errELF) {
			t.Errorf("%s: error %v does not wrap errELF", name, err)
		}
	}
}

// The FuzzScanELF crash input is rejected with a warning and a small allocation.
func TestScanRejectsHostileELFHeaderCheaply(t *testing.T) {
	data := []byte("\x7fELF\x02\x01\x010000000000000\x0100000000000000000000000000000000000\x00000000 ")
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "usr/lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "usr/lib/libcrypto.so.3"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	snap, err := BuiltinSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	res, err := Scan(context.Background(), root, nil, snap, DefaultOptions())
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > 4<<20 {
		t.Errorf("scan of a %d-byte hostile ELF allocated %d bytes", len(data), got)
	}
	if len(res.Modules) != 0 || len(res.Warnings) == 0 {
		t.Errorf("modules=%d warnings=%q; want no module and a warning", len(res.Modules), res.Warnings)
	}
}
