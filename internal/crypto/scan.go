package crypto

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/uddeshya-world/gapproof/internal/evidence"
	"github.com/uddeshya-world/gapproof/internal/inventory"
)

// Module statuses (spec §3.3).
const (
	StatusValidated   = "validated-snapshot-match"
	StatusUnvalidated = "unvalidated"
	StatusUnknown     = "unknown"
)

// Module is one crypto implementation found in the image.
type Module struct {
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	Library     string `json:"library"`
	Version     string `json:"version,omitempty"`
	Origin      string `json:"origin"`            // system | python-wheel | node-module | go-binary | app
	Package     string `json:"package,omitempty"` // owning Python/Node package for bundled copies
	Status      string `json:"status"`
	Certificate string `json:"certificate,omitempty"`
	Note        string `json:"note,omitempty"`
}

// FIPSProvider is an OpenSSL 3 FIPS provider (fips.so).
type FIPSProvider struct {
	Path       string `json:"path"`
	Version    string `json:"version,omitempty"`
	Configured bool   `json:"configured"` // some openssl.cnf in the image activates it
}

// Result is the module output; all slices are sorted.
type Result struct {
	SnapshotDate  string             `json:"cmvp_snapshot_date"`
	Modules       []Module           `json:"modules"`
	FIPSProviders []FIPSProvider     `json:"fips_providers"`
	Configs       []string           `json:"fips_configs"` // openssl.cnf files that activate a FIPS provider
	Findings      []evidence.Finding `json:"findings"`
	Warnings      []string           `json:"warnings,omitempty"`
}

// Options bound per-file work.
type Options struct {
	MaxELFSize   int64 // larger ELF files are skipped with a warning
	MaxScanBytes int64 // bytes searched when an ELF has no .rodata
}

func DefaultOptions() Options { return Options{MaxELFSize: 2 << 30, MaxScanBytes: 256 << 20} }

// Rule IDs.
const (
	RuleUnvalidated    = "CRYPTO-UNVALIDATED-MODULE"
	RuleUnknown        = "CRYPTO-UNKNOWN-MODULE"
	RuleProviderOff    = "CRYPTO-FIPS-PROVIDER-NOT-CONFIGURED"
	RuleWeakHash       = "CRYPTO-WEAK-HASH"
	RuleInsecureRandom = "CRYPTO-INSECURE-RANDOM"
	disclaimerSuffix   = " Gapproof inventories modules and matches them against a dated CMVP snapshot; it doesn't certify anything."
)

var cryptoLib = regexp.MustCompile(`^lib(ssl|crypto|gnutls|nss3|mbedcrypto|mbedtls|wolfssl|gcrypt|nettle|boringssl)[.-]`)

// Scan inventories crypto modules under root.
func Scan(ctx context.Context, root *os.Root, inv *inventory.Inventory, snap *Snapshot, opt Options) (*Result, error) {
	s := &scanner{root: root, snap: snap, opt: opt, res: &Result{SnapshotDate: snap.SnapshotDate}}
	var elfs, cnfs []string
	err := fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if !d.Type().IsRegular() {
			return nil
		}
		base := path.Base(p)
		switch {
		case base == "openssl.cnf":
			cnfs = append(cnfs, p)
		case base == "fips.so", cryptoLib.MatchString(base), bundledPath(p) && isSharedObject(base):
			elfs = append(elfs, p)
		default:
			if fi, err := d.Info(); err == nil && fi.Mode()&0o111 != 0 {
				elfs = append(elfs, p) // executables: candidate Go binaries
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, p := range cnfs {
		if s.fipsConfigured(p) {
			s.res.Configs = append(s.res.Configs, p)
		}
	}
	for _, p := range elfs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		s.file(p)
	}
	s.assignStatuses()
	if inv != nil {
		s.sourceHints(ctx, inv)
	}

	slices.SortFunc(s.res.Modules, func(a, b Module) int { return cmp.Compare(a.Path, b.Path) })
	slices.SortFunc(s.res.FIPSProviders, func(a, b FIPSProvider) int { return cmp.Compare(a.Path, b.Path) })
	slices.Sort(s.res.Configs)
	evidence.Sort(s.res.Findings)
	for _, x := range []*[]Module{&s.res.Modules} {
		if *x == nil {
			*x = []Module{}
		}
	}
	if s.res.FIPSProviders == nil {
		s.res.FIPSProviders = []FIPSProvider{}
	}
	if s.res.Configs == nil {
		s.res.Configs = []string{}
	}
	if s.res.Findings == nil {
		s.res.Findings = []evidence.Finding{}
	}
	return s.res, nil
}

type scanner struct {
	root *os.Root
	snap *Snapshot
	opt  Options
	res  *Result
}

func bundledPath(p string) bool {
	return strings.Contains(p, "site-packages/") || strings.Contains(p, "dist-packages/") || strings.Contains(p, "node_modules/")
}

func isSharedObject(base string) bool {
	return strings.HasSuffix(base, ".so") || strings.Contains(base, ".so.") || strings.HasSuffix(base, ".node")
}

// origin classifies where a module came from, and which package bundled it.
func origin(p string) (string, string) {
	for _, marker := range []string{"site-packages/", "dist-packages/"} {
		if _, rest, ok := strings.Cut(p, marker); ok {
			pkg, _, _ := strings.Cut(rest, "/")
			return "python-wheel", strings.TrimSuffix(pkg, ".libs")
		}
	}
	if _, rest, ok := strings.Cut(p, "node_modules/"); ok {
		pkg, _, _ := strings.Cut(rest, "/")
		return "node-module", pkg
	}
	if strings.HasPrefix(p, "usr/") || strings.HasPrefix(p, "lib") || strings.HasPrefix(p, "opt/") || strings.HasPrefix(p, "etc/") {
		return "system", ""
	}
	return "app", ""
}

var (
	reOpenSSL   = regexp.MustCompile(`OpenSSL (\d+\.\d+\.\d+[a-z]?)(?:-[A-Za-z0-9.+]+)? +\d{1,2} [A-Z][a-z]{2} \d{4}`)
	reLibreSSL  = regexp.MustCompile(`LibreSSL (\d+\.\d+\.\d+)`)
	reBoringSSL = regexp.MustCompile(`BoringSSL`)
	reNSS       = regexp.MustCompile(`NSS (\d+\.\d+(?:\.\d+)?)`)
	reMbed      = regexp.MustCompile(`(?i)mbed ?TLS (\d+\.\d+\.\d+)`)
	reBareVer   = regexp.MustCompile(`\x00(\d+\.\d+\.\d+)\x00`)
	elfMagic    = []byte("\x7fELF")
	// Go function names in .gopclntab for public crypto packages.
	goCrypto = regexp.MustCompile(`crypto/(tls|aes|cipher|sha1|sha256|sha512|sha3|hmac|hkdf|pbkdf2|ecdsa|ecdh|ed25519|rsa|rand|x509|mlkem)\.|golang\.org/x/crypto/`)
)

// file analyses one candidate. A malformed file can make the stdlib ELF
// parsers fail; that's recorded as a warning, never a crash.
func (s *scanner) file(p string) {
	defer func() {
		if r := recover(); r != nil {
			s.warnf("%s: parse error (%v); not inventoried", p, r)
		}
	}()
	f, err := s.root.Open(p)
	if err != nil {
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return
	}
	var magic [4]byte
	if n, _ := f.ReadAt(magic[:], 0); n < 4 || !bytes.Equal(magic[:], elfMagic) {
		return
	}
	if fi.Size() > s.opt.MaxELFSize {
		s.warnf("%s: %d bytes, larger than the %d-byte ELF limit; not inventoried", p, fi.Size(), s.opt.MaxELFSize)
		return
	}
	// Everything below reads through a reader capped at the real file size, and
	// only after the headers have been checked against it (elfguard.go).
	capped := io.NewSectionReader(f, 0, fi.Size())
	if err := validateELF(capped, fi.Size()); err != nil {
		s.warnf("%s: %v; not inventoried", p, err)
		return
	}
	if bi, err := buildinfo.Read(capped); err == nil {
		s.goBinary(p, f, capped, bi)
		return
	}
	ef, err := elf.NewFile(capped)
	if err != nil {
		return // not an ELF we can read; not a crypto finding
	}
	base := path.Base(p)
	if base != "fips.so" && !cryptoLib.MatchString(base) && linksCryptoLib(ef) {
		// e.g. /usr/bin/openssl: it carries the version string but uses the
		// shared libcrypto, which is inventoried on its own.
		return
	}
	data, err := s.rodata(ef, f)
	if err != nil {
		s.warnf("%s: %v", p, err)
		return
	}
	m := Module{Path: p}
	m.Origin, m.Package = origin(p)
	switch {
	case base == "fips.so":
		m.Library = "openssl-fips-provider"
		if v := reOpenSSL.FindSubmatch(data); v != nil {
			m.Version = string(v[1])
		} else if v := reBareVer.FindSubmatch(data); v != nil {
			m.Version = string(v[1])
		}
		s.res.FIPSProviders = append(s.res.FIPSProviders, FIPSProvider{Path: p, Version: m.Version, Configured: len(s.res.Configs) > 0})
	case reLibreSSL.Match(data):
		m.Library, m.Version = "libressl", string(reLibreSSL.FindSubmatch(data)[1])
	case reOpenSSL.Match(data):
		m.Library, m.Version = "openssl", string(reOpenSSL.FindSubmatch(data)[1])
	case reBoringSSL.Match(data):
		m.Library = "boringssl"
	case strings.HasPrefix(base, "libnss3"):
		m.Library = "nss"
		if v := reNSS.FindSubmatch(data); v != nil {
			m.Version = string(v[1])
		}
	case reMbed.Match(data) || strings.HasPrefix(base, "libmbed"):
		m.Library = "mbedtls"
		if v := reMbed.FindSubmatch(data); v != nil {
			m.Version = string(v[1])
		}
	case strings.HasPrefix(base, "libgnutls"):
		m.Library = "gnutls"
	case strings.HasPrefix(base, "libgcrypt"):
		m.Library = "libgcrypt"
	case strings.HasPrefix(base, "libwolfssl"):
		m.Library = "wolfssl"
	case strings.HasPrefix(base, "libnettle"):
		m.Library = "nettle"
	case strings.HasPrefix(base, "libcrypto"):
		m.Library = "openssl" // version string not found
	default:
		return // libssl without its own version string, or a .so with no crypto: libcrypto carries the module
	}
	m.SHA256 = hashFile(f)
	s.res.Modules = append(s.res.Modules, m)
}

// linksCryptoLib reports whether an ELF dynamically links a crypto library.
func linksCryptoLib(ef *elf.File) bool {
	libs, _ := ef.ImportedLibraries()
	for _, l := range libs {
		if cryptoLib.MatchString(l) {
			return true
		}
	}
	return false
}

// rodata returns the .rodata section, or the leading bytes of the file.
func (s *scanner) rodata(ef *elf.File, f *os.File) ([]byte, error) {
	if sec := ef.Section(".rodata"); sec != nil && sec.Type != elf.SHT_NOBITS {
		if int64(sec.Size) > s.opt.MaxScanBytes {
			return io.ReadAll(io.LimitReader(sec.Open(), s.opt.MaxScanBytes))
		}
		return io.ReadAll(sec.Open())
	}
	return io.ReadAll(io.NewSectionReader(f, 0, s.opt.MaxScanBytes))
}

func (s *scanner) goBinary(p string, f *os.File, capped *io.SectionReader, bi *buildinfo.BuildInfo) {
	ef, err := elf.NewFile(capped)
	if err != nil {
		return
	}
	var tab []byte
	if sec := ef.Section(".gopclntab"); sec != nil {
		tab, _ = io.ReadAll(io.LimitReader(sec.Open(), s.opt.MaxScanBytes))
	} else {
		tab, _ = io.ReadAll(io.NewSectionReader(f, 0, s.opt.MaxScanBytes))
	}
	if !goCrypto.Match(tab) {
		return // a Go binary that doesn't use crypto isn't a crypto module
	}
	m := Module{Path: p, Library: "go", Origin: "go-binary", SHA256: hashFile(f)}
	settings := map[string]string{}
	for _, st := range bi.Settings {
		settings[st.Key] = st.Value
	}
	m.Version = settings["GOFIPS140"]
	if m.Version == "off" {
		m.Version = ""
	}
	m.Note = bi.GoVersion
	if strings.Contains(settings["GOEXPERIMENT"], "boringcrypto") {
		m.Library = "go-boringcrypto"
	}
	s.res.Modules = append(s.res.Modules, m)
}

// fipsConfigured reports whether an openssl.cnf activates the FIPS provider.
var (
	reCnfComment = regexp.MustCompile(`(?m)#.*$`)
	reFIPSLine   = regexp.MustCompile(`(?m)^\s*fips\s*=\s*\S+`)
	reFIPSInc    = regexp.MustCompile(`(?m)^\s*\.include\s+\S*fipsmodule\.cnf`)
	reFIPSSect   = regexp.MustCompile(`(?m)^\s*\[\s*fips_sect\s*\]`)
)

func (s *scanner) fipsConfigured(p string) bool {
	f, err := s.root.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, 1<<20))
	b = reCnfComment.ReplaceAll(b, nil)
	return reFIPSLine.Match(b) && (reFIPSInc.Match(b) || reFIPSSect.Match(b))
}

// assignStatuses maps each module against the snapshot.
func (s *scanner) assignStatuses() {
	// Is there a configured FIPS provider whose version holds an active certificate?
	var active *SnapEntry
	var activeProv FIPSProvider
	for i := range s.res.FIPSProviders {
		pv := &s.res.FIPSProviders[i]
		pv.Configured = len(s.res.Configs) > 0
		if e := s.snap.lookup("openssl-fips-provider", pv.Version); e != nil && e.Status == "active" && pv.Configured {
			active, activeProv = e, *pv
		}
		if !pv.Configured {
			s.add(RuleProviderOff, pv.Path, "", fmt.Sprintf("OpenSSL FIPS provider %s present but no openssl.cnf activates it", orUnknown(pv.Version)))
		}
	}
	snapNote := " (CMVP snapshot " + s.snap.SnapshotDate + ")"
	for i := range s.res.Modules {
		m := &s.res.Modules[i]
		switch m.Library {
		case "openssl-fips-provider", "go":
			e := s.snap.lookup(m.Library, m.Version)
			switch {
			case e != nil && e.Status == "active":
				m.Status, m.Certificate = StatusValidated, e.Certificate
				m.Note = joinNote(m.Note, fmt.Sprintf("%s certificate #%s (%s)", e.Standard, e.Certificate, e.Name))
			case e != nil:
				m.Status = StatusUnvalidated
				m.Note = joinNote(m.Note, fmt.Sprintf("snapshot entry is %s: %s", e.Status, e.Note))
			case m.Library == "go" && m.Version == "":
				m.Status = StatusUnvalidated
				m.Note = joinNote(m.Note, "standard Go crypto, not built with GOFIPS140")
			default:
				m.Status = StatusUnvalidated
				m.Note = joinNote(m.Note, "version not in the CMVP snapshot")
			}
		case "openssl":
			switch {
			case m.Origin == "python-wheel" || m.Origin == "node-module":
				m.Status = StatusUnvalidated
				m.Note = "statically bundled by " + orUnknown(m.Package) + "; it doesn't use the system FIPS provider"
			case active != nil && strings.HasPrefix(m.Version, "3."):
				m.Status, m.Certificate = StatusValidated, active.Certificate
				m.Note = fmt.Sprintf("via configured FIPS provider %s (%s certificate #%s)", activeProv.Version, active.Standard, active.Certificate)
			default:
				m.Status = StatusUnvalidated
				m.Note = "no configured FIPS provider with an active certificate in the image"
			}
		case "libressl", "boringssl":
			m.Status = StatusUnvalidated
			m.Note = m.Library + " builds aren't CMVP-validated modules"
		default:
			m.Status = StatusUnknown
			m.Note = "vendor builds may hold their own certificates; not in the snapshot"
		}
		what := fmt.Sprintf("%s %s (%s", m.Library, orUnknown(m.Version), m.Origin)
		if m.Package != "" {
			what += ", " + m.Package
		}
		what += "): " + m.Note + snapNote
		switch m.Status {
		case StatusUnvalidated:
			s.add(RuleUnvalidated, m.Path, m.SHA256, what)
		case StatusUnknown:
			s.add(RuleUnknown, m.Path, m.SHA256, what)
		}
	}
}

var (
	reWeakHash   = regexp.MustCompile(`hashlib\.(md5|sha1)\(|hashlib\.new\(\s*['"](md5|sha1)['"]`)
	reNotSec     = regexp.MustCompile(`usedforsecurity\s*=\s*False`)
	reRandomCall = regexp.MustCompile(`\brandom\.(random|randint|randrange|choice|choices|getrandbits|sample)\(`)
	reSecretWord = regexp.MustCompile(`(?i)(token|secret|passw|nonce|salt|api_?key|session|otp)`)
)

// sourceHints flags weak hashes and non-CSPRNG randomness in application code.
func (s *scanner) sourceHints(ctx context.Context, inv *inventory.Inventory) {
	for _, p := range inv.Sources {
		if ctx.Err() != nil || !strings.HasSuffix(p, ".py") {
			continue
		}
		f, err := s.root.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		var off int64
		var weak, rnd bool
		var sum string
		for sc.Scan() {
			l := sc.Text()
			if !weak && reWeakHash.MatchString(l) && !reNotSec.MatchString(l) {
				weak = true
				sum = cmp.Or(sum, hashFile(f))
				s.addAt(RuleWeakHash, p, sum, off, strings.TrimSpace(l))
			}
			if !rnd && reRandomCall.MatchString(l) && reSecretWord.MatchString(l) {
				rnd = true
				sum = cmp.Or(sum, hashFile(f))
				s.addAt(RuleInsecureRandom, p, sum, off, strings.TrimSpace(l))
			}
			off += int64(len(l)) + 1
		}
		f.Close()
	}
}

var ruleText = map[string]struct {
	sev                     evidence.Severity
	title, explanation, fix string
}{
	RuleUnvalidated: {evidence.High, "Crypto module without a matching active CMVP certificate",
		"This crypto implementation doesn't match an active CMVP certificate in Gapproof's snapshot. Under AGR-3 it must be replaced or accepted in writing." + disclaimerSuffix,
		"Use a validated module (for example OpenSSL 3 with a validated, configured FIPS provider, or Go built with GOFIPS140), rebuild bundled copies against it, or record an accepted risk."},
	RuleUnknown: {evidence.High, "Crypto module with unknown validation status",
		"Gapproof found this crypto library but can't map it to a certificate: vendor builds (for example distro FIPS packages) may be validated, but that isn't visible from the file." + disclaimerSuffix,
		"Confirm the vendor's certificate for this exact build and record it as an accepted risk, or remove the library if it isn't used."},
	RuleProviderOff: {evidence.Medium, "OpenSSL FIPS provider present but not configured",
		"The image ships the OpenSSL FIPS provider, but no openssl.cnf activates it, so OpenSSL keeps using the default provider.",
		"Run `openssl fipsinstall` at build time and include the generated fipsmodule.cnf from openssl.cnf with the fips provider activated."},
	RuleWeakHash: {evidence.Medium, "Application uses MD5/SHA-1",
		"Application code calls MD5 or SHA-1 without usedforsecurity=False. Auditors flag this, and FIPS-mode OpenSSL refuses it.",
		"Use SHA-256, or pass usedforsecurity=False where the hash isn't security-relevant (cache keys)."},
	RuleInsecureRandom: {evidence.Medium, "Application uses non-cryptographic randomness for a secret",
		"Application code uses the random module next to a token/secret/key name. random isn't a CSPRNG.",
		"Use the secrets module (secrets.token_bytes / token_urlsafe) for anything secret."},
}

var cryptoControls = map[string][]string{
	RuleUnvalidated: {"SC-12", "SC-13"}, RuleUnknown: {"SC-12", "SC-13"}, RuleProviderOff: {"SC-13", "CM-6"},
	RuleWeakHash: {"SC-13"}, RuleInsecureRandom: {"SC-12", "SC-13"},
}

func (s *scanner) add(rule, p, sha, detail string) { s.addOff(rule, p, sha, nil, detail) }

func (s *scanner) addAt(rule, p, sha string, off int64, detail string) {
	s.addOff(rule, p, sha, evidence.Off(off), detail)
}

func (s *scanner) addOff(rule, p, sha string, off *int64, detail string) {
	t := ruleText[rule]
	if sha == "" {
		if f, err := s.root.Open(p); err == nil {
			sha = hashFile(f)
			f.Close()
		}
	}
	if len(detail) > 200 {
		detail = detail[:200] + "…"
	}
	s.res.Findings = append(s.res.Findings, evidence.Finding{
		Rule: rule, Severity: t.sev, Title: t.title, Explanation: t.explanation, Fix: t.fix,
		Controls: cryptoControls[rule],
		Evidence: evidence.Evidence{Path: p, SHA256: sha, Offset: off, Detail: detail},
	})
}

func (s *scanner) warnf(format string, a ...any) {
	if len(s.res.Warnings) < 100 {
		s.res.Warnings = append(s.res.Warnings, fmt.Sprintf(format, a...))
	}
}

func hashFile(f *os.File) string {
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(f, 0, 1<<62)); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func orUnknown(s string) string { return cmp.Or(s, "(version unknown)") }

func joinNote(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}
