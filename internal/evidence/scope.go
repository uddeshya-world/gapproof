package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// maxConfigFile bounds the scope and waivers files.
const maxConfigFile = 1 << 20

// Scope is a loaded gapproof.scope.yaml (AGR_SPEC §2). A nil *Scope means
// no scope file: only localhost and the target's own hostname are in scope.
type Scope struct {
	SHA256        string         `json:"sha256"`
	InternalNames []string       `json:"internal_names"`
	InternalCIDRs []netip.Prefix `json:"internal_cidrs"`
	Raw           []byte         `json:"-"` // the file as read, for the evidence copy
}

type scopeFile struct {
	ScopeVersion  int      `yaml:"scope_version"`
	InternalNames []string `yaml:"internal_names"`
	InternalCIDRs []string `yaml:"internal_cidrs"`
}

var (
	// privateRanges are the only ranges a scope file may declare.
	privateRanges = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("fc00::/7"),
	}
	// syntheticRange holds the sinkhole's per-name DNS answers (spec §3.1).
	syntheticRange = netip.MustParsePrefix("198.18.0.0/15")
)

// privateTLDs may be wildcarded at a single label: reserved names (RFC 6761,
// RFC 8375, ICANN's .internal) plus common private conventions.
var privateTLDs = map[string]bool{
	"internal": true, "local": true, "lan": true, "corp": true, "home": true,
	"intranet": true, "private": true, "localdomain": true, "test": true,
	"invalid": true, "example": true, "arpa": true,
}

const privateTLDList = "internal, local, lan, corp, home, intranet, private, localdomain, test, invalid, example, arpa"

// readConfig reads a small user-supplied file; failures are usage errors.
func readConfig(path, what string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, usagef("%s file: %v", what, err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxConfigFile+1))
	if err != nil {
		return nil, usagef("%s file: %v", what, err)
	}
	if len(b) > maxConfigFile {
		return nil, usagef("%s file %s is larger than %d bytes", what, path, maxConfigFile)
	}
	return b, nil
}

// decodeStrict decodes exactly one YAML document, rejecting unknown keys.
func decodeStrict(b []byte, v any, what string) error {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return usagef("%s file is empty", what)
		}
		return usagef("%s file: %v", what, err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return usagef("%s file: exactly one YAML document expected", what)
	}
	return nil
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// LoadScope reads and validates a scope file. Every problem, including a
// public CIDR, is a *UsageError.
func LoadScope(path string) (*Scope, error) {
	b, err := readConfig(path, "scope")
	if err != nil {
		return nil, err
	}
	return ParseScope(b)
}

// ParseScope validates scope file bytes (see LoadScope).
func ParseScope(b []byte) (*Scope, error) {
	var f scopeFile
	if err := decodeStrict(b, &f, "scope"); err != nil {
		return nil, err
	}
	if f.ScopeVersion != 1 {
		return nil, usagef("scope file: scope_version must be 1, got %d", f.ScopeVersion)
	}
	s := &Scope{SHA256: sha256Hex(b), Raw: slices.Clone(b), InternalNames: []string{}, InternalCIDRs: []netip.Prefix{}}
	for _, n := range f.InternalNames {
		norm, err := normalizeScopeName(n)
		if err != nil {
			return nil, err
		}
		s.InternalNames = append(s.InternalNames, norm)
	}
	slices.Sort(s.InternalNames)
	s.InternalNames = slices.Compact(s.InternalNames)
	for _, c := range f.InternalCIDRs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			return nil, usagef("scope file: internal_cidrs: %q is not a CIDR", c)
		}
		p = p.Masked()
		if !isPrivatePrefix(p) {
			return nil, usagef("scope file: internal_cidrs: %s is not private (allowed: RFC 1918, 100.64.0.0/10, fc00::/7)", p)
		}
		s.InternalCIDRs = append(s.InternalCIDRs, p)
	}
	slices.SortFunc(s.InternalCIDRs, func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
	s.InternalCIDRs = slices.Compact(s.InternalCIDRs)
	return s, nil
}

func normalizeScopeName(n string) (string, error) {
	norm := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
	base := strings.TrimPrefix(norm, "*.")
	if base == "" || strings.Contains(base, "*") {
		return "", usagef("scope file: internal_names: %q: use an exact name or a leading \"*.\" wildcard", n)
	}
	if strings.HasPrefix(base, ".") || strings.HasSuffix(base, ".") || strings.Contains(base, "..") {
		return "", usagef("scope file: internal_names: %q has an empty label", n)
	}
	// A wildcard over a whole top-level label ("*.com") would put most of the
	// internet in scope. Only reserved or conventionally private TLDs may be
	// wildcarded at one label; anything else needs at least two labels.
	if norm != base && !strings.Contains(base, ".") && !privateTLDs[base] {
		return "", usagef("scope file: internal_names: %q is too broad; a wildcard needs at least two labels (e.g. \"*.corp.example\") unless it covers a private TLD (%s)", n, privateTLDList)
	}
	for _, r := range base {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_') {
			return "", usagef("scope file: internal_names: %q contains %q", n, r)
		}
	}
	return norm, nil
}

func isPrivatePrefix(p netip.Prefix) bool {
	for _, r := range privateRanges {
		if p.Addr().Is4() == r.Addr().Is4() && p.Bits() >= r.Bits() && r.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

func normalizeName(n string) string {
	return strings.TrimSuffix(strings.ToLower(n), ".")
}

func (s *Scope) nameIn(n, target string) bool {
	n = normalizeName(n)
	if n == "localhost" || (target != "" && n == normalizeName(target)) {
		return true
	}
	if s == nil {
		return false
	}
	for _, d := range s.InternalNames {
		if suffix, ok := strings.CutPrefix(d, "*."); ok {
			if strings.HasSuffix(n, "."+suffix) {
				return true
			}
		} else if n == d {
			return true
		}
	}
	return false
}

func (s *Scope) cidrIn(ip netip.Addr) bool {
	if s == nil {
		return false
	}
	for _, p := range s.InternalCIDRs {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// hostOnly strips a port from an HTTP Host value.
func hostOnly(h string) string {
	if strings.HasPrefix(h, "[") {
		if i := strings.IndexByte(h, ']'); i > 0 {
			return h[1:i]
		}
		return h
	}
	if strings.Count(h, ":") == 1 {
		return h[:strings.IndexByte(h, ':')]
	}
	return h
}

// Contains reports whether an attempt is in scope. Every identifier the
// attempt carries must be in scope (fail closed): its name, TLS SNI and HTTP
// Host each match an internal name (exact, or a "*." suffix wildcard), and a
// literal destination IP is loopback or inside an internal CIDR. A
// synthetic sinkhole address (198.18.0.0/15) stands for its DNS name and is
// judged by that name. localhost and targetHostname are always in scope.
//
// DNS queries are judged by the queried name. The resolver they were sent to
// must also be loopback or inside a declared internal CIDR: a hard-coded
// resolver anywhere else, public or merely private but undeclared, is out of
// scope even for an internal name.
func (s *Scope) Contains(a EgressAttempt, targetHostname string) bool {
	var names []string
	for _, n := range []string{a.Name, a.SNI, hostOnly(a.HTTPHost)} {
		if n != "" {
			names = append(names, n)
		}
	}
	for _, n := range names {
		if lit, err := netip.ParseAddr(n); err == nil {
			// A literal IP in SNI or Host is judged as an address.
			if lit = lit.Unmap(); !lit.IsLoopback() && !s.cidrIn(lit) {
				return false
			}
		} else if !s.nameIn(n, targetHostname) {
			return false
		}
	}
	ip, err := netip.ParseAddr(a.OrigDstIP)
	hasIP := a.OrigDstIP != "" && err == nil
	if a.OrigDstIP != "" && err != nil {
		return false // unparseable destination: fail closed
	}
	ip = ip.Unmap()
	if a.Kind == KindDNS {
		if len(names) == 0 {
			return false
		}
		// The resolver must be loopback (the container's own resolver) or inside
		// a declared internal CIDR. A private address that was not declared is
		// not trusted: it may be a resolver on a shared network (D-042).
		return !hasIP || ip.IsLoopback() || s.cidrIn(ip)
	}
	if !hasIP {
		return len(names) > 0
	}
	if syntheticRange.Contains(ip) {
		return len(names) > 0
	}
	return ip.IsLoopback() || s.cidrIn(ip)
}

// Mark returns a copy of attempts with InScope set by Contains.
func (s *Scope) Mark(attempts []EgressAttempt, targetHostname string) []EgressAttempt {
	out := slices.Clone(attempts)
	for i := range out {
		out[i].InScope = s.Contains(out[i], targetHostname)
	}
	return out
}

// String renders the scope for messages.
func (s *Scope) String() string {
	if s == nil {
		return "no scope file"
	}
	return fmt.Sprintf("%d internal names, %d internal CIDRs", len(s.InternalNames), len(s.InternalCIDRs))
}
