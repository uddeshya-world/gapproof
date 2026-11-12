package phonehome

import (
	"cmp"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"strings"
)

// A small PEP 440 subset for rule version bounds (D-036): parse a version
// and compare two of them in PEP 440's total order (as
// packaging.version.Version does). Specifiers are comma-separated clauses
// of <, <=, >, >=, == or != against a full version. ~=, ===, and ==X.*
// wildcards are rejected at load time.
//
// Clauses are evaluated with the total order only. PEP 440's specifier
// rule that "<1.5.4" excludes 1.5.4rc1 is deliberately not applied: an
// installed pre-release of the fixing version may not have the fix, so
// the rule fires (fail closed).

type pepVersion struct {
	epoch   *big.Int
	release []*big.Int // trailing zeros stripped: 1.0 == 1.0.0
	pre     int        // 0 none, else 'a', 'b', 'c' (rc)
	preN    *big.Int
	post    *big.Int // nil: no post segment
	dev     *big.Int // nil: no dev segment
	local   []string // lower-cased segments; numeric ones compare as numbers
}

// The canonical PEP 440 regex (Appendix B), case-insensitive.
var pep440Re = regexp.MustCompile(`(?i)^\s*v?` +
	`(?:([0-9]+)!)?` + // epoch
	`([0-9]+(?:\.[0-9]+)*)` + // release
	`(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?([0-9]+)?)?` + // pre
	`(?:-([0-9]+)|[-_.]?(post|rev|r)[-_.]?([0-9]+)?)?` + // post
	`(?:[-_.]?(dev)[-_.]?([0-9]+)?)?` + // dev
	`(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?` + // local
	`\s*$`)

// maxVersionLen bounds the work one version string can cause.
const maxVersionLen = 256

var errBadVersion = errors.New("not a PEP 440 version")

func num(s string) *big.Int {
	n, _ := new(big.Int).SetString(s, 10) // the regex guarantees digits
	return n
}

func parseVersion(s string) (pepVersion, error) {
	if len(s) > maxVersionLen {
		return pepVersion{}, errBadVersion
	}
	m := pep440Re.FindStringSubmatch(s)
	if m == nil {
		return pepVersion{}, errBadVersion
	}
	v := pepVersion{epoch: big.NewInt(0)}
	if m[1] != "" {
		v.epoch = num(m[1])
	}
	for p := range strings.SplitSeq(m[2], ".") {
		v.release = append(v.release, num(p))
	}
	for len(v.release) > 1 && v.release[len(v.release)-1].Sign() == 0 {
		v.release = v.release[:len(v.release)-1]
	}
	if m[3] != "" {
		switch strings.ToLower(m[3]) {
		case "a", "alpha":
			v.pre = 'a'
		case "b", "beta":
			v.pre = 'b'
		default: // c, rc, pre, preview
			v.pre = 'c'
		}
		v.preN = big.NewInt(0)
		if m[4] != "" {
			v.preN = num(m[4])
		}
	}
	switch {
	case m[5] != "":
		v.post = num(m[5])
	case m[6] != "":
		v.post = big.NewInt(0)
		if m[7] != "" {
			v.post = num(m[7])
		}
	}
	if m[8] != "" {
		v.dev = big.NewInt(0)
		if m[9] != "" {
			v.dev = num(m[9])
		}
	}
	if m[10] != "" {
		v.local = strings.FieldsFunc(strings.ToLower(m[10]), func(r rune) bool { return r == '-' || r == '_' || r == '.' })
	}
	return v, nil
}

// String is the normalised form.
func (v pepVersion) String() string {
	var b strings.Builder
	if v.epoch.Sign() != 0 {
		b.WriteString(v.epoch.String() + "!")
	}
	for i, r := range v.release {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(r.String())
	}
	if v.pre != 0 {
		b.WriteString(map[int]string{'a': "a", 'b': "b", 'c': "rc"}[v.pre] + v.preN.String())
	}
	if v.post != nil {
		b.WriteString(".post" + v.post.String())
	}
	if v.dev != nil {
		b.WriteString(".dev" + v.dev.String())
	}
	if len(v.local) > 0 {
		b.WriteString("+" + strings.Join(v.local, "."))
	}
	return b.String()
}

// cmpRelease compares release tuples, padding the shorter one with zeros.
func cmpRelease(a, b []*big.Int) int {
	for i := range max(len(a), len(b)) {
		x, y := big.NewInt(0), big.NewInt(0)
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if c := x.Cmp(y); c != 0 {
			return c
		}
	}
	return 0
}

// phase ranks the pre-release part: a dev-only release sorts before any
// pre-release, a final (or post) release after them all.
func (v pepVersion) phase() int {
	switch {
	case v.pre != 0:
		return v.pre // 'a' < 'b' < 'c'
	case v.post == nil && v.dev != nil:
		return 0
	}
	return 'z'
}

// cmpOpt compares optional numbers; nil sorts first when nilFirst.
func cmpOpt(a, b *big.Int, nilFirst bool) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return map[bool]int{true: -1, false: 1}[nilFirst]
	case b == nil:
		return map[bool]int{true: 1, false: -1}[nilFirst]
	}
	return a.Cmp(b)
}

func cmpLocal(a, b []string) int {
	for i := range min(len(a), len(b)) {
		x, y := a[i], b[i]
		xn, xok := new(big.Int).SetString(x, 10)
		yn, yok := new(big.Int).SetString(y, 10)
		var c int
		switch {
		case xok && yok:
			c = xn.Cmp(yn)
		case xok: // numeric segments sort after alphanumeric ones
			c = 1
		case yok:
			c = -1
		default:
			c = strings.Compare(x, y)
		}
		if c != 0 {
			return c
		}
	}
	return cmp.Compare(len(a), len(b))
}

// compareVersions is PEP 440's total order.
func compareVersions(a, b pepVersion) int {
	if c := a.epoch.Cmp(b.epoch); c != 0 {
		return c
	}
	if c := cmpRelease(a.release, b.release); c != 0 {
		return c
	}
	if c := cmp.Compare(a.phase(), b.phase()); c != 0 {
		return c
	}
	if a.pre != 0 {
		if c := a.preN.Cmp(b.preN); c != 0 {
			return c
		}
	}
	if c := cmpOpt(a.post, b.post, true); c != 0 {
		return c
	}
	if c := cmpOpt(a.dev, b.dev, false); c != 0 {
		return c
	}
	return cmpLocal(a.local, b.local)
}

type clause struct {
	op string
	v  pepVersion
}

// VersionSpec is a parsed comma-separated specifier: every clause must hold.
type VersionSpec []clause

var specOps = []string{"<=", ">=", "==", "!=", "<", ">"} // two-char operators first

const maxClauses = 16

// parseSpec parses "<1.5.4" or ">=0.4, <1.5.4".
func parseSpec(s string) (VersionSpec, error) {
	if strings.TrimSpace(s) == "" {
		return nil, errors.New("empty version specifier")
	}
	parts := strings.Split(s, ",")
	if len(parts) > maxClauses {
		return nil, fmt.Errorf("more than %d clauses", maxClauses)
	}
	var out VersionSpec
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, "~=") || strings.HasPrefix(p, "===") {
			return nil, fmt.Errorf("clause %q: only <, <=, >, >=, == and != are supported", p)
		}
		i := slices.IndexFunc(specOps, func(op string) bool { return strings.HasPrefix(p, op) })
		if i < 0 {
			return nil, fmt.Errorf("clause %q needs one of <, <=, >, >=, ==, !=", p)
		}
		op := specOps[i]
		rest := strings.TrimSpace(p[len(op):])
		if strings.HasSuffix(rest, ".*") {
			return nil, fmt.Errorf("clause %q: wildcards are not supported", p)
		}
		v, err := parseVersion(rest)
		if err != nil {
			return nil, fmt.Errorf("clause %q: %w", p, err)
		}
		out = append(out, clause{op, v})
	}
	return out, nil
}

// Contains reports whether version satisfies every clause. An unparseable
// version is reported as contained (ok=false): Gapproof fails closed.
func (s VersionSpec) Contains(version string) (in, ok bool) {
	v, err := parseVersion(version)
	if err != nil {
		return true, false
	}
	for _, c := range s {
		r := compareVersions(v, c.v)
		var hold bool
		switch c.op {
		case "<":
			hold = r < 0
		case "<=":
			hold = r <= 0
		case ">":
			hold = r > 0
		case ">=":
			hold = r >= 0
		case "==":
			hold = r == 0
		case "!=":
			hold = r != 0
		}
		if !hold {
			return false, true
		}
	}
	return true, true
}

func (s VersionSpec) String() string {
	parts := make([]string, len(s))
	for i, c := range s {
		parts[i] = c.op + c.v.String()
	}
	return strings.Join(parts, ",")
}
