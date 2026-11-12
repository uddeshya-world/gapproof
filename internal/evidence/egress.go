package evidence

import (
	"cmp"
	"slices"
	"strconv"
	"strings"
)

// Egress attempt kinds (spec §3.1).
const (
	KindDNS  = "dns"
	KindTCP  = "tcp"
	KindUDP  = "udp"
	KindICMP = "icmp"
	KindIP   = "ip"
)

// RuleEgressAttempt is the finding for an observed out-of-scope attempt.
// It can't be waived (AGR_SPEC §4).
const RuleEgressAttempt = "EGRESS-ATTEMPT"

// EgressAttempt is one entry of the deduplicated egress set (spec §3.1).
// Per-attempt counts and timestamps live only in egress.log.jsonl (rule 6).
type EgressAttempt struct {
	Kind      string   `json:"kind"`
	Name      string   `json:"name,omitempty"`
	OrigDstIP string   `json:"orig_dst_ip,omitempty"`
	Port      int      `json:"port,omitempty"`
	ProtoHint string   `json:"proto_hint,omitempty"`
	SNI       string   `json:"sni,omitempty"`
	ALPN      []string `json:"alpn,omitempty"`
	HTTPHost  string   `json:"http_host,omitempty"`
	InScope   bool     `json:"in_scope"`
}

func (a EgressAttempt) ipOrName() string {
	if a.OrigDstIP != "" {
		return a.OrigDstIP
	}
	return a.Name
}

func compareAttempts(a, b EgressAttempt) int {
	return cmp.Or(
		cmp.Compare(a.Kind, b.Kind),
		cmp.Compare(a.Name, b.Name),
		cmp.Compare(a.ipOrName(), b.ipOrName()),
		cmp.Compare(a.Port, b.Port),
		cmp.Compare(a.SNI, b.SNI),
		cmp.Compare(a.HTTPHost, b.HTTPHost),
	)
}

// DedupeAttempts returns the attempt set keyed on (kind, name,
// orig_dst_ip-or-name, port, sni, http_host), sorted by that key. Entries
// that share a key are merged: ALPN values are unioned, the most specific
// proto hint wins (any known hint beats "unknown", ties go to the smallest),
// and the entry is in scope only if every merged attempt was (fail closed).
//
// A bare entry (no SNI, Host header or ALPN, hint unknown or empty) for the
// same kind, name, address and port as a detailed entry is folded into it.
// That is a connection cut before its first bytes, typically a telemetry
// flush killed at container stop and seen only by NFLOG; whether a target
// gets that far at teardown is a race, and it must not change the set.
func DedupeAttempts(in []EgressAttempt) []EgressAttempt {
	out := make([]EgressAttempt, 0, len(in))
	for _, a := range in {
		a.ALPN = slices.Clone(a.ALPN)
		out = append(out, a)
	}
	slices.SortStableFunc(out, compareAttempts)
	merged := out[:0]
	for _, a := range out {
		if n := len(merged); n > 0 && compareAttempts(merged[n-1], a) == 0 {
			m := &merged[n-1]
			m.ALPN = append(m.ALPN, a.ALPN...)
			m.ProtoHint = betterHint(m.ProtoHint, a.ProtoHint)
			m.InScope = m.InScope && a.InScope
			continue
		}
		merged = append(merged, a)
	}
	merged = foldBare(merged)
	for i := range merged {
		slices.Sort(merged[i].ALPN)
		merged[i].ALPN = slices.Compact(merged[i].ALPN)
		if len(merged[i].ALPN) == 0 {
			merged[i].ALPN = nil
		}
	}
	return merged
}

func isBare(a EgressAttempt) bool {
	return a.SNI == "" && a.HTTPHost == "" && len(a.ALPN) == 0 && (a.ProtoHint == "" || a.ProtoHint == "unknown")
}

func sameEndpoint(a, b EgressAttempt) bool {
	return a.Kind == b.Kind && a.Name == b.Name && a.ipOrName() == b.ipOrName() && a.Port == b.Port
}

// foldBare drops bare entries that a detailed entry for the same endpoint
// explains; the detailed entries inherit their scope (fail closed). in is
// sorted, so entries for one endpoint are adjacent.
func foldBare(in []EgressAttempt) []EgressAttempt {
	out := make([]EgressAttempt, 0, len(in))
	for i := 0; i < len(in); {
		j := i
		for j < len(in) && sameEndpoint(in[i], in[j]) {
			j++
		}
		group := in[i:j]
		detailed := slices.ContainsFunc(group, func(a EgressAttempt) bool { return !isBare(a) })
		scope := true
		for _, a := range group {
			scope = scope && a.InScope
		}
		for _, a := range group {
			if detailed && isBare(a) {
				continue
			}
			if detailed {
				a.InScope = scope
			}
			out = append(out, a)
		}
		i = j
	}
	return out
}

func betterHint(a, b string) string {
	rank := func(h string) int {
		switch h {
		case "":
			return 2
		case "unknown":
			return 1
		}
		return 0
	}
	if ra, rb := rank(a), rank(b); ra != rb {
		if ra < rb {
			return a
		}
		return b
	}
	return min(a, b)
}

// Destination is a short human description, e.g. "tcp api.example.com:443".
func (a EgressAttempt) Destination() string {
	host := a.Name
	if host == "" {
		host = a.SNI
	}
	if host == "" {
		host = hostOnly(a.HTTPHost)
	}
	if host == "" {
		host = a.OrigDstIP
	} else if a.OrigDstIP != "" && a.Kind != KindDNS {
		host += " (" + a.OrigDstIP + ")"
	}
	if host == "" {
		host = "(unknown destination)"
	}
	if a.Port != 0 && a.Kind != KindDNS {
		host += ":" + strconv.Itoa(a.Port)
	}
	return a.Kind + " " + host
}

// Detail encodes the attempt's identifying fields for Evidence.Detail, in a
// fixed order. Values from target traffic are quoted when they contain
// anything beyond hostname characters.
func (a EgressAttempt) Detail() string {
	var b strings.Builder
	add := func(k, v string) {
		if v == "" {
			return
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(quoteIfNeeded(v))
	}
	add("kind", a.Kind)
	add("name", a.Name)
	add("ip", a.OrigDstIP)
	if a.Port != 0 {
		add("port", strconv.Itoa(a.Port))
	}
	add("proto", a.ProtoHint)
	add("sni", a.SNI)
	add("alpn", strings.Join(a.ALPN, ","))
	add("host", a.HTTPHost)
	return b.String()
}

func quoteIfNeeded(s string) string {
	for _, r := range s {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			strings.ContainsRune(".-_:[]/,", r)
		if !ok {
			return strconv.Quote(s)
		}
	}
	return s
}

// EgressFindings turns every out-of-scope entry of the (deduplicated)
// attempt set into a high, unwaivable EGRESS-ATTEMPT finding. In-scope
// attempts are listed in the evidence but are not findings.
func EgressFindings(attempts []EgressAttempt) []Finding {
	var fs []Finding
	for _, a := range DedupeAttempts(attempts) {
		if a.InScope {
			continue
		}
		dest := a.Destination()
		fs = append(fs, Finding{
			Rule:     RuleEgressAttempt,
			Severity: High,
			Title:    "Out-of-scope egress attempt: " + dest,
			Explanation: "With all egress blocked, the target tried to reach a destination that is not " +
				"declared in the scope file. In an air-gapped network this request fails or leaks. " +
				"An observed attempt can't be waived (AGR_SPEC §4).",
			Evidence: Evidence{Detail: a.Detail()},
			Fix: "Disable or remove the code path that contacts " + dest +
				", or declare the destination in gapproof.scope.yaml if it is truly internal.",
			Controls: []string{"SC-7", "AC-4"},
		})
	}
	return fs
}
