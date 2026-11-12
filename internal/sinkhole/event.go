// Package sinkhole owns the egress harness's network namespace (spec §3.1).
// It programs the netns (dummy default route, NFLOG logging, redirects to
// local catch-alls, default deny), drops privileges, and then logs every
// attempt the target makes to reach anything outside its own loopback:
// DNS queries, TCP connects (with TLS SNI/ALPN or HTTP Host), UDP datagrams
// (classified) and every other new flow seen by NFLOG (ICMP and the rest).
//
// It never dials out, never completes TLS, never proxies and never replies
// to UDP other than DNS. Everything it parses comes from the target and is
// treated as hostile (CLAUDE.md rule 3): bounded reads, deadlines, no
// allocation driven by attacker-supplied lengths beyond fixed caps.
package sinkhole

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Kinds of egress attempt.
const (
	KindDNS  = "dns"
	KindTCP  = "tcp"
	KindUDP  = "udp"
	KindICMP = "icmp"
	KindIP   = "ip" // any other IP protocol (GRE, SCTP, raw...)
	// KindFlow lines are raw NFLOG records. They are the audit trail and the
	// correlation source; the evidence set is built from the other kinds.
	KindFlow = "flow"
	// KindReady and KindStats are control lines, not attempts.
	KindReady = "ready"
	KindStats = "stats"
)

// Proto hints.
const (
	HintTLS     = "tls"
	HintHTTP    = "http"
	HintQUIC    = "quic"
	HintNTP     = "ntp"
	HintStatsd  = "statsd"
	HintSyslog  = "syslog"
	HintDNS     = "dns"
	HintUnknown = "unknown"
)

// Event is one line of egress.log.jsonl. Field names follow spec §3.1.
type Event struct {
	Time      time.Time `json:"time"`
	Kind      string    `json:"kind"`
	Name      string    `json:"name,omitempty"`  // DNS name queried, or the name behind a synthetic IP
	QType     string    `json:"qtype,omitempty"` // DNS only
	OrigDstIP string    `json:"orig_dst_ip,omitempty"`
	Port      int       `json:"port,omitempty"`
	Proto     int       `json:"ip_proto,omitempty"` // KindFlow/KindIP: IP protocol number
	SrcPort   int       `json:"src_port,omitempty"`
	ProtoHint string    `json:"proto_hint,omitempty"`
	SNI       string    `json:"sni,omitempty"`
	ALPN      []string  `json:"alpn,omitempty"`
	HTTPHost  string    `json:"http_host,omitempty"`
	Note      string    `json:"note,omitempty"`
}

// Log serialises events as JSON lines. It is safe for concurrent use.
type Log struct {
	mu  sync.Mutex
	enc *json.Encoder
	now func() time.Time
	n   map[string]int
}

// NewLog writes JSON lines to w.
func NewLog(w io.Writer) *Log {
	return &Log{enc: json.NewEncoder(w), now: time.Now, n: map[string]int{}}
}

// Emit stamps (if unset) and writes e.
func (l *Log) Emit(e Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e.Time.IsZero() {
		e.Time = l.now().UTC()
	}
	l.n[e.Kind]++
	_ = l.enc.Encode(e) // stdout write failure: nothing better to do than keep going
}

// Counts returns the number of events emitted per kind.
func (l *Log) Counts() map[string]int {
	l.mu.Lock()
	defer l.mu.Unlock()
	c := make(map[string]int, len(l.n))
	for k, v := range l.n {
		c[k] = v
	}
	return c
}
