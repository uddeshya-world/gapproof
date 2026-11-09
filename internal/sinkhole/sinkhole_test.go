package sinkhole

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/uddeshya-world/gapproof/internal/testutil/quicinit"
)

func dnsQuery(name string, qtype uint16) []byte {
	m := []byte{0xab, 0xcd, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		m = append(m, byte(len(l)))
		m = append(m, l...)
	}
	m = append(m, 0)
	m = binary.BigEndian.AppendUint16(m, qtype)
	return binary.BigEndian.AppendUint16(m, 1)
}

func TestDNSAnswer(t *testing.T) {
	s := NewSynth()
	for _, tc := range []struct {
		name    string
		qtype   uint16
		rcode   uint16
		ancount uint16
		ip      string
	}{
		{"Example.COM", qtypeA, 0, 1, "198.18.0.1"},
		{"example.com", qtypeA, 0, 1, "198.18.0.1"}, // stable per name
		{"api.openai.com", qtypeA, 0, 1, "198.18.0.2"},
		{"example.com", qtypeAAAA, 0, 0, ""}, // NODATA
		{"example.com", 16, 3, 0, ""},        // TXT -> NXDOMAIN
	} {
		m := dnsQuery(tc.name, tc.qtype)
		q, err := ParseQuery(m)
		if err != nil {
			t.Fatal(err)
		}
		r := Answer(m, q, s)
		if binary.BigEndian.Uint16(r) != 0xabcd || r[2]&0x80 == 0 {
			t.Fatalf("%s: bad header %x", tc.name, r[:4])
		}
		if rc := binary.BigEndian.Uint16(r[2:]) & 0xf; rc != tc.rcode {
			t.Errorf("%s/%d: rcode %d want %d", tc.name, tc.qtype, rc, tc.rcode)
		}
		if an := binary.BigEndian.Uint16(r[6:]); an != tc.ancount {
			t.Errorf("%s/%d: ancount %d want %d", tc.name, tc.qtype, an, tc.ancount)
		}
		if tc.ip != "" {
			got := netip.AddrFrom4([4]byte(r[len(r)-4:])).String()
			if got != tc.ip {
				t.Errorf("%s: A = %s want %s", tc.name, got, tc.ip)
			}
		}
	}
	if s.Name(netip.MustParseAddr("198.18.0.2")) != "api.openai.com" {
		t.Error("reverse mapping")
	}
}

func TestParseQueryRejects(t *testing.T) {
	good := dnsQuery("a.b", 1)
	resp := append([]byte(nil), good...)
	resp[2] |= 0x80
	ptr := append(append([]byte(nil), good[:12]...), 0xc0, 0x0c, 0, 1, 0, 1)
	long := []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for i := 0; i < 5; i++ {
		long = append(long, 63)
		long = append(long, bytes.Repeat([]byte{'a'}, 63)...)
	}
	long = append(long, 0, 0, 1, 0, 1)
	for name, m := range map[string][]byte{
		"short": good[:10], "response": resp, "pointer": ptr, "too long": long,
		"truncated label": good[:14], "no type": good[:len(good)-3],
	} {
		if _, err := ParseQuery(m); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	q, err := ParseQuery(append(append(good[:12:12], 3, 'a', 0x01, '\n', 0), 0, 1, 0, 1))
	if err != nil || q.Name != `a\001\010` {
		t.Errorf("control chars not escaped: %q %v", q.Name, err)
	}
	if QTypeName(99) != "TYPE99" || QTypeName(65) != "HTTPS" {
		t.Error("QTypeName")
	}
}

func TestClientHelloAndHTTP(t *testing.T) {
	hello := quicinit.ClientHello("api.openai.com", []string{"h2", "http/1.1"})
	rec := append([]byte{22, 3, 1, byte(len(hello) >> 8), byte(len(hello))}, hello...)
	ch, ok := ParseClientHello(rec)
	if !ok || ch.SNI != "api.openai.com" || strings.Join(ch.ALPN, ",") != "h2,http/1.1" {
		t.Fatalf("got %+v %v", ch, ok)
	}
	if !tlsRecordComplete(rec) || tlsRecordComplete(rec[:20]) {
		t.Error("tlsRecordComplete")
	}
	for i := range rec { // truncation never panics
		ParseClientHello(rec[:i])
	}
	if _, ok := ParseClientHello([]byte("GET / HTTP/1.1\r\n")); ok {
		t.Error("HTTP parsed as TLS")
	}
	h, ok := ParseHTTPHost([]byte("POST /e HTTP/1.1\r\nUser-Agent: x\r\nhost:  telemetry.example \r\n\r\n"))
	if !ok || h != "telemetry.example" {
		t.Errorf("host %q %v", h, ok)
	}
	if _, ok := ParseHTTPHost([]byte("SSH-2.0-x\r\n")); ok {
		t.Error("ssh parsed as http")
	}
	if h, ok := ParseHTTPHost([]byte("GET / HTTP/1.0\r\n\r\n")); !ok || h != "" {
		t.Error("no host")
	}
	if !headersComplete([]byte("a\r\n\r\n")) || headersComplete([]byte("a\r\n")) {
		t.Error("headersComplete")
	}
	if printable("a\x00\\b") != `a\x00\x5cb` {
		t.Errorf("printable: %q", printable("a\x00\\b"))
	}
}

func TestClassifyUDP(t *testing.T) {
	ntp := make([]byte, 48)
	ntp[0] = 0x23
	q := quicinit.Packet([]byte{9, 8, 7, 6, 5, 4, 3, 2}, "one.one.one.one", []string{"h3"})
	bad := append([]byte(nil), q...)
	bad[len(bad)-1] ^= 1 // auth tag broken: still QUIC, no SNI
	for name, tc := range map[string]struct {
		p    []byte
		hint string
		sni  string
	}{
		"quic":      {q, HintQUIC, "one.one.one.one"},
		"quic-bad":  {bad, HintQUIC, ""},
		"ntp":       {ntp, HintNTP, ""},
		"statsd":    {[]byte("a.b:1|c\nx:2.5|ms|@0.1\n"), HintStatsd, ""},
		"dogstatsd": {[]byte("page.views:1|c|#env:prod"), HintStatsd, ""},
		"syslog":    {[]byte("<34>Oct 11 22:14:15 host app: hi"), HintSyslog, ""},
		"dns":       {dnsQuery("x.y", 1), HintDNS, ""},
		"unknown":   {[]byte{1, 2, 3}, HintUnknown, ""},
	} {
		got := ClassifyUDP(tc.p)
		if got.Hint != tc.hint || got.SNI != tc.sni {
			t.Errorf("%s: got %+v want %s/%s", name, got, tc.hint, tc.sni)
		}
	}
	for i := 0; i < len(q); i += 7 {
		ClassifyUDP(q[:i]) // no panics on truncation
	}
}

func TestParseIPv4(t *testing.T) {
	p := make([]byte, 28)
	p[0], p[9] = 0x45, protoUDP
	copy(p[12:], []byte{10, 0, 0, 2})
	copy(p[16:], []byte{8, 8, 8, 8})
	binary.BigEndian.PutUint16(p[20:], 40000)
	binary.BigEndian.PutUint16(p[22:], 123)
	f, ok := ParseIPv4(p)
	if !ok || f.Dst.String() != "8.8.8.8" || f.DstPort != 123 || f.SrcPort != 40000 {
		t.Fatalf("%+v", f)
	}
	p[9] = protoICMP
	p[20] = 8
	if f, _ := ParseIPv4(p); f.ICMP != 8 {
		t.Error("icmp type")
	}
	binary.BigEndian.PutUint16(p[6:], 5) // non-first fragment
	if f, _ := ParseIPv4(p); f.DstPort != 0 || f.ICMP != 0 {
		t.Error("fragment")
	}
	for _, b := range [][]byte{nil, p[:19], {0x65}, append([]byte{0x4f}, p[1:]...)} {
		if _, ok := ParseIPv4(b); ok {
			t.Errorf("accepted %x", b)
		}
	}
}

func TestSinkholeHandlers(t *testing.T) {
	var out bytes.Buffer
	var pcap bytes.Buffer
	s, err := newSinkhole(Config{Events: &out, Pcap: &pcap})
	if err != nil {
		t.Fatal(err)
	}
	s.wait = 50 * time.Millisecond
	now := time.Unix(1700000000, 0).UTC()
	pkt := func(proto byte, dst [4]byte, sport, dport int) []byte {
		p := make([]byte, 28)
		p[0], p[9] = 0x45, proto
		copy(p[16:], dst[:])
		binary.BigEndian.PutUint16(p[20:], uint16(sport))
		binary.BigEndian.PutUint16(p[22:], uint16(dport))
		return p
	}
	// DNS via NFLOG-correlated UDP, then a TCP connect to the synthetic IP.
	s.onPacket(now, pkt(protoUDP, [4]byte{8, 8, 8, 8}, 5000, 53), 28)
	resp := s.handleDNS(dnsQuery("api.openai.com", 1), netip.MustParseAddrPort("8.8.8.8:53"), false)
	if len(resp) == 0 {
		t.Fatal("no dns response")
	}
	s.handleDNS([]byte{1, 2}, netip.AddrPort{}, true)
	s.onPacket(now, pkt(protoUDP, [4]byte{1, 1, 1, 1}, 6000, 443), 28)
	s.handleUDP(quicinit.Packet([]byte{1, 2, 3, 4}, "one.one.one.one", nil), 6000)
	s.handleUDP([]byte("x:1|c"), 6000) // duplicate key suppressed? different hint -> logged
	s.handleUDP([]byte("x:1|c"), 6000) // exact duplicate suppressed
	s.handleUDP([]byte{0}, 7777)       // no NFLOG record
	s.onPacket(now, pkt(protoICMP, [4]byte{1, 1, 1, 1}, 0x0800, 0), 28)
	s.onPacket(now, pkt(protoICMP, [4]byte{1, 1, 1, 1}, 0x0800, 0), 28)
	s.onPacket(now, pkt(47, [4]byte{9, 9, 9, 9}, 0, 0), 28) // GRE
	s.onPacket(now, pkt(protoTCP, [4]byte{198, 18, 0, 1}, 7000, 443), 28)
	s.onPacket(now, pkt(protoTCP, [4]byte{5, 5, 5, 5}, 7001, 25), 28) // never reaches a listener
	s.onPacket(now, []byte{0x60}, 1)                                  // not IPv4: pcap only
	s.flows.Explain(protoTCP, netip.MustParseAddr("198.18.0.1"), 443, 7000)
	s.finish(2)

	var evs []Event
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var e Event
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			t.Fatal(err)
		}
		evs = append(evs, e)
	}
	count := func(f func(Event) bool) int {
		n := 0
		for _, e := range evs {
			if f(e) {
				n++
			}
		}
		return n
	}
	checks := map[string]int{
		"dns api.openai.com via 8.8.8.8": count(func(e Event) bool { return e.Kind == KindDNS && e.Name == "api.openai.com" && e.OrigDstIP == "8.8.8.8" }),
		"malformed dns":                  count(func(e Event) bool { return e.Kind == KindDNS && e.Note == "malformed dns query" }),
		"quic with sni":                  count(func(e Event) bool { return e.Kind == KindUDP && e.SNI == "one.one.one.one" && e.OrigDstIP == "1.1.1.1" }),
		"statsd once":                    count(func(e Event) bool { return e.Kind == KindUDP && e.ProtoHint == HintStatsd }),
		"udp unknown dst":                count(func(e Event) bool { return e.Kind == KindUDP && strings.Contains(e.Note, "unknown") }),
		"icmp once":                      count(func(e Event) bool { return e.Kind == KindICMP }),
		"gre":                            count(func(e Event) bool { return e.Kind == KindIP && e.Proto == 47 }),
		"unexplained tcp:25":             count(func(e Event) bool { return e.Kind == KindTCP && e.Port == 25 && strings.Contains(e.Note, "NFLOG only") }),
		"explained tcp not reported":     1 - count(func(e Event) bool { return e.Kind == KindTCP && e.Port == 443 }),
		"overrun noted":                  count(func(e Event) bool { return e.Kind == KindStats && strings.Contains(e.Note, "overruns: 2") }),
		"synthetic name on flow":         count(func(e Event) bool { return e.Kind == KindFlow && e.Name == "api.openai.com" }),
	}
	for k, n := range checks {
		if n != 1 {
			t.Errorf("%s: %d events, want 1", k, n)
		}
	}
	if s.log.Counts()[KindFlow] != 7 {
		t.Errorf("flow lines: %v", s.log.Counts())
	}
	if pcap.Len() < 28+20+7*(32+28) {
		t.Errorf("pcap too small: %d", pcap.Len())
	}
	if binary.LittleEndian.Uint32(pcap.Bytes()) != 0x0a0d0d0a {
		t.Error("pcapng magic")
	}
}

func TestSynthExhaustion(t *testing.T) {
	s := NewSynth()
	s.next = synthSize - 2
	a := s.Addr("one")
	b := s.Addr("two")
	if a != b || !IsSynthetic(a) {
		t.Errorf("exhausted allocator should reuse the last address: %v %v", a, b)
	}
}

func TestFlowsLookupWaits(t *testing.T) {
	f := NewFlows()
	go func() {
		time.Sleep(20 * time.Millisecond)
		f.Add(Flow{Proto: protoUDP, SrcPort: 9, Dst: netip.MustParseAddr("1.2.3.4"), DstPort: 53}, time.Now())
	}()
	got, ok := f.Lookup(protoUDP, 9, time.Second)
	if !ok || got.DstPort != 53 {
		t.Fatal("lookup should wait for the NFLOG record")
	}
	if _, ok := f.Lookup(protoUDP, 10, 30*time.Millisecond); ok {
		t.Fatal("unknown flow")
	}
	if len(f.Unexplained()) != 0 {
		t.Error("looked-up flow is explained")
	}
}
