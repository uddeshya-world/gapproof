package sinkhole

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// Config for a sinkhole run.
type Config struct {
	Events io.Writer // egress.log.jsonl lines (stdout in the harness)
	Pcap   io.Writer // optional: NFLOG packets as pcapng
	// Ready is called once listeners are up, before Run blocks.
	Ready func()
}

// Sinkhole holds the shared state of one run.
type Sinkhole struct {
	log   *Log
	synth *Synth
	flows *Flows
	pcap  *PcapNG

	mu      sync.Mutex
	seen    map[string]bool // dedupe keys for repeated UDP/ICMP lines
	slots   chan struct{}   // bounds concurrent TCP handlers
	timeout time.Duration
	wait    time.Duration // how long a listener waits for its NFLOG record
}

func newSinkhole(cfg Config) (*Sinkhole, error) {
	s := &Sinkhole{
		log: NewLog(cfg.Events), synth: NewSynth(), flows: NewFlows(),
		seen: map[string]bool{}, slots: make(chan struct{}, 256),
		timeout: 2 * time.Second, wait: 300 * time.Millisecond,
	}
	if cfg.Pcap != nil {
		p, err := NewPcapNG(cfg.Pcap)
		if err != nil {
			return nil, err
		}
		s.pcap = p
	}
	return s, nil
}

func (s *Sinkhole) first(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen[key] || len(s.seen) > 1<<16 {
		return false
	}
	s.seen[key] = true
	return true
}

// onPacket handles one NFLOG record: it's the source of truth for every new
// flow's original destination, and the only source for ICMP and other
// protocols.
func (s *Sinkhole) onPacket(t time.Time, payload []byte, origLen int) {
	if s.pcap != nil {
		s.pcap.Write(t, payload, origLen)
	}
	f, ok := ParseIPv4(payload)
	if !ok {
		return
	}
	s.flows.Add(f, t)
	e := Event{Time: t, Kind: KindFlow, Proto: f.Proto, OrigDstIP: f.Dst.String(), Port: f.DstPort, SrcPort: f.SrcPort}
	if IsSynthetic(f.Dst) {
		e.Name = s.synth.Name(f.Dst)
	}
	s.log.Emit(e)
	switch f.Proto {
	case protoTCP, protoUDP:
		return // the listeners report these, enriched
	case protoICMP:
		if s.first("icmp|" + f.Dst.String() + "|" + itoa(f.ICMP)) {
			s.log.Emit(Event{Time: t, Kind: KindICMP, OrigDstIP: f.Dst.String(), Name: e.Name, Note: "icmp type " + itoa(f.ICMP)})
		}
	default:
		if s.first("ip|" + f.Dst.String() + "|" + itoa(f.Proto)) {
			s.log.Emit(Event{Time: t, Kind: KindIP, Proto: f.Proto, OrigDstIP: f.Dst.String(), Name: e.Name})
		}
	}
}

// handleDNS answers one query and logs it. orig is the resolver the target
// actually addressed (from NFLOG or SO_ORIGINAL_DST).
func (s *Sinkhole) handleDNS(msg []byte, orig netip.AddrPort, tcp bool) []byte {
	q, err := ParseQuery(msg)
	e := Event{Kind: KindDNS, OrigDstIP: addrStr(orig), Port: int(orig.Port()), ProtoHint: HintDNS}
	if tcp {
		e.Note = "dns over tcp"
	}
	if err != nil {
		e.ProtoHint = HintUnknown
		e.Note = "malformed dns query"
		s.log.Emit(e)
		return nil
	}
	e.Name, e.QType = q.Name, QTypeName(q.Type)
	s.log.Emit(e)
	return Answer(msg, q, s.synth)
}

// handleTCP logs one redirected connection from what it sends first.
func (s *Sinkhole) handleTCP(c net.Conn, dst netip.AddrPort, sport int) {
	defer c.Close()
	s.flows.Explain(protoTCP, dst.Addr(), int(dst.Port()), sport)
	e := Event{Kind: KindTCP, OrigDstIP: addrStr(dst), Port: int(dst.Port()), SrcPort: sport, ProtoHint: HintUnknown}
	if IsSynthetic(dst.Addr()) {
		e.Name = s.synth.Name(dst.Addr())
	}
	_ = c.SetReadDeadline(time.Now().Add(s.timeout))
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for len(buf) < cap(buf) {
		n, err := c.Read(tmp[:cap(buf)-len(buf)])
		buf = append(buf, tmp[:n]...)
		if ch, ok := ParseClientHello(buf); ok && (ch.SNI != "" || tlsRecordComplete(buf)) {
			e.ProtoHint, e.SNI, e.ALPN = HintTLS, ch.SNI, ch.ALPN
			break
		}
		if h, ok := ParseHTTPHost(buf); ok && (h != "" || headersComplete(buf)) {
			e.ProtoHint, e.HTTPHost = HintHTTP, h
			break
		}
		if err != nil {
			if len(buf) > 0 && buf[0] == 22 {
				ch, _ := ParseClientHello(buf)
				e.ProtoHint, e.SNI, e.ALPN = HintTLS, ch.SNI, ch.ALPN
			}
			break
		}
	}
	s.log.Emit(e)
}

func tlsRecordComplete(b []byte) bool {
	return len(b) >= 5 && len(b) >= 5+int(binary.BigEndian.Uint16(b[3:]))
}

func headersComplete(b []byte) bool {
	for i := 0; i+3 < len(b); i++ {
		if b[i] == '\r' && b[i+1] == '\n' && b[i+2] == '\r' && b[i+3] == '\n' {
			return true
		}
	}
	return false
}

// handleUDP logs one datagram that reached the UDP catch-all. Never replies.
func (s *Sinkhole) handleUDP(p []byte, sport int) {
	f, ok := s.flows.Lookup(protoUDP, sport, s.wait)
	info := ClassifyUDP(p)
	e := Event{Kind: KindUDP, SrcPort: sport, ProtoHint: info.Hint, SNI: info.SNI, ALPN: info.ALPN}
	if ok {
		e.OrigDstIP, e.Port = f.Dst.String(), f.DstPort
		if IsSynthetic(f.Dst) {
			e.Name = s.synth.Name(f.Dst)
		}
	} else {
		e.Note = "original destination unknown (no NFLOG record)"
	}
	if s.first("udp|" + e.OrigDstIP + "|" + itoa(e.Port) + "|" + itoa(sport) + "|" + e.ProtoHint + "|" + e.SNI) {
		s.log.Emit(e)
	}
}

// finish reports flows NFLOG saw that no listener explained, and stats.
func (s *Sinkhole) finish(overruns int) {
	for _, f := range s.flows.Unexplained() {
		kind := KindTCP
		if f.Proto == protoUDP {
			kind = KindUDP
		}
		s.log.Emit(Event{Kind: kind, OrigDstIP: f.Dst.String(), Port: f.DstPort, SrcPort: f.SrcPort,
			Name: s.synth.Name(f.Dst), ProtoHint: HintUnknown, Note: "seen by NFLOG only (no listener record)"})
	}
	note := ""
	if overruns > 0 {
		note = "NFLOG overruns: " + itoa(overruns) + " batches of log records were dropped by the kernel; coverage is incomplete"
	}
	s.log.Emit(Event{Kind: KindStats, Note: note})
}

func addrStr(a netip.AddrPort) string {
	if !a.IsValid() {
		return ""
	}
	return a.Addr().String()
}

func itoa(n int) string { return strconv.Itoa(n) }
