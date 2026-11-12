package sinkhole

import (
	"encoding/binary"
	"net/netip"
)

// Flow is the 5-tuple of a packet's IPv4 header (from NFLOG).
type Flow struct {
	Proto   int
	Src     netip.Addr
	Dst     netip.Addr
	SrcPort int
	DstPort int
	ICMP    int // ICMP type, for proto 1
}

// IP protocol numbers.
const (
	protoICMP = 1
	protoTCP  = 6
	protoUDP  = 17
)

// ParseIPv4 reads the header of an IPv4 packet (as delivered by NFLOG,
// possibly truncated to the copy range).
func ParseIPv4(p []byte) (Flow, bool) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return Flow{}, false
	}
	ihl := int(p[0]&0x0f) * 4
	if ihl < 20 || ihl > len(p) {
		return Flow{}, false
	}
	f := Flow{
		Proto: int(p[9]),
		Src:   netip.AddrFrom4([4]byte(p[12:16])),
		Dst:   netip.AddrFrom4([4]byte(p[16:20])),
	}
	l4 := p[ihl:]
	fragOff := binary.BigEndian.Uint16(p[6:]) & 0x1fff
	if fragOff != 0 {
		return f, true // non-first fragment: no transport header
	}
	switch f.Proto {
	case protoTCP, protoUDP:
		if len(l4) >= 4 {
			f.SrcPort = int(binary.BigEndian.Uint16(l4))
			f.DstPort = int(binary.BigEndian.Uint16(l4[2:]))
		}
	case protoICMP:
		if len(l4) >= 1 {
			f.ICMP = int(l4[0])
		}
	}
	return f, true
}
