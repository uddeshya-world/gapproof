package sinkhole

import (
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
)

// DNS record types the sinkhole answers specially.
const (
	qtypeA    = 1
	qtypeAAAA = 28
)

var qtypeNames = map[uint16]string{1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 64: "SVCB", 65: "HTTPS", 255: "ANY"}

// QTypeName renders a query type ("TYPE99" for unknown ones).
func QTypeName(t uint16) string {
	if n, ok := qtypeNames[t]; ok {
		return n
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// Question is the single question of a DNS query.
type Question struct {
	ID    uint16
	Flags uint16
	Name  string // lower-case, no trailing dot
	Type  uint16
	Class uint16
	end   int // offset just past the question
}

var errDNS = errors.New("malformed DNS query")

// ParseQuery parses a DNS query message (RFC 1035 §4.1). Only the first
// question is used; compression pointers are not allowed in a query name.
func ParseQuery(m []byte) (Question, error) {
	if len(m) < 12 {
		return Question{}, errDNS
	}
	q := Question{ID: binary.BigEndian.Uint16(m), Flags: binary.BigEndian.Uint16(m[2:])}
	if q.Flags&0x8000 != 0 || binary.BigEndian.Uint16(m[4:]) == 0 {
		return Question{}, errDNS // a response, or no question
	}
	var labels []string
	i, total := 12, 0
	for {
		if i >= len(m) {
			return Question{}, errDNS
		}
		l := int(m[i])
		i++
		if l == 0 {
			break
		}
		if l > 63 || i+l > len(m) {
			return Question{}, errDNS // >63 also rejects compression pointers
		}
		total += l + 1
		if total > 255 {
			return Question{}, errDNS
		}
		labels = append(labels, sanitizeLabel(m[i:i+l]))
		i += l
	}
	if i+4 > len(m) {
		return Question{}, errDNS
	}
	q.Name = strings.ToLower(strings.Join(labels, "."))
	q.Type = binary.BigEndian.Uint16(m[i:])
	q.Class = binary.BigEndian.Uint16(m[i+2:])
	q.end = i + 4
	return q, nil
}

// sanitizeLabel keeps a label printable: bytes outside visible ASCII become
// \DDD escapes (RFC 1035 master-file style), so a hostile name can't inject
// control characters into logs or reports.
func sanitizeLabel(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c > 0x20 && c < 0x7f && c != '\\' && c != '.' {
			sb.WriteByte(c)
			continue
		}
		sb.WriteString("\\" + leftPad(strconv.Itoa(int(c))))
	}
	return sb.String()
}

func leftPad(s string) string {
	for len(s) < 3 {
		s = "0" + s
	}
	return s
}

// Answer builds the sinkhole's response to q (whose raw message is m):
// A gets the synthetic address, AAAA gets NODATA (IPv6 is disabled in the
// netns), anything else gets NXDOMAIN. The question section is echoed.
func Answer(m []byte, q Question, synth *Synth) []byte {
	resp := make([]byte, 0, q.end+16)
	resp = append(resp, m[:q.end]...)
	// QR=1, opcode copied, AA=1, RD copied, RA=1.
	flags := uint16(0x8000) | q.Flags&0x7800 | 0x0400 | q.Flags&0x0100 | 0x0080
	ancount := uint16(0)
	switch q.Type {
	case qtypeA:
		if q.Class == 1 {
			ancount = 1
		}
	case qtypeAAAA:
	default:
		flags |= 3 // NXDOMAIN
	}
	binary.BigEndian.PutUint16(resp[2:], flags)
	binary.BigEndian.PutUint16(resp[4:], 1)
	binary.BigEndian.PutUint16(resp[6:], ancount)
	binary.BigEndian.PutUint16(resp[8:], 0)
	binary.BigEndian.PutUint16(resp[10:], 0)
	if ancount == 1 {
		a := synth.Addr(q.Name).As4()
		resp = append(resp, 0xc0, 12) // pointer to the question name
		resp = binary.BigEndian.AppendUint16(resp, qtypeA)
		resp = binary.BigEndian.AppendUint16(resp, 1)
		resp = binary.BigEndian.AppendUint32(resp, 60) // TTL
		resp = binary.BigEndian.AppendUint16(resp, 4)
		resp = append(resp, a[:]...)
	}
	return resp
}
