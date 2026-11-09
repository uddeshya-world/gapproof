package sinkhole

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// ClientHello is what the sinkhole extracts from a TLS ClientHello.
type ClientHello struct {
	SNI  string
	ALPN []string
}

// ParseClientHello extracts SNI and ALPN from a TLS record carrying a
// ClientHello (possibly truncated: whatever parses is returned, ok reports
// whether it was a ClientHello at all). b is hostile; every length is
// bounds-checked against the slice.
func ParseClientHello(b []byte) (ch ClientHello, ok bool) {
	// TLS record header: type 22 (handshake), version, length.
	if len(b) < 5 || b[0] != 22 || b[1] != 3 {
		return ch, false
	}
	b = b[5:]
	return parseHandshakeClientHello(b)
}

// parseHandshakeClientHello parses a handshake message (type 1). Also used
// for the CRYPTO frame of a QUIC Initial, which carries it without a record.
func parseHandshakeClientHello(b []byte) (ch ClientHello, ok bool) {
	if len(b) < 4 || b[0] != 1 {
		return ch, false
	}
	r := reader(b[4:])
	r.skip(2 + 32) // legacy_version, random
	r.skip(int(r.u8()))
	r.skip(int(r.u16())) // cipher suites
	r.skip(int(r.u8()))  // compression
	ext := reader(r.bytes(int(r.u16())))
	for len(ext) >= 4 {
		typ := ext.u16()
		body := reader(ext.bytes(int(ext.u16())))
		switch typ {
		case 0: // server_name
			list := reader(body.bytes(int(body.u16())))
			for len(list) >= 3 {
				nt := list.u8()
				name := list.bytes(int(list.u16()))
				if nt == 0 && ch.SNI == "" {
					ch.SNI = printable(string(name))
				}
			}
		case 16: // ALPN
			list := reader(body.bytes(int(body.u16())))
			for len(list) > 0 && len(ch.ALPN) < 16 {
				p := list.bytes(int(list.u8()))
				ch.ALPN = append(ch.ALPN, printable(string(p)))
			}
		}
	}
	return ch, true
}

// ParseHTTPHost returns the Host header of an HTTP/1 request prefix.
func ParseHTTPHost(b []byte) (host string, ok bool) {
	line, rest, found := bytes.Cut(b, []byte("\n"))
	if !found {
		return "", false
	}
	f := strings.Fields(string(line))
	if len(f) != 3 || !strings.HasPrefix(f[2], "HTTP/1.") {
		return "", false
	}
	for len(rest) > 0 {
		var l []byte
		l, rest, _ = bytes.Cut(rest, []byte("\n"))
		l = bytes.TrimRight(l, "\r")
		if len(l) == 0 {
			break
		}
		k, v, ok := bytes.Cut(l, []byte(":"))
		if ok && strings.EqualFold(string(bytes.TrimSpace(k)), "host") {
			return printable(string(bytes.TrimSpace(v))), true
		}
	}
	return "", true
}

// printable caps and escapes attacker-supplied strings for logs and reports.
func printable(s string) string {
	const maxLen = 253
	var sb strings.Builder
	for i := 0; i < len(s) && sb.Len() < maxLen; i++ {
		c := s[i]
		if c >= 0x20 && c < 0x7f && c != '\\' {
			sb.WriteByte(c)
		} else {
			sb.WriteString("\\x" + string("0123456789abcdef"[c>>4]) + string("0123456789abcdef"[c&15]))
		}
	}
	return sb.String()
}

// reader is a bounds-checked big-endian cursor; reads past the end yield
// zeros/empty and leave it empty, so hostile lengths can't panic.
type reader []byte

func (r *reader) u8() uint8 {
	if len(*r) < 1 {
		*r = nil
		return 0
	}
	v := (*r)[0]
	*r = (*r)[1:]
	return v
}

func (r *reader) u16() uint16 {
	if len(*r) < 2 {
		*r = nil
		return 0
	}
	v := binary.BigEndian.Uint16(*r)
	*r = (*r)[2:]
	return v
}

func (r *reader) bytes(n int) []byte {
	if n > len(*r) {
		n = len(*r)
		v := *r
		*r = nil
		return v
	}
	v := (*r)[:n]
	*r = (*r)[n:]
	return v
}

func (r *reader) skip(n int) { r.bytes(n) }
