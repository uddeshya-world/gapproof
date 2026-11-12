package sinkhole

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"regexp"
	"slices"
)

// UDPInfo is the classification of one UDP datagram.
type UDPInfo struct {
	Hint string
	SNI  string
	ALPN []string
}

var (
	statsdLine = regexp.MustCompile(`^[^:\s|]+:[^|\s]+\|(c|g|ms|h|s|d)(\|[^\s]*)?$`)
	syslogHead = regexp.MustCompile(`^<[0-9]{1,3}>`)
)

// ClassifyUDP guesses the protocol of a datagram from its bytes (spec §3.1:
// QUIC Initial with SNI, NTP, statsd/DogStatsD, syslog, DNS). Cheap, bounded
// and never trusted for anything but a label.
func ClassifyUDP(p []byte) UDPInfo {
	if ch, ok := quicInitialHello(p); ok {
		return UDPInfo{Hint: HintQUIC, SNI: ch.SNI, ALPN: ch.ALPN}
	}
	if isQUICLongHeader(p) {
		return UDPInfo{Hint: HintQUIC}
	}
	if len(p) >= 48 && p[0]&7 == 3 && (p[0]>>3)&7 >= 1 && (p[0]>>3)&7 <= 4 {
		return UDPInfo{Hint: HintNTP}
	}
	if _, err := ParseQuery(p); err == nil {
		return UDPInfo{Hint: HintDNS}
	}
	if syslogHead.Match(p) {
		return UDPInfo{Hint: HintSyslog}
	}
	if len(p) > 0 && len(p) <= 8192 {
		lines := bytes.Split(bytes.TrimRight(p, "\n"), []byte("\n"))
		all := true
		for _, l := range lines {
			if !statsdLine.Match(l) {
				all = false
				break
			}
		}
		if all {
			return UDPInfo{Hint: HintStatsd}
		}
	}
	return UDPInfo{Hint: HintUnknown}
}

func isQUICLongHeader(p []byte) bool {
	return len(p) >= 7 && p[0]&0xc0 == 0xc0 && binary.BigEndian.Uint32(p[1:]) != 0
}

// QUIC v1 Initial salt (RFC 9001 §5.2). These keys are public by design:
// anyone on path can read a client Initial, which is what we do here.
var quicV1Salt = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}

// quicInitialHello decrypts a QUIC v1 client Initial (RFC 9000 §17.2.2,
// RFC 9001 §5) and parses the ClientHello in its CRYPTO frames.
func quicInitialHello(p []byte) (ClientHello, bool) {
	if len(p) < 7 || p[0]&0xf0 != 0xc0 || binary.BigEndian.Uint32(p[1:]) != 1 {
		return ClientHello{}, false // not a v1 long-header Initial
	}
	r := reader(p[5:])
	dcid := r.bytes(int(r.u8()))
	if len(dcid) > 20 {
		return ClientHello{}, false
	}
	r.skip(int(r.u8())) // SCID
	tokLen, ok := r.varint()
	if !ok {
		return ClientHello{}, false
	}
	r.skip(int(min(tokLen, uint64(len(p)))))
	length, ok := r.varint()
	if !ok || r == nil {
		return ClientHello{}, false
	}
	pnOff := len(p) - len(r)
	if length > uint64(len(r)) || length < 20 || pnOff+4+16 > len(p) {
		return ClientHello{}, false
	}
	key, iv, hp, err := quicClientKeys(dcid)
	if err != nil {
		return ClientHello{}, false
	}
	hb, err := aes.NewCipher(hp)
	if err != nil {
		return ClientHello{}, false
	}
	mask := make([]byte, 16)
	hb.Encrypt(mask, p[pnOff+4:pnOff+4+16])
	hdr := slices.Clone(p[:pnOff+4])
	hdr[0] ^= mask[0] & 0x0f
	pnLen := int(hdr[0]&3) + 1
	var pn uint64
	for i := 0; i < pnLen; i++ {
		hdr[pnOff+i] ^= mask[1+i]
		pn = pn<<8 | uint64(hdr[pnOff+i])
	}
	hdr = hdr[:pnOff+pnLen]
	end := pnOff + int(length)
	if end > len(p) {
		return ClientHello{}, false
	}
	nonce := slices.Clone(iv)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return ClientHello{}, false
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return ClientHello{}, false
	}
	plain, err := aead.Open(nil, nonce, p[pnOff+pnLen:end], hdr)
	if err != nil {
		return ClientHello{}, false
	}
	return parseHandshakeClientHello(cryptoStream(plain))
}

// cryptoStream reassembles the contiguous-from-zero CRYPTO frame data of
// one packet (frames may arrive out of order, as Chrome sends them).
func cryptoStream(plain []byte) []byte {
	type chunk struct {
		off  uint64
		data []byte
	}
	var chunks []chunk
	r := reader(plain)
	for len(r) > 0 && len(chunks) < 64 {
		switch t := r.u8(); t {
		case 0x00, 0x01: // PADDING, PING
		case 0x06: // CRYPTO
			off, ok1 := r.varint()
			n, ok2 := r.varint()
			if !ok1 || !ok2 || n > uint64(len(r)) {
				r = nil
				break
			}
			chunks = append(chunks, chunk{off, r.bytes(int(n))})
		default:
			r = nil // ACK etc. don't appear before CRYPTO in a client's first Initial; stop
		}
	}
	slices.SortFunc(chunks, func(a, b chunk) int { return int(min(a.off, 1<<30)) - int(min(b.off, 1<<30)) })
	var out []byte
	for _, c := range chunks {
		if c.off > uint64(len(out)) {
			break
		}
		if end := c.off + uint64(len(c.data)); end > uint64(len(out)) {
			out = append(out, c.data[uint64(len(out))-c.off:]...)
		}
	}
	return out
}

func quicClientKeys(dcid []byte) (key, iv, hp []byte, err error) {
	initial, err := hkdf.Extract(sha256.New, dcid, quicV1Salt)
	if err != nil {
		return nil, nil, nil, err
	}
	client, err := expandLabel(initial, "client in", 32)
	if err != nil {
		return nil, nil, nil, err
	}
	if key, err = expandLabel(client, "quic key", 16); err != nil {
		return nil, nil, nil, err
	}
	if iv, err = expandLabel(client, "quic iv", 12); err != nil {
		return nil, nil, nil, err
	}
	hp, err = expandLabel(client, "quic hp", 16)
	return key, iv, hp, err
}

// expandLabel is TLS 1.3 HKDF-Expand-Label with an empty context.
func expandLabel(secret []byte, label string, n int) ([]byte, error) {
	full := "tls13 " + label
	info := []byte{byte(n >> 8), byte(n), byte(len(full))}
	info = append(info, full...)
	info = append(info, 0)
	return hkdf.Expand(sha256.New, secret, string(info), n)
}

// varint reads a QUIC variable-length integer (RFC 9000 §16).
func (r *reader) varint() (uint64, bool) {
	if len(*r) < 1 {
		return 0, false
	}
	n := 1 << ((*r)[0] >> 6)
	if len(*r) < n {
		*r = nil
		return 0, false
	}
	v := uint64((*r)[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64((*r)[i])
	}
	*r = (*r)[n:]
	return v, true
}
