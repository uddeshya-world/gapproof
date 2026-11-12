// Package quicinit builds a QUIC v1 client Initial packet carrying a
// ClientHello with a chosen SNI (RFC 9000 §17.2.2, RFC 9001 §5). Test-only:
// used by the sinkhole unit tests and the harness integration probe.
package quicinit

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
)

var salt = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}

// ClientHello returns a TLS 1.3 ClientHello handshake message (no record header).
func ClientHello(sni string, alpn []string) []byte {
	var ext []byte
	// server_name
	sn := append([]byte{0}, u16(len(sni))...)
	sn = append(sn, sni...)
	ext = append(ext, extension(0, append(u16(len(sn)), sn...))...)
	// ALPN
	var al []byte
	for _, p := range alpn {
		al = append(al, byte(len(p)))
		al = append(al, p...)
	}
	if len(alpn) > 0 {
		ext = append(ext, extension(16, append(u16(len(al)), al...))...)
	}
	ext = append(ext, extension(43, []byte{2, 3, 4})...) // supported_versions: TLS 1.3
	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // session id
	body = append(body, 0, 2, 0x13, 0x01)    // TLS_AES_128_GCM_SHA256
	body = append(body, 1, 0)                // compression
	body = append(body, u16(len(ext))...)
	body = append(body, ext...)
	return append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

// Packet returns a padded (1200-byte) protected client Initial.
func Packet(dcid []byte, sni string, alpn []string) []byte {
	hello := ClientHello(sni, alpn)
	frame := []byte{0x06, 0x00} // CRYPTO, offset 0
	frame = append(frame, varint2(len(hello))...)
	frame = append(frame, hello...)
	const pnLen = 4
	hdrLen := 1 + 4 + 1 + len(dcid) + 1 + 1 + 2 + pnLen
	payLen := 1200 - hdrLen - 16
	plain := append(frame, make([]byte, payLen-len(frame))...) // PADDING frames
	hdr := []byte{0xc0 | (pnLen - 1)}
	hdr = binary.BigEndian.AppendUint32(hdr, 1)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, 0, 0) // SCID len, token len
	hdr = append(hdr, varint2(pnLen+len(plain)+16)...)
	pnOff := len(hdr)
	hdr = append(hdr, 0, 0, 0, 0) // packet number 0

	key, iv, hp := keys(dcid)
	blk, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(blk)
	pkt := aead.Seal(append([]byte(nil), hdr...), iv, plain, hdr) // pn=0: nonce = iv
	hb, _ := aes.NewCipher(hp)
	mask := make([]byte, 16)
	hb.Encrypt(mask, pkt[pnOff+4:pnOff+20])
	pkt[0] ^= mask[0] & 0x0f
	for i := 0; i < pnLen; i++ {
		pkt[pnOff+i] ^= mask[1+i]
	}
	return pkt
}

func keys(dcid []byte) (key, iv, hp []byte) {
	init, _ := hkdf.Extract(sha256.New, dcid, salt)
	c := label(init, "client in", 32)
	return label(c, "quic key", 16), label(c, "quic iv", 12), label(c, "quic hp", 16)
}

func label(secret []byte, l string, n int) []byte {
	full := "tls13 " + l
	info := append([]byte{byte(n >> 8), byte(n), byte(len(full))}, full...)
	info = append(info, 0)
	out, _ := hkdf.Expand(sha256.New, secret, string(info), n)
	return out
}

func extension(t int, data []byte) []byte {
	return append(append(u16(t), u16(len(data))...), data...)
}

func u16(n int) []byte     { return []byte{byte(n >> 8), byte(n)} }
func varint2(n int) []byte { return []byte{0x40 | byte(n>>8), byte(n)} }
