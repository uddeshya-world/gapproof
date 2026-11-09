package sinkhole

import (
	"testing"

	"github.com/uddeshya-world/gapproof/internal/testutil/quicinit"
)

// Hostile-input fuzzers (M8): none of these may panic or hang.
func FuzzParseQuery(f *testing.F) {
	f.Add(dnsQuery("example.com", 1))
	f.Add([]byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c})
	s := NewSynth()
	f.Fuzz(func(t *testing.T, b []byte) {
		if q, err := ParseQuery(b); err == nil {
			Answer(b, q, s)
		}
	})
}

func FuzzClientHello(f *testing.F) {
	h := quicinit.ClientHello("a.example", []string{"h2"})
	f.Add(append([]byte{22, 3, 1, byte(len(h) >> 8), byte(len(h))}, h...))
	f.Fuzz(func(t *testing.T, b []byte) {
		ParseClientHello(b)
		ParseHTTPHost(b)
	})
}

func FuzzClassifyUDP(f *testing.F) {
	f.Add(quicinit.Packet([]byte{1, 2, 3, 4, 5, 6, 7, 8}, "x.example", []string{"h3"}))
	f.Add([]byte("a:1|c"))
	f.Fuzz(func(t *testing.T, b []byte) {
		ClassifyUDP(b)
		ParseIPv4(b)
		cryptoStream(b)
	})
}
