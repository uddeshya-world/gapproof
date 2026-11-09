package sinkhole

import (
	"net/netip"
	"strings"
	"sync"
)

// Synth hands out per-name synthetic IPv4 addresses from 198.18.0.0/15
// (RFC 2544 benchmarking space, never routed). The first name gets
// 198.18.0.1, the next 198.18.0.2, and so on; a name keeps its address for
// the whole run so later connections can be attributed back to it.
type Synth struct {
	mu     sync.Mutex
	byName map[string]netip.Addr
	byAddr map[netip.Addr]string
	next   uint32
}

const (
	synthBase = 198<<24 | 18<<16 // 198.18.0.0
	synthSize = 1 << 17          // /15
	// maxNames caps memory if a target floods random names; once reached,
	// new names share the last address (still logged by name).
	maxNames = 65536
)

// NewSynth returns an empty allocator.
func NewSynth() *Synth {
	return &Synth{byName: map[string]netip.Addr{}, byAddr: map[netip.Addr]string{}, next: 1}
}

// Addr returns the synthetic address for name (case-insensitive, no trailing dot).
func (s *Synth) Addr(name string) netip.Addr {
	name = canonName(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.byName[name]; ok {
		return a
	}
	if len(s.byName) >= maxNames || s.next >= synthSize-1 {
		return u32Addr(synthBase + s.next - 1)
	}
	a := u32Addr(synthBase + s.next)
	s.next++
	s.byName[name] = a
	s.byAddr[a] = name
	return a
}

// Name returns the name behind a synthetic address, if any.
func (s *Synth) Name(a netip.Addr) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byAddr[a]
}

// IsSynthetic reports whether a is inside 198.18.0.0/15.
func IsSynthetic(a netip.Addr) bool {
	return netip.MustParsePrefix("198.18.0.0/15").Contains(a)
}

func u32Addr(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func canonName(n string) string { return strings.TrimSuffix(strings.ToLower(n), ".") }
