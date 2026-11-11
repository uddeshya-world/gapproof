package sinkhole

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

// Flows correlates NFLOG records (the source of truth for the original
// 5-tuple) with what the listeners see after REDIRECT, and remembers which
// flows a listener explained so the rest can be reported at shutdown.
type Flows struct {
	mu      sync.Mutex
	cond    *sync.Cond
	byPort  map[flowKey]*flowRec // (proto, src port) -> most recent
	all     []*flowRec
	maxKeep int
	// early holds explanations that arrived before their NFLOG record
	// (the TCP listener reads SO_ORIGINAL_DST and can win the race).
	early map[flowKey]earlyExpl
}

type earlyExpl struct {
	dst   netip.Addr
	dport int
}

type flowKey struct{ proto, sport int }

type flowRec struct {
	Flow
	seen      time.Time
	explained bool
}

// NewFlows returns an empty table.
func NewFlows() *Flows {
	f := &Flows{byPort: map[flowKey]*flowRec{}, maxKeep: 1 << 16, early: map[flowKey]earlyExpl{}}
	f.cond = sync.NewCond(&f.mu)
	return f
}

// Add records a new flow from NFLOG.
func (f *Flows) Add(fl Flow, t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := &flowRec{Flow: fl, seen: t}
	if fl.Proto == protoTCP || fl.Proto == protoUDP {
		k := flowKey{fl.Proto, fl.SrcPort}
		f.byPort[k] = r
		if e, ok := f.early[k]; ok {
			delete(f.early, k)
			r.explained = e.dst == fl.Dst && e.dport == fl.DstPort
		}
	}
	if len(f.all) < f.maxKeep {
		f.all = append(f.all, r)
	}
	f.cond.Broadcast()
}

// Lookup returns the original destination of the flow with this protocol
// and source port, waiting up to wait for the NFLOG record to arrive (the
// listener can win the race against the netlink reader). It marks the flow
// explained.
func (f *Flows) Lookup(proto, sport int, wait time.Duration) (Flow, bool) {
	deadline := time.Now().Add(wait)
	f.mu.Lock()
	defer f.mu.Unlock()
	for {
		if r, ok := f.byPort[flowKey{proto, sport}]; ok {
			r.explained = true
			return r.Flow, true
		}
		if time.Now().After(deadline) {
			return Flow{}, false
		}
		t := time.AfterFunc(10*time.Millisecond, f.cond.Broadcast)
		f.cond.Wait()
		t.Stop()
	}
}

// Explain marks the TCP/UDP flow with this destination and source port as
// accounted for by a listener (TCP uses SO_ORIGINAL_DST, not Lookup). If
// the NFLOG record hasn't arrived yet, the explanation is held and applied
// when it does.
func (f *Flows) Explain(proto int, dst netip.Addr, dport, sport int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := flowKey{proto, sport}
	if r, ok := f.byPort[k]; ok && r.Dst == dst && r.DstPort == dport && !r.explained {
		r.explained = true
		return
	}
	if len(f.early) < f.maxKeep {
		f.early[k] = earlyExpl{dst, dport}
	}
}

// Unexplained returns TCP/UDP flows no listener accounted for, oldest
// first. These shouldn't exist (every TCP/UDP flow is redirected); if they
// do, they're still reported, so nothing NFLOG saw goes unlisted.
func (f *Flows) Unexplained() []Flow {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*flowRec
	for _, r := range f.all {
		if (r.Proto == protoTCP || r.Proto == protoUDP) && !r.explained {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].seen.Before(out[j].seen) })
	fl := make([]Flow, len(out))
	for i, r := range out {
		fl[i] = r.Flow
	}
	return fl
}
