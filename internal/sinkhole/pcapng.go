package sinkhole

import (
	"encoding/binary"
	"io"
	"sync"
	"time"
)

// PcapNG writes packets (raw IPv4, LINKTYPE_RAW) as a pcapng file. Only
// the NFLOG copy range (first 256 bytes) of each packet is ever written.
type PcapNG struct {
	mu  sync.Mutex
	w   io.Writer
	err error
}

const linktypeRaw = 101

// NewPcapNG writes the section header and interface description.
func NewPcapNG(w io.Writer) (*PcapNG, error) {
	p := &PcapNG{w: w}
	// Section Header Block.
	shb := make([]byte, 0, 28)
	shb = le32(shb, 0x0a0d0d0a)
	shb = le32(shb, 28)
	shb = le32(shb, 0x1a2b3c4d)
	shb = le16(shb, 1)
	shb = le16(shb, 0)
	shb = append(shb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff) // section length unknown
	shb = le32(shb, 28)
	// Interface Description Block (snaplen 256, microsecond timestamps).
	idb := make([]byte, 0, 20)
	idb = le32(idb, 1)
	idb = le32(idb, 20)
	idb = le16(idb, linktypeRaw)
	idb = le16(idb, 0)
	idb = le32(idb, 256)
	idb = le32(idb, 20)
	if _, err := w.Write(append(shb, idb...)); err != nil {
		return nil, err
	}
	return p, nil
}

// Write appends one Enhanced Packet Block.
func (p *PcapNG) Write(t time.Time, pkt []byte, origLen int) {
	if len(pkt) > 256 {
		pkt = pkt[:256]
	}
	pad := (4 - len(pkt)%4) % 4
	total := 32 + len(pkt) + pad
	us := uint64(t.UnixMicro())
	b := make([]byte, 0, total)
	b = le32(b, 6)
	b = le32(b, uint32(total))
	b = le32(b, 0)
	b = le32(b, uint32(us>>32))
	b = le32(b, uint32(us))
	b = le32(b, uint32(len(pkt)))
	b = le32(b, uint32(origLen))
	b = append(b, pkt...)
	b = append(b, make([]byte, pad)...)
	b = le32(b, uint32(total))
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err == nil {
		_, p.err = p.w.Write(b)
	}
}

func le32(b []byte, v uint32) []byte { return binary.LittleEndian.AppendUint32(b, v) }
func le16(b []byte, v uint16) []byte { return binary.LittleEndian.AppendUint16(b, v) }
