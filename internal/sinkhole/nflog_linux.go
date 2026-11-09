//go:build linux

package sinkhole

import (
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

// Raw NFLOG over AF_NETLINK/NETLINK_NETFILTER, standard library only
// (spec §3.1). Constants from linux/netfilter/nfnetlink{,_log}.h.
const (
	nfnlSubsysULOG   = 4
	nfulnlMsgPacket  = 0
	nfulnlMsgConfig  = 1
	nfulaCfgCmd      = 1
	nfulaCfgMode     = 2
	nfulaCfgQThresh  = 5
	nfulnlCfgCmdBind = 1
	nfulnlCopyPacket = 2
	nfulaTimestamp   = 3
	nfulaPayload     = 9
	nlaTypeMask      = 0x3fff
	nflogCopyRange   = 256
)

// NFLOG is a bound netlink socket for one NFLOG group.
type NFLOG struct {
	fd       int
	Overruns int // ENOBUFS seen: the kernel dropped log records (a coverage gap, reported)
}

// OpenNFLOG binds group (needs CAP_NET_ADMIN: call before dropping privileges).
func OpenNFLOG(group uint16) (*NFLOG, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("nflog socket: %w", err)
	}
	n := &NFLOG{fd: fd}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		n.Close()
		return nil, fmt.Errorf("nflog bind: %w", err)
	}
	// Big receive buffer (FORCE needs CAP_NET_ADMIN, which we still have).
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, 8<<20)
	tv := syscall.NsecToTimeval((200 * time.Millisecond).Nanoseconds())
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		n.Close()
		return nil, err
	}
	steps := [][]byte{
		attr(nfulaCfgCmd, []byte{nfulnlCfgCmdBind}),
		attr(nfulaCfgMode, append(binary.BigEndian.AppendUint32(nil, nflogCopyRange), nfulnlCopyPacket, 0)),
		attr(nfulaCfgQThresh, binary.BigEndian.AppendUint32(nil, 1)),
	}
	for i, a := range steps {
		if err := n.config(group, uint32(i+1), a); err != nil {
			n.Close()
			return nil, err
		}
	}
	return n, nil
}

func (n *NFLOG) config(group uint16, seq uint32, a []byte) error {
	body := []byte{syscall.AF_INET, 0, byte(group >> 8), byte(group)} // nfgenmsg
	body = append(body, a...)
	msg := make([]byte, syscall.NLMSG_HDRLEN, syscall.NLMSG_HDRLEN+len(body))
	binary.NativeEndian.PutUint32(msg[0:], uint32(syscall.NLMSG_HDRLEN+len(body)))
	binary.NativeEndian.PutUint16(msg[4:], nfnlSubsysULOG<<8|nfulnlMsgConfig)
	binary.NativeEndian.PutUint16(msg[6:], syscall.NLM_F_REQUEST|syscall.NLM_F_ACK)
	binary.NativeEndian.PutUint32(msg[8:], seq)
	msg = append(msg, body...)
	if err := syscall.Sendto(n.fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return fmt.Errorf("nflog config: %w", err)
	}
	buf := make([]byte, 4096)
	nr, _, err := syscall.Recvfrom(n.fd, buf, 0)
	if err != nil {
		return fmt.Errorf("nflog config ack: %w", err)
	}
	msgs, err := syscall.ParseNetlinkMessage(buf[:nr])
	if err != nil {
		return err
	}
	for _, m := range msgs {
		if m.Header.Type == syscall.NLMSG_ERROR && len(m.Data) >= 4 {
			if code := int32(binary.NativeEndian.Uint32(m.Data)); code != 0 {
				return fmt.Errorf("nflog config: %w", syscall.Errno(-code))
			}
		}
	}
	return nil
}

func attr(typ uint16, data []byte) []byte {
	l := 4 + len(data)
	b := binary.NativeEndian.AppendUint16(nil, uint16(l))
	b = binary.NativeEndian.AppendUint16(b, typ)
	b = append(b, data...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

// Packet is one logged packet.
type Packet struct {
	Time    time.Time
	Payload []byte // IPv4 packet, first nflogCopyRange bytes
}

// Run delivers packets to fn until stop is closed.
func (n *NFLOG) Run(stop <-chan struct{}, fn func(Packet)) error {
	buf := make([]byte, 1<<16)
	for {
		select {
		case <-stop:
			return nil
		default:
		}
		nr, _, err := syscall.Recvfrom(n.fd, buf, 0)
		if err != nil {
			switch {
			case errors.Is(err, syscall.EAGAIN), errors.Is(err, syscall.EINTR):
				continue
			case errors.Is(err, syscall.ENOBUFS):
				n.Overruns++
				continue
			}
			return fmt.Errorf("nflog recv: %w", err)
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:nr])
		if err != nil {
			continue
		}
		for _, m := range msgs {
			if m.Header.Type != nfnlSubsysULOG<<8|nfulnlMsgPacket || len(m.Data) < 4 {
				continue
			}
			if p, ok := parsePacketAttrs(m.Data[4:]); ok {
				fn(p)
			}
		}
	}
}

func parsePacketAttrs(b []byte) (Packet, bool) {
	p := Packet{}
	for len(b) >= 4 {
		l := int(binary.NativeEndian.Uint16(b))
		typ := binary.NativeEndian.Uint16(b[2:]) & nlaTypeMask
		if l < 4 || l > len(b) {
			break
		}
		data := b[4:l]
		switch typ {
		case nfulaPayload:
			p.Payload = append([]byte(nil), data...)
		case nfulaTimestamp:
			if len(data) >= 16 {
				sec := binary.BigEndian.Uint64(data)
				usec := binary.BigEndian.Uint64(data[8:])
				p.Time = time.Unix(int64(sec), int64(usec)*1000).UTC()
			}
		}
		adv := (l + 3) &^ 3
		if adv > len(b) {
			break
		}
		b = b[adv:]
	}
	if p.Time.IsZero() {
		p.Time = time.Now().UTC()
	}
	return p, p.Payload != nil
}

// Close closes the socket.
func (n *NFLOG) Close() error { return syscall.Close(n.fd) }

// origDst reads SO_ORIGINAL_DST (the pre-REDIRECT IPv4 destination).
func origDst(fd uintptr) (ip [4]byte, port int, err error) {
	const soOriginalDst = 80
	var sa syscall.RawSockaddrInet4
	l := uint32(unsafe.Sizeof(sa))
	_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.SOL_IP, soOriginalDst,
		uintptr(unsafe.Pointer(&sa)), uintptr(unsafe.Pointer(&l)), 0)
	if e != 0 {
		return ip, 0, e
	}
	p := (*[2]byte)(unsafe.Pointer(&sa.Port))
	return sa.Addr, int(p[0])<<8 | int(p[1]), nil
}
