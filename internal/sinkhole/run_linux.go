//go:build linux

package sinkhole

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// Run programs the netns, drops privileges, starts the listeners and logs
// until ctx is cancelled (SIGTERM from `docker stop`).
func Run(ctx context.Context, cfg Config) error {
	s, err := newSinkhole(cfg)
	if err != nil {
		return err
	}
	digest, _, err := ProgramNetns()
	if err != nil {
		return err
	}
	nf, err := OpenNFLOG(NFGroup)
	if err != nil {
		return err
	}
	defer nf.Close()
	if err := DropPrivileges(); err != nil {
		return err
	}

	lc := net.ListenConfig{}
	dnsU, err := lc.ListenPacket(ctx, "udp4", fmt.Sprintf("127.0.0.1:%d", DNSPort))
	if err != nil {
		return err
	}
	dnsT, err := lc.Listen(ctx, "tcp4", fmt.Sprintf("127.0.0.1:%d", DNSPort))
	if err != nil {
		return err
	}
	tcpL, err := lc.Listen(ctx, "tcp4", fmt.Sprintf("0.0.0.0:%d", TCPPort))
	if err != nil {
		return err
	}
	udpL, err := lc.ListenPacket(ctx, "udp4", fmt.Sprintf("0.0.0.0:%d", UDPPort))
	if err != nil {
		return err
	}
	stop := make(chan struct{})
	done := make(chan struct{}, 5)
	go func() {
		if err := nf.Run(stop, func(p Packet) { s.onPacket(p.Time, p.Payload, len(p.Payload)) }); err != nil {
			slog.Error("nflog reader stopped", "err", err)
		}
		done <- struct{}{}
	}()
	go func() { s.serveDNSUDP(dnsU.(*net.UDPConn)); done <- struct{}{} }()
	go func() { s.serveTCP(dnsT, true); done <- struct{}{} }()
	go func() { s.serveTCP(tcpL, false); done <- struct{}{} }()
	go func() { s.serveUDP(udpL.(*net.UDPConn)); done <- struct{}{} }()

	s.log.Emit(Event{Kind: KindReady, Note: "netfilter " + digest})
	if cfg.Ready != nil {
		cfg.Ready()
	}
	<-ctx.Done()
	// Let in-flight NFLOG records and peeks land before closing.
	time.Sleep(s.wait + 200*time.Millisecond)
	close(stop)
	for _, c := range []io.Closer{dnsU, dnsT, tcpL, udpL} {
		c.Close()
	}
	for range 5 {
		<-done
	}
	s.finish(nf.Overruns)
	return nil
}

func (s *Sinkhole) serveDNSUDP(c *net.UDPConn) {
	buf := make([]byte, 4096)
	for {
		n, from, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		msg := append([]byte(nil), buf[:n]...)
		go func() {
			var orig netip.AddrPort
			if f, ok := s.flows.Lookup(protoUDP, int(from.Port()), s.wait); ok {
				orig = netip.AddrPortFrom(f.Dst, uint16(f.DstPort))
			}
			if resp := s.handleDNS(msg, orig, false); resp != nil {
				_, _ = c.WriteToUDPAddrPort(resp, from)
			}
		}()
	}
}

func (s *Sinkhole) serveUDP(c *net.UDPConn) {
	buf := make([]byte, 65536)
	for {
		n, from, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		p := append([]byte(nil), buf[:min(n, 4096)]...)
		go s.handleUDP(p, int(from.Port()))
	}
}

func (s *Sinkhole) serveTCP(l net.Listener, dns bool) {
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		dst, err := connOrigDst(c)
		sport := c.RemoteAddr().(*net.TCPAddr).Port
		if err != nil {
			slog.Warn("SO_ORIGINAL_DST failed", "err", err)
		}
		select {
		case s.slots <- struct{}{}:
		default:
			// Saturated: still log the attempt, skip the peek.
			s.log.Emit(Event{Kind: KindTCP, OrigDstIP: addrStr(dst), Port: int(dst.Port()), SrcPort: sport, ProtoHint: HintUnknown, Note: "not peeked: handler limit"})
			c.Close()
			continue
		}
		go func() {
			defer func() { <-s.slots }()
			if dns {
				s.serveDNSTCP(c, dst, sport)
				return
			}
			s.handleTCP(c, dst, sport)
		}()
	}
}

func (s *Sinkhole) serveDNSTCP(c net.Conn, dst netip.AddrPort, sport int) {
	defer c.Close()
	s.flows.Explain(protoTCP, dst.Addr(), int(dst.Port()), sport)
	for range 16 {
		_ = c.SetDeadline(time.Now().Add(s.timeout))
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(l[:]))
		if n > 4096 {
			return
		}
		msg := make([]byte, n)
		if _, err := io.ReadFull(c, msg); err != nil {
			return
		}
		resp := s.handleDNS(msg, dst, true)
		if resp == nil {
			return
		}
		if _, err := c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(resp))), resp...)); err != nil {
			return
		}
	}
}

func connOrigDst(c net.Conn) (netip.AddrPort, error) {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return netip.AddrPort{}, errors.New("not a syscall.Conn")
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	var ip [4]byte
	var port int
	var oerr error
	if err := rc.Control(func(fd uintptr) { ip, port, oerr = origDst(fd) }); err != nil {
		return netip.AddrPort{}, err
	}
	if oerr != nil {
		return netip.AddrPort{}, oerr
	}
	return netip.AddrPortFrom(netip.AddrFrom4(ip), uint16(port)), nil
}
