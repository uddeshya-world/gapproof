// Command probe is the M3 integration-test target. It makes the nine egress
// attempts of docs/03_BUILD_PLAN.md M3, then serves HTTP on :8080 for the
// driver and stays up. Every attempt has a short timeout; none can succeed
// inside the harness.
package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/uddeshya-world/gapproof/internal/testutil/quicinit"
)

func main() {
	go func() {
		http.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "probe ok") })
		_ = http.ListenAndServe(":8080", nil)
	}()
	time.Sleep(time.Second)
	step := func(n int, what string, fn func() error) {
		err := fn()
		fmt.Fprintf(os.Stderr, "probe %d %s: %v\n", n, what, err)
	}
	d := net.Dialer{Timeout: 3 * time.Second}
	step(1, "resolver lookup example.com", func() error { _, err := net.LookupHost("example.com"); return err })
	step(2, "dns direct to 8.8.8.8:53", func() error {
		c, err := d.Dial("udp", "8.8.8.8:53")
		if err != nil {
			return err
		}
		defer c.Close()
		q := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 6, 'd', 'i', 'r', 'e', 'c', 't', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0, 1, 0, 1}
		_, _ = c.Write(q)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err = c.Read(make([]byte, 512))
		return err
	})
	step(3, "https api.openai.com", func() error {
		c, err := tls.DialWithDialer(&d, "tcp", "api.openai.com:443", &tls.Config{NextProtos: []string{"h2", "http/1.1"}})
		if err == nil {
			c.Close()
		}
		return err
	})
	step(4, "http Host telemetry.example", func() error {
		c, err := d.Dial("tcp", "telemetry.example:80")
		if err != nil {
			return err
		}
		defer c.Close()
		_, err = c.Write([]byte("GET /v1/events HTTP/1.1\r\nHost: telemetry.example\r\nUser-Agent: probe\r\n\r\n"))
		_, _ = c.Read(make([]byte, 64))
		return err
	})
	step(5, "tls literal 1.1.1.1 sni cloudflare-dns.com", func() error {
		c, err := tls.DialWithDialer(&d, "tcp", "1.1.1.1:443", &tls.Config{ServerName: "cloudflare-dns.com", NextProtos: []string{"h2"}})
		if err == nil {
			c.Close()
		}
		return err
	})
	udp := func(addr string, payload []byte) error {
		c, err := d.Dial("udp", addr)
		if err != nil {
			return err
		}
		defer c.Close()
		_, err = c.Write(payload)
		return err
	}
	ntp := make([]byte, 48)
	ntp[0] = 0x23 // LI 0, VN 4, mode 3 (client)
	step(6, "ntp 8.8.8.8:123", func() error { return udp("8.8.8.8:123", ntp) })
	step(7, "statsd 203.0.113.10:8125", func() error { return udp("203.0.113.10:8125", []byte("gapproof.probe.hits:1|c\n")) })
	step(8, "quic initial 1.1.1.1:443", func() error {
		return udp("1.1.1.1:443", quicinit.Packet([]byte{1, 2, 3, 4, 5, 6, 7, 8}, "one.one.one.one", []string{"h3"}))
	})
	step(9, "icmp echo 1.1.1.1", func() error {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMP)
		if err != nil {
			return err
		}
		defer syscall.Close(fd)
		echo := []byte{8, 0, 0, 0, 0, 1, 0, 1, 'g', 'p'}
		return syscall.Sendto(fd, echo, 0, &syscall.SockaddrInet4{Addr: [4]byte{1, 1, 1, 1}})
	})
	fmt.Fprintln(os.Stderr, "probe done")
	select {}
}
