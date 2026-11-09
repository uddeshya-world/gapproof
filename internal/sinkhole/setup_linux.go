//go:build linux

package sinkhole

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Listener ports inside the netns (spec §3.1).
const (
	DNSPort  = 5353
	TCPPort  = 15001
	UDPPort  = 15002
	NFGroup  = 7
	DropUID  = 65532
	dockerNS = "127.0.0.11" // Docker's embedded resolver; must never be reachable directly
)

// netnsCommands is the exact netns program (D-016). No uid or subnet is
// exempt: nothing in this netns is trusted to originate traffic, so a target
// that setuid()s to the sinkhole's uid gains nothing, and the internal
// network's gateway (the host) is unreachable. Driver->target traffic enters
// via INPUT and its replies are ESTABLISHED, so it is never logged.
func netnsCommands() [][]string {
	nflog := []string{"-j", "NFLOG", "--nflog-group", strconv.Itoa(NFGroup), "--nflog-size", "256", "--nflog-threshold", "1"}
	ipt := func(a ...string) []string { return append([]string{"iptables", "-w", "5"}, a...) }
	return [][]string{
		{"ip", "link", "add", "gp0", "type", "dummy"},
		{"ip", "link", "set", "gp0", "up"},
		{"ip", "route", "replace", "default", "dev", "gp0"},
		// Logging first (mangle runs before nat, so NFLOG sees the original destination).
		ipt(append([]string{"-t", "mangle", "-I", "OUTPUT", "1", "-m", "conntrack", "--ctstate", "NEW", "!", "-o", "lo"}, nflog...)...),
		ipt(append([]string{"-t", "mangle", "-I", "OUTPUT", "2", "-d", dockerNS, "-m", "conntrack", "--ctstate", "NEW"}, nflog...)...),
		// Redirects, inserted ahead of Docker's own DOCKER_OUTPUT jump.
		ipt("-t", "nat", "-I", "OUTPUT", "1", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", strconv.Itoa(DNSPort)),
		ipt("-t", "nat", "-I", "OUTPUT", "2", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", strconv.Itoa(DNSPort)),
		ipt("-t", "nat", "-I", "OUTPUT", "3", "-o", "lo", "!", "-d", dockerNS, "-j", "RETURN"),
		ipt("-t", "nat", "-I", "OUTPUT", "4", "-p", "tcp", "-j", "REDIRECT", "--to-ports", strconv.Itoa(TCPPort)),
		ipt("-t", "nat", "-I", "OUTPUT", "5", "-p", "udp", "-j", "REDIRECT", "--to-ports", strconv.Itoa(UDPPort)),
		// Default deny.
		ipt("-t", "filter", "-I", "OUTPUT", "1", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"),
		// Redirected packets: after REDIRECT the filter hook still sees the
		// pre-NAT output interface, so "-o lo" doesn't match them; accept the
		// listener ports on 127.0.0.1 explicitly.
		ipt("-t", "filter", "-I", "OUTPUT", "2", "-d", "127.0.0.1", "-p", "tcp", "-m", "multiport", "--dports", fmt.Sprintf("%d,%d", DNSPort, TCPPort), "-j", "ACCEPT"),
		ipt("-t", "filter", "-I", "OUTPUT", "3", "-d", "127.0.0.1", "-p", "udp", "-m", "multiport", "--dports", fmt.Sprintf("%d,%d", DNSPort, UDPPort), "-j", "ACCEPT"),
		ipt("-t", "filter", "-I", "OUTPUT", "4", "-d", dockerNS, "-j", "DROP"),
		ipt("-t", "filter", "-I", "OUTPUT", "5", "-o", "lo", "-j", "ACCEPT"),
		ipt("-t", "filter", "-I", "OUTPUT", "6", "-j", "DROP"),
		ipt("-t", "filter", "-P", "OUTPUT", "DROP"),
	}
}

// ProgramNetns sets up routing and netfilter, refusing to continue if IPv6
// is enabled (the rules are IPv4-only). Returns the iptables-save output's
// sha256 and text for the audit trail.
func ProgramNetns() (digest, rules string, err error) {
	if v, err := os.ReadFile("/proc/sys/net/ipv6/conf/all/disable_ipv6"); err == nil && strings.TrimSpace(string(v)) != "1" {
		return "", "", fmt.Errorf("IPv6 is enabled in the harness netns; start the sinkhole with --sysctl net.ipv6.conf.all.disable_ipv6=1")
	}
	for _, c := range netnsCommands() {
		if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
			return "", "", fmt.Errorf("%s: %v: %s", strings.Join(c, " "), err, bytes.TrimSpace(out))
		}
	}
	out, err := exec.Command("iptables-save").Output()
	if err != nil {
		return "", "", fmt.Errorf("iptables-save: %w", err)
	}
	// Drop iptables-save's timestamp comments so the digest is stable.
	var keep []string
	for _, l := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(l, "#") && l != "" {
			keep = append(keep, l)
		}
	}
	rules = strings.Join(keep, "\n") + "\n"
	sum := sha256.Sum256([]byte(rules))
	return "sha256:" + hex.EncodeToString(sum[:]), rules, nil
}

// DropPrivileges switches every thread to uid/gid DropUID with no
// supplementary groups, sets no_new_privs, and verifies all capability sets
// are empty. Called before any listener opens or any target byte is parsed.
func DropPrivileges() error {
	if os.Getuid() != 0 {
		return checkNoCaps() // already unprivileged (tests)
	}
	if err := syscall.Setgroups(nil); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setgid(DropUID); err != nil {
		return fmt.Errorf("setgid: %w", err)
	}
	if err := syscall.Setuid(DropUID); err != nil {
		return fmt.Errorf("setuid: %w", err)
	}
	const prSetNoNewPrivs = 38
	if _, _, e := syscall.AllThreadsSyscall(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0); e != 0 {
		return fmt.Errorf("no_new_privs: %w", e)
	}
	return checkNoCaps()
}

func checkNoCaps() error {
	tasks, err := filepath.Glob("/proc/self/task/*/status")
	if err != nil || len(tasks) == 0 {
		return fmt.Errorf("can't read thread status to verify capabilities")
	}
	for _, t := range tasks {
		b, err := os.ReadFile(t)
		if err != nil {
			continue // thread exited
		}
		for _, l := range strings.Split(string(b), "\n") {
			for _, k := range []string{"CapPrm:", "CapEff:", "CapAmb:"} {
				if strings.HasPrefix(l, k) && strings.Trim(strings.TrimSpace(strings.TrimPrefix(l, k)), "0") != "" {
					return fmt.Errorf("capabilities still held after drop (%s)", strings.TrimSpace(l))
				}
			}
		}
	}
	return nil
}
