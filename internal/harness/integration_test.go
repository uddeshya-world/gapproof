package harness

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/uddeshya-world/gapproof/internal/sinkhole"
)

// requireEngine returns a real engine with the harness image loaded, or
// skips (fails when GAPPROOF_REQUIRE_CONTAINER=1).
func requireEngine(t *testing.T) *Engine {
	t.Helper()
	if testing.Short() {
		t.Skip("container test skipped in -short mode")
	}
	// Use the pin `make harness` wrote, as a `make build` binary would.
	if b, err := os.ReadFile("../../dist/harness.pin"); err == nil && PinnedConfigDigest == "" {
		if f := strings.Fields(string(b)); len(f) == 2 {
			PinnedConfigDigest, PinnedLayers = f[0], f[1]
		}
	}
	ctx := context.Background()
	e, err := DetectEngine(ctx)
	if err == nil {
		err = Check(ctx, e)
	}
	if err != nil {
		if os.Getenv("GAPPROOF_REQUIRE_CONTAINER") == "1" {
			t.Fatalf("GAPPROOF_REQUIRE_CONTAINER=1: %v (run `make harness build` and `bin/gapproof harness load dist/gapproof-harness-*.oci.tar`)", err)
		}
		t.Skip(err)
	}
	return e
}

func buildProbe(t *testing.T, e *Engine) string {
	t.Helper()
	dir := t.TempDir()
	build := exec.Command("go", "build", "-trimpath", "-o", filepath.Join(dir, "probe"), "./testdata/probe")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build probe: %v\n%s", err, out)
	}
	df, _ := os.ReadFile("testdata/probe/Dockerfile")
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), df, 0o644); err != nil {
		t.Fatal(err)
	}
	const ref = "gapproof-probe:test"
	if out, err := exec.Command(e.Bin, "build", "-q", "-t", ref, dir).CombinedOutput(); err != nil {
		t.Fatalf("build probe image: %v\n%s", err, out)
	}
	return ref
}

// TestEgressProbe is the M3 acceptance test: all nine attempts are logged
// with the right kind/destination/port/hints, the driver's traffic is not
// logged, nothing reaches the host side, and nothing is pulled.
func TestEgressProbe(t *testing.T) {
	e := requireEngine(t)
	ref := buildProbe(t, e)
	stopCap := startHostCapture(t, e)

	out := t.TempDir()
	res, err := Run(context.Background(), e, Config{Target: ref, Workload: "testdata/workload.sh", Observe: 20 * time.Second, Pcap: true, OutDir: out})
	if err != nil {
		t.Fatal(err)
	}
	leaked := stopCap()
	if leaked != "" {
		t.Errorf("host-side capture saw packets to off-subnet destinations:\n%s", leaked)
	}
	if !res.Passed() || !res.WorkloadPassed {
		t.Errorf("target/workload should pass: %+v", res)
	}
	has := func(desc string, ok func(ev sinkhole.Event) bool) {
		t.Helper()
		for _, ev := range res.Events {
			if ok(ev) {
				return
			}
		}
		t.Errorf("missing attempt: %s", desc)
	}
	has("(1) resolver lookup of example.com", func(ev sinkhole.Event) bool {
		return ev.Kind == "dns" && ev.Name == "example.com" && ev.QType == "A" && ev.Port == 53
	})
	has("(2) DNS straight to 8.8.8.8:53", func(ev sinkhole.Event) bool {
		return ev.Kind == "dns" && ev.Name == "direct.example" && ev.OrigDstIP == "8.8.8.8" && ev.Port == 53
	})
	has("(3) HTTPS to api.openai.com", func(ev sinkhole.Event) bool {
		return ev.Kind == "tcp" && ev.Name == "api.openai.com" && ev.Port == 443 && ev.ProtoHint == "tls" && ev.SNI == "api.openai.com" && strings.HasPrefix(ev.OrigDstIP, "198.18.")
	})
	has("(4) HTTP Host telemetry.example", func(ev sinkhole.Event) bool {
		return ev.Kind == "tcp" && ev.Port == 80 && ev.ProtoHint == "http" && ev.HTTPHost == "telemetry.example" && ev.Name == "telemetry.example"
	})
	has("(5) TLS to literal 1.1.1.1 with SNI", func(ev sinkhole.Event) bool {
		return ev.Kind == "tcp" && ev.OrigDstIP == "1.1.1.1" && ev.Port == 443 && ev.SNI == "cloudflare-dns.com" && ev.Name == ""
	})
	has("(6) NTP to 8.8.8.8:123", func(ev sinkhole.Event) bool {
		return ev.Kind == "udp" && ev.OrigDstIP == "8.8.8.8" && ev.Port == 123 && ev.ProtoHint == "ntp"
	})
	has("(7) statsd to 203.0.113.10:8125", func(ev sinkhole.Event) bool {
		return ev.Kind == "udp" && ev.OrigDstIP == "203.0.113.10" && ev.Port == 8125 && ev.ProtoHint == "statsd"
	})
	has("(8) QUIC Initial to 1.1.1.1:443", func(ev sinkhole.Event) bool {
		return ev.Kind == "udp" && ev.OrigDstIP == "1.1.1.1" && ev.Port == 443 && ev.ProtoHint == "quic" && ev.SNI == "one.one.one.one"
	})
	has("(9) ICMP echo to 1.1.1.1", func(ev sinkhole.Event) bool {
		return ev.Kind == "icmp" && ev.OrigDstIP == "1.1.1.1"
	})
	for _, ev := range res.Events {
		if ev.Port == 8080 || ev.SrcPort == 8080 {
			t.Errorf("driver traffic logged as egress: %+v", ev)
		}
		if ev.Note != "" && strings.Contains(ev.Note, "NFLOG only") {
			t.Errorf("flow not explained by a listener: %+v", ev)
		}
	}
	for _, c := range e.Calls() {
		if strings.Contains(strings.Join(c, " "), " pull") {
			t.Errorf("engine call pulls an image: %v", c)
		}
	}
	for _, f := range []string{"egress.log.jsonl", "egress.pcapng", "harness.log"} {
		if st, err := os.Stat(filepath.Join(out, f)); err != nil || st.Size() == 0 {
			t.Errorf("%s missing or empty: %v", f, err)
		}
	}
	assertNoLeftovers(t, e, res.RunID)
	if t.Failed() {
		b, _ := os.ReadFile(filepath.Join(out, "egress.log.jsonl"))
		h, _ := os.ReadFile(filepath.Join(out, "harness.log"))
		t.Logf("egress.log.jsonl:\n%s\nharness.log:\n%s", b, h)
	}
}

// TestCancelCleansUp: cancelling mid-run (what Ctrl-C does via the CLI's
// signal context) leaves no labelled containers or networks.
func TestCancelCleansUp(t *testing.T) {
	e := requireEngine(t)
	ref := buildProbe(t, e)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(8 * time.Second); cancel() }()
	_, err := Run(ctx, e, Config{Target: ref, Observe: 5 * time.Minute, OutDir: t.TempDir(), RunID: "canceltest01"})
	if err == nil {
		t.Fatal("expected cancellation error")
	}
	assertNoLeftovers(t, e, "canceltest01")
}

func assertNoLeftovers(t *testing.T, e *Engine, runID string) {
	t.Helper()
	for _, args := range [][]string{
		{"ps", "-aq", "--filter", "label=" + LabelRunID + "=" + runID},
		{"network", "ls", "-q", "--filter", "label=" + LabelRunID + "=" + runID},
	} {
		out, err := exec.Command(e.Bin, args...).Output()
		if err != nil {
			t.Fatal(err)
		}
		if s := strings.TrimSpace(string(out)); s != "" {
			t.Errorf("left behind after run %s (%v): %s", runID, args, s)
		}
	}
}

// startHostCapture runs tcpdump in the engine host's network namespace
// (privileged, --network host) watching for any packet to the probe's
// off-subnet destinations or the synthetic range. The returned func stops
// it and returns what it saw ("" = nothing left).
func startHostCapture(t *testing.T, e *Engine) func() string {
	t.Helper()
	df := "FROM alpine:3.20\nRUN apk add --no-cache tcpdump\n"
	b := exec.Command(e.Bin, "build", "-q", "-t", "gapproof-tcpdump:test", "-")
	b.Stdin = strings.NewReader(df)
	if out, err := b.CombinedOutput(); err != nil {
		t.Fatalf("build tcpdump image: %v\n%s", err, out)
	}
	filter := "dst host 1.1.1.1 or dst host 8.8.8.8 or dst host 203.0.113.10 or dst net 198.18.0.0/15"
	name := "gapproof-hostcap-" + strings.ReplaceAll(t.Name(), "/", "-")
	_ = exec.Command(e.Bin, "rm", "-f", name).Run()
	if out, err := exec.Command(e.Bin, "run", "-d", "--name", name, "--privileged", "--network", "host",
		"gapproof-tcpdump:test", "tcpdump", "-i", "any", "-n", "-l", filter).CombinedOutput(); err != nil {
		t.Fatalf("start host capture: %v\n%s", err, out)
	}
	time.Sleep(2 * time.Second)
	return func() string {
		time.Sleep(time.Second)
		out, _ := exec.Command(e.Bin, "logs", name).Output() // packet lines go to stdout
		_ = exec.Command(e.Bin, "rm", "-f", name).Run()
		return strings.TrimSpace(string(out))
	}
}
