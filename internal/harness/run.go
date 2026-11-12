package harness

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/uddeshya-world/gapproof/internal/sinkhole"
)

// TargetHostname is the hostname of the shared netns (the target inherits
// it). It is always in scope (AGR_SPEC §2).
const TargetHostname = "gapproof-target"

// Label put on every container and network a run creates.
const (
	LabelRunID = "gapproof.runid"
	LabelPID   = "gapproof.pid"
)

// Config for one harness run.
type Config struct {
	Target   string        // local image ref or ID (never pulled)
	Workload string        // optional host path of a POSIX sh script for the driver
	Observe  time.Duration // observation window
	Pcap     bool          // sinkhole writes egress.pcapng
	OutDir   string        // egress.log.jsonl, egress.pcapng, harness.log are written here
	RunID    string        // optional; random if empty
	// Resource limits for the target.
	Memory string // default "4g"
	Pids   int    // default 4096
}

// Result of a run.
type Result struct {
	RunID          string
	Refused        []string // label entries asking for NET_ADMIN/NET_RAW: the target was not run
	TargetStarted  bool
	TargetRunning  bool   // still running at the end of the window
	TargetHealth   string // engine health status if the image has a HEALTHCHECK
	TargetExit     int    // exit code if it stopped
	WorkloadRan    bool
	WorkloadPassed bool
	WorkloadExit   int
	Observed       time.Duration
	Events         []sinkhole.Event // every non-flow, non-control line of egress.log.jsonl
	Notes          []string         // coverage gaps, e.g. NFLOG overruns, unpinned harness
}

// Passed reports whether the target ran and its workload (or, without one,
// its liveness and health) passed with all egress blocked (AGR-1).
func (r *Result) Passed() bool {
	if !r.TargetStarted {
		return false
	}
	alive := r.TargetRunning && r.TargetHealth != "unhealthy"
	if r.WorkloadRan {
		// A target that crashed makes no egress: a passing workload alone
		// must not make it look silent (AGR_SPEC §1, "did not become healthy").
		return r.WorkloadPassed && alive
	}
	return alive
}

// Run executes the harness. On any return, everything it created is removed.
// A non-nil error means the harness itself failed (the result is
// "unassessed"), not that the target failed.
func Run(ctx context.Context, e *Engine, cfg Config) (res *Result, err error) {
	if cfg.Observe <= 0 {
		return nil, errors.New("observe window must be > 0")
	}
	if cfg.Memory == "" {
		cfg.Memory = "4g"
	}
	if cfg.Pids == 0 {
		cfg.Pids = 4096
	}
	if cfg.RunID == "" {
		b := make([]byte, 6)
		_, _ = rand.Read(b)
		cfg.RunID = hex.EncodeToString(b)
	}
	res = &Result{RunID: cfg.RunID}
	if !Pinned() {
		res.Notes = append(res.Notes, "harness image is unpinned (development build of gapproof)")
	}
	if err := Check(ctx, e); err != nil {
		return nil, err
	}
	ti, err := InspectTarget(ctx, e, cfg.Target)
	if err != nil {
		return nil, err
	}
	if hits := RequestedNetCaps(ti.Labels); len(hits) > 0 {
		res.Refused = hits
		return res, nil
	}
	if err := os.MkdirAll(cfg.OutDir, 0o755); err != nil {
		return nil, err
	}
	CleanupStale(ctx, e)

	r := &run{e: e, cfg: cfg, net: "gapproof-" + cfg.RunID}
	defer func() {
		// Teardown must happen even if ctx was cancelled (Ctrl-C).
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
		defer cancel()
		if cerr := r.teardown(cctx); cerr != nil && err == nil {
			err = cerr
		}
	}()
	labels := []string{"--label", LabelRunID + "=" + cfg.RunID, "--label", LabelPID + "=" + strconv.Itoa(os.Getpid())}

	if _, err := e.run(ctx, append(append([]string{"network", "create", "--internal"}, labels...), r.net)...); err != nil {
		return nil, err
	}
	r.netMade = true

	// Sinkhole: owns the netns. NET_ADMIN to program it, SETUID/SETGID to drop.
	sinkArgs := []string{"run", "-d", "--pull", "never", "--name", r.name("sinkhole")}
	sinkArgs = append(sinkArgs, labels...)
	sinkArgs = append(sinkArgs,
		"--network", r.net, "--hostname", TargetHostname,
		"--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--cap-add", "SETUID", "--cap-add", "SETGID",
		"--sysctl", "net.ipv6.conf.all.disable_ipv6=1",
		"--sysctl", "net.ipv6.conf.default.disable_ipv6=1",
		"--sysctl", "net.ipv4.ping_group_range=0 2147483647",
		// REDIRECT maps locally generated packets to 127.0.0.1; without this the
		// kernel drops them as martians (source is the eth0 address).
		"--sysctl", "net.ipv4.conf.all.route_localnet=1",
		"--read-only", "--tmpfs", "/tmp", "--tmpfs", "/run",
		"--mount", "type=volume,dst=/out", // survives stop (unlike tmpfs) until rm -v
		"--entrypoint", "/usr/local/bin/gapproof",
		ImageRef(), "sinkhole")
	if cfg.Pcap {
		sinkArgs = append(sinkArgs, "--pcap", "/out/egress.pcapng")
	}
	if _, err := e.run(ctx, sinkArgs...); err != nil {
		return nil, err
	}
	r.made = append(r.made, r.name("sinkhole"))
	if err := r.waitReady(ctx, 60*time.Second); err != nil {
		return nil, err
	}
	ip, err := r.inspect(ctx, r.name("sinkhole"), `{{(index .NetworkSettings.Networks "`+r.net+`").IPAddress}}`)
	if err != nil || ip == "" {
		return nil, fmt.Errorf("sinkhole has no address on %s: %v", r.net, err)
	}

	// Target: shares the sinkhole netns, no added capabilities.
	tArgs := []string{"run", "-d", "--pull", "never", "--name", r.name("target")}
	tArgs = append(tArgs, labels...)
	tArgs = append(tArgs,
		"--network", "container:"+r.name("sinkhole"),
		"--cap-drop", "NET_RAW", "--cap-drop", "NET_ADMIN",
		"--security-opt", "no-new-privileges",
		"--memory", cfg.Memory, "--pids-limit", strconv.Itoa(cfg.Pids),
		cfg.Target)
	if _, err := e.run(ctx, tArgs...); err != nil {
		return nil, err
	}
	r.made = append(r.made, r.name("target"))
	res.TargetStarted = true
	start := time.Now()

	// Driver: own netns on the internal network, runs the workload.
	type wres struct {
		code int
		err  error
	}
	wdone := make(chan wres, 1)
	if cfg.Workload != "" {
		abs, err := filepath.Abs(cfg.Workload)
		if err != nil {
			return nil, err
		}
		port := "80"
		if len(ti.ExposedPorts) > 0 {
			port = strings.SplitN(ti.ExposedPorts[0], "/", 2)[0]
		}
		dArgs := []string{"run", "--pull", "never", "--name", r.name("driver")}
		dArgs = append(dArgs, labels...)
		dArgs = append(dArgs,
			"--network", r.net, "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
			"-v", abs+":/gapproof/workload.sh:ro",
			"-e", "GAPPROOF_TARGET="+ip+":"+port, "-e", "GAPPROOF_TARGET_IP="+ip, "-e", "GAPPROOF_TARGET_PORT="+port,
			"--entrypoint", "/bin/sh", ImageRef(), "/gapproof/workload.sh")
		r.made = append(r.made, r.name("driver"))
		res.WorkloadRan = true
		wctx, wcancel := context.WithTimeout(ctx, cfg.Observe)
		defer wcancel()
		go func() {
			_, err := e.run(wctx, dArgs...)
			var ee *EngineError
			switch {
			case err == nil:
				wdone <- wres{0, nil}
			case errors.As(err, &ee) && ee.ExitCode() > 0:
				wdone <- wres{ee.ExitCode(), nil}
			default:
				wdone <- wres{-1, err}
			}
		}()
	}

	// Observe for the whole window (periodic telemetry), even if the workload ends early.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(cfg.Observe):
	}
	res.Observed = time.Since(start).Truncate(time.Second)
	if res.WorkloadRan {
		select {
		case w := <-wdone:
			res.WorkloadExit = w.code
			res.WorkloadPassed = w.err == nil && w.code == 0
		case <-time.After(15 * time.Second):
			res.WorkloadExit = -1
		}
	}
	state, _ := r.inspect(ctx, r.name("target"), "{{.State.Running}} {{.State.ExitCode}} {{if .State.Health}}{{.State.Health.Status}}{{end}}")
	if f := strings.Fields(state); len(f) >= 2 {
		res.TargetRunning = f[0] == "true"
		res.TargetExit, _ = strconv.Atoi(f[1])
		if len(f) > 2 {
			res.TargetHealth = f[2]
		}
	}

	// Stop the target and driver first so nothing new happens, then let the
	// sinkhole flush (SIGTERM) and collect its log.
	_, _ = e.run(ctx, "stop", "-t", "5", r.name("target"))
	_, _ = e.run(ctx, "rm", "-f", r.name("driver"))
	if _, err := e.run(ctx, "stop", "-t", "20", r.name("sinkhole")); err != nil {
		return nil, err
	}
	if err := r.collect(ctx, res); err != nil {
		return nil, err
	}
	return res, nil
}

type run struct {
	e       *Engine
	cfg     Config
	net     string
	netMade bool
	made    []string
}

func (r *run) name(role string) string { return "gapproof-" + r.cfg.RunID + "-" + role }

func (r *run) inspect(ctx context.Context, obj, format string) (string, error) {
	out, err := r.e.run(ctx, "inspect", "--format", format, obj)
	return strings.TrimSpace(string(out)), err
}

func (r *run) waitReady(ctx context.Context, max time.Duration) error {
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		out, _ := r.e.run(ctx, "logs", r.name("sinkhole"))
		if bytes.Contains(out, []byte(`"kind":"ready"`)) {
			return nil
		}
		if running, _ := r.inspect(ctx, r.name("sinkhole"), "{{.State.Running}}"); running == "false" {
			logs, _ := r.combinedLogs(ctx, r.name("sinkhole"))
			return fmt.Errorf("sinkhole exited before it was ready:\n%s", logs)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return errors.New("sinkhole did not become ready in time")
}

func (r *run) combinedLogs(ctx context.Context, name string) (string, error) {
	cmd := []string{"logs", name}
	r.e.mu.Lock()
	r.e.calls = append(r.e.calls, append([]string{r.e.Bin}, cmd...))
	r.e.mu.Unlock()
	out, err := execCombined(ctx, r.e.Bin, cmd...)
	return string(out), err
}

// collect writes egress.log.jsonl (sinkhole stdout), harness.log (stderr of
// every container) and the pcap, and parses the events.
func (r *run) collect(ctx context.Context, res *Result) error {
	out, err := r.e.run(ctx, "logs", r.name("sinkhole"))
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(r.cfg.OutDir, "egress.log.jsonl"), out, 0o644); err != nil {
		return err
	}
	ready, stats := false, false
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var ev sinkhole.Event
		if json.Unmarshal(sc.Bytes(), &ev) != nil {
			continue
		}
		switch ev.Kind {
		case sinkhole.KindReady:
			ready = true
		case sinkhole.KindStats:
			stats = true
			if ev.Note != "" {
				res.Notes = append(res.Notes, ev.Note)
			}
		case sinkhole.KindFlow:
		default:
			res.Events = append(res.Events, ev)
		}
	}
	if !ready || !stats {
		return errors.New("sinkhole log is incomplete (no ready/stats record): the observation can't be trusted")
	}
	var hl bytes.Buffer
	for _, role := range []string{"sinkhole", "target"} {
		l, _ := r.combinedLogs(ctx, r.name(role))
		fmt.Fprintf(&hl, "=== %s ===\n%s\n", role, l)
	}
	if err := os.WriteFile(filepath.Join(r.cfg.OutDir, "harness.log"), hl.Bytes(), 0o644); err != nil {
		return err
	}
	if r.cfg.Pcap {
		if _, err := r.e.run(ctx, "cp", r.name("sinkhole")+":/out/egress.pcapng", filepath.Join(r.cfg.OutDir, "egress.pcapng")); err != nil {
			return err
		}
	}
	return nil
}

func (r *run) teardown(ctx context.Context) error {
	var errs []error
	for i := len(r.made) - 1; i >= 0; i-- {
		if _, err := r.e.run(ctx, "rm", "-f", "-v", r.made[i]); err != nil && !strings.Contains(err.Error(), "No such container") && !strings.Contains(err.Error(), "no such container") {
			errs = append(errs, err)
		}
	}
	if r.netMade {
		if _, err := r.e.run(ctx, "network", "rm", r.net); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// CleanupStale removes containers and networks left by crashed runs: those
// labelled gapproof.runid whose owning process (gapproof.pid) is gone.
func CleanupStale(ctx context.Context, e *Engine) {
	for _, kind := range []string{"container", "network"} {
		var args []string
		if kind == "container" {
			args = []string{"ps", "-a", "--filter", "label=" + LabelRunID, "--format", `{{.Names}} {{.Label "` + LabelPID + `"}}`}
		} else {
			args = []string{"network", "ls", "--filter", "label=" + LabelRunID, "--format", `{{.Name}} {{.Label "` + LabelPID + `"}}`}
		}
		out, err := e.run(ctx, args...)
		if err != nil {
			continue
		}
		for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			f := strings.Fields(l)
			if len(f) == 0 {
				continue
			}
			if len(f) == 2 {
				if pid, err := strconv.Atoi(f[1]); err == nil && alive(pid) {
					continue
				}
			}
			if kind == "container" {
				_, _ = e.run(ctx, "rm", "-f", "-v", f[0])
			} else {
				_, _ = e.run(ctx, "network", "rm", f[0])
			}
		}
	}
}

func alive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
