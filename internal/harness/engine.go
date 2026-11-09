// Package harness runs the egress harness (spec §3.1): an --internal
// network, the sinkhole sidecar that owns the netns, the target sharing that
// netns, and a driver running the vendor's workload from its own netns. It
// drives Docker or Podman through their CLI (no SDK) and never pulls an
// image: every `run` passes --pull never, and the harness image must have
// been loaded from the release tarball (`gapproof harness load`).
package harness

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// Engine is a container engine CLI (docker or podman).
type Engine struct {
	Bin string

	mu    sync.Mutex
	calls [][]string
}

// DetectEngine returns the first usable engine: docker, then podman.
func DetectEngine(ctx context.Context) (*Engine, error) {
	for _, b := range []string{"docker", "podman"} {
		if _, err := exec.LookPath(b); err != nil {
			continue
		}
		e := &Engine{Bin: b}
		if _, err := e.run(ctx, "version", "--format", "{{.Server.Version}}"); err == nil {
			return e, nil
		}
	}
	return nil, errors.New("no usable container engine: install Docker or Podman and make sure the daemon/socket is reachable")
}

// Calls returns every command line run so far (tests assert, e.g., that
// nothing ever ran `pull`).
func (e *Engine) Calls() [][]string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([][]string(nil), e.calls...)
}

func (e *Engine) run(ctx context.Context, args ...string) ([]byte, error) {
	e.mu.Lock()
	e.calls = append(e.calls, append([]string{e.Bin}, args...))
	e.mu.Unlock()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, e.Bin, args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), &EngineError{Args: args, Err: err, Stderr: strings.TrimSpace(stderr.String())}
	}
	return stdout.Bytes(), nil
}

// EngineError is a failed engine command.
type EngineError struct {
	Args   []string
	Err    error
	Stderr string
}

func (e *EngineError) Error() string {
	return fmt.Sprintf("%s: %v: %s", strings.Join(e.Args, " "), e.Err, e.Stderr)
}

func (e *EngineError) Unwrap() error { return e.Err }

// ExitCode returns the command's exit status, or -1.
func (e *EngineError) ExitCode() int {
	var ee *exec.ExitError
	if errors.As(e.Err, &ee) {
		return ee.ExitCode()
	}
	return -1
}
