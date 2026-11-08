// Command gapproof checks whether an AI product is ready for an air-gapped
// network and emits offline-verifiable evidence. See docs/02_SPEC.md.
//
// Gapproof never makes a network call (CLAUDE.md rule 1). TestNoEgress and
// TestNoNetworkImports enforce this.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// Exit codes (docs/02_SPEC.md §2).
const (
	exitOK             = 0
	exitBelowThreshold = 1
	exitUsage          = 2
	exitInternal       = 3
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the CLI and maps errors to exit codes. Every RunE is wrapped
// by runE, which turns untyped errors into internal errors, so any untyped
// error that reaches this point came from cobra's own argument/flag parsing
// and is a usage error.
func run(args []string, stdout, stderr io.Writer) int {
	root := newRootCmd(stdout, stderr)
	if args == nil {
		args = []string{} // cobra treats nil as "use os.Args", which we never want here
	}
	root.SetArgs(args)
	err := root.Execute()
	if err == nil {
		return exitOK
	}
	fmt.Fprintln(stderr, "gapproof:", err)
	return exitCode(err)
}

func exitCode(err error) int {
	var ie *internalError
	var bt *belowThresholdError
	var cf *checkFailedError
	switch {
	case err == nil:
		return exitOK
	case errors.As(err, &bt), errors.As(err, &cf):
		return exitBelowThreshold
	case errors.Is(err, errNotImplemented), errors.As(err, &ie):
		return exitInternal
	default:
		return exitUsage
	}
}

// errNotImplemented marks stub commands that land in a later milestone.
var errNotImplemented = errors.New("not implemented yet")

func notImplemented(milestone string) error {
	return fmt.Errorf("%w (arrives in %s, see docs/03_BUILD_PLAN.md)", errNotImplemented, milestone)
}

type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

func usagef(format string, a ...any) error { return &usageError{fmt.Sprintf(format, a...)} }

type internalError struct{ err error }

func (e *internalError) Error() string { return e.err.Error() }
func (e *internalError) Unwrap() error { return e.err }

// checkFailedError means a check ran and its result didn't meet the
// expectation (exit 1), e.g. `rules test --expect`.
type checkFailedError struct{ msg string }

func (e *checkFailedError) Error() string { return e.msg }

// belowThresholdError means the scan ran but the target is below --min-agr.
type belowThresholdError struct{ level, min string }

func (e *belowThresholdError) Error() string {
	return fmt.Sprintf("result %s is below --min-agr %s", e.level, e.min)
}
