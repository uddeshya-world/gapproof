//go:build !linux

package sinkhole

import (
	"context"
	"errors"
)

// Run is Linux-only: the sinkhole programs a Linux network namespace.
func Run(context.Context, Config) error {
	return errors.New("the sinkhole runs only inside the Linux harness container (gapproof harness load, then gapproof scan)")
}
