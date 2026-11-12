package harness

import (
	"context"
	"os/exec"
)

func execCombined(ctx context.Context, bin string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, bin, args...).CombinedOutput()
}
