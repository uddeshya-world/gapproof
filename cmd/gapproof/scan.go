package main

import (
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var scanModules = []string{"egress", "phonehome", "crypto", "models", "agents"}

type scanOpts struct {
	image, rootfs, models, workload, agents string
	scope, waivers, out                     string
	observe                                 time.Duration
	skip                                    []string
	minAGR                                  int

	replay      string
	only        []string
	replaySpeed float64
}

func newScanCmd() *cobra.Command {
	o := &scanOpts{}
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan a container image or rootfs for air-gap readiness",
		Long: "Scan a container image (docker save tar or local ref) or an unpacked rootfs.\n" +
			"Runs the egress harness, phone-home rules, crypto inventory, model scanner\n" +
			"and agent containment analysis, and writes an evidence directory.\n\n" +
			"With --replay, re-print a saved run's terminal output instead (for demos).",
		Args: exactArgs(0),
		RunE: runE(func(cmd *cobra.Command, _ []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			if o.replay != "" {
				return notImplemented("M4")
			}
			return notImplemented("M1–M4")
		}),
	}
	f := cmd.Flags()
	f.StringVar(&o.image, "image", "", "container image: docker save tarball or local image ref")
	f.StringVar(&o.rootfs, "rootfs", "", "unpacked root filesystem directory (instead of --image)")
	f.StringVar(&o.models, "models", "", "extra model directory not inside the image")
	f.StringVar(&o.workload, "workload", "", "smoke-test script run by the driver container")
	f.DurationVar(&o.observe, "observe", 10*time.Minute, "egress observation window")
	f.StringVar(&o.agents, "agents", "", "agents.yaml or MCP tools/list JSON dump")
	f.StringSliceVar(&o.skip, "skip", nil, "modules to skip: "+strings.Join(scanModules, "|"))
	f.IntVar(&o.minAGR, "min-agr", -1, "CI gate: exit 1 if the result is below AGR-N (0-4)")
	f.StringVar(&o.scope, "scope", "", "gapproof.scope.yaml: declared internal names/CIDRs (docs/AGR_SPEC.md §2)")
	f.StringVar(&o.waivers, "waivers", "", "gapproof.waivers.yaml: accepted risks (docs/AGR_SPEC.md §3)")
	f.StringVar(&o.out, "out", "", "evidence output directory")
	f.StringVar(&o.replay, "replay", "", "re-print the terminal output of a saved evidence directory")
	f.StringSliceVar(&o.only, "only", nil, "with --replay: only these modules")
	f.Float64Var(&o.replaySpeed, "replay-speed", 1.0, "with --replay: playback speed multiplier")
	return cmd
}

func (o *scanOpts) validate() error {
	if o.replay != "" {
		if o.image != "" || o.rootfs != "" || o.out != "" {
			return usagef("--replay cannot be combined with --image, --rootfs or --out")
		}
		if o.replaySpeed <= 0 {
			return usagef("--replay-speed must be > 0")
		}
		return checkModules("--only", o.only)
	}
	if len(o.only) > 0 {
		return usagef("--only requires --replay")
	}
	switch {
	case o.image == "" && o.rootfs == "":
		return usagef("one of --image or --rootfs is required")
	case o.image != "" && o.rootfs != "":
		return usagef("--image and --rootfs are mutually exclusive")
	case o.out == "":
		return usagef("--out is required")
	case o.observe <= 0:
		return usagef("--observe must be > 0")
	case o.minAGR < -1 || o.minAGR > 4:
		return usagef("--min-agr must be between 0 and 4")
	}
	if o.rootfs != "" && !slices.Contains(o.skip, "egress") {
		// A bare rootfs can't be run, so egress can't be observed (AGR_SPEC §5).
		return usagef("--rootfs cannot run the egress harness; add --skip egress (result: unassessed, static-only)")
	}
	return checkModules("--skip", o.skip)
}

func checkModules(flag string, mods []string) error {
	for _, m := range mods {
		if !slices.Contains(scanModules, m) {
			return usagef("%s: unknown module %q (want one of %s)", flag, m, strings.Join(scanModules, ", "))
		}
	}
	return nil
}
