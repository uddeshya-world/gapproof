package main

import (
	"slices"

	"github.com/spf13/cobra"
)

// Stub commands. Each validates its arguments now, so the CLI contract (and
// exit code 2 for usage errors) is fixed from M0, and returns
// errNotImplemented (exit 3) until its milestone lands.

func newReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Render the HTML and/or Markdown report from an evidence directory",
		Args:  exactArgs(0),
		RunE: runE(func(cmd *cobra.Command, _ []string) error {
			if err := requireFlags(cmd, "in"); err != nil {
				return err
			}
			if f, _ := cmd.Flags().GetString("format"); !slices.Contains([]string{"html", "md", "both"}, f) {
				return usagef("--format must be html, md or both")
			}
			return notImplemented("M4")
		}),
	}
	cmd.Flags().String("in", "", "evidence directory")
	cmd.Flags().String("format", "both", "html|md|both")
	return cmd
}

func newDiffCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "diff <old-evidence-dir> <new-evidence-dir>",
		Short: "Show what changed between two evidence directories",
		Args:  exactArgs(2),
		RunE:  runE(func(*cobra.Command, []string) error { return notImplemented("M7") }),
	}
}

func newHarnessCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "harness",
		Short: "Manage the offline egress-harness image (never pulled)",
		Args:  exactArgs(0),
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "load <gapproof-harness.oci.tar>",
		Short: "Load the pinned harness image into Docker/Podman and check its digest",
		Args:  exactArgs(1),
		RunE:  runE(func(*cobra.Command, []string) error { return notImplemented("M3") }),
	})
	return cmd
}

func newSinkholeCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "sinkhole",
		Short:  "Internal: run the egress sinkhole inside the harness sidecar",
		Hidden: true,
		Args:   exactArgs(0),
		RunE:   runE(func(*cobra.Command, []string) error { return notImplemented("M3") }),
	}
}
