package main

import (
	"errors"
	"io"
	"log/slog"

	"github.com/spf13/cobra"
)

func newRootCmd(stdout, stderr io.Writer) *cobra.Command {
	var verbose bool
	root := &cobra.Command{
		Use:   "gapproof",
		Short: "Prove your AI is ready for the air gap",
		Long: "Gapproof checks whether an AI product (container images, model weights,\n" +
			"agent tool graphs) is ready for an air-gapped network, and emits\n" +
			"offline-verifiable evidence. It produces an inventory and findings; it does\n" +
			"not certify FIPS 140-3 or grant an accreditation.\n\n" +
			"Gapproof itself never makes a network call.",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			level := slog.LevelInfo
			if verbose {
				level = slog.LevelDebug
			}
			slog.SetDefault(slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level})))
		},
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "debug logging to stderr")
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return &usageError{err.Error()} })
	root.CompletionOptions.DisableDefaultCmd = true

	root.AddCommand(
		newScanCmd(),
		newReportCmd(),
		newSignCmd(),
		newVerifyCmd(),
		newDiffCmd(),
		newKeygenCmd(),
		newRulesCmd(),
		newAgentsCmd(),
		newHarnessCmd(),
		newSinkholeCmd(),
		newVersionCmd(),
	)
	return root
}

// runE wraps a command body so that untyped errors become internal errors
// (exit 3). Usage, not-implemented and below-threshold errors pass through.
func runE(fn func(cmd *cobra.Command, args []string) error) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		err := fn(cmd, args)
		if err == nil {
			return nil
		}
		var ue *usageError
		var bt *belowThresholdError
		var cf *checkFailedError
		var ie *internalError
		if errors.As(err, &ue) || errors.As(err, &bt) || errors.As(err, &cf) || errors.As(err, &ie) || errors.Is(err, errNotImplemented) {
			return err
		}
		return &internalError{err}
	}
}

// exactArgs is cobra.ExactArgs with a usage-typed error.
func exactArgs(n int) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if err := cobra.ExactArgs(n)(cmd, args); err != nil {
			return &usageError{err.Error()}
		}
		return nil
	}
}

// requireFlags returns a usage error naming the first empty string flag.
func requireFlags(cmd *cobra.Command, names ...string) error {
	for _, n := range names {
		if v, _ := cmd.Flags().GetString(n); v == "" {
			return usagef("--%s is required", n)
		}
	}
	return nil
}
