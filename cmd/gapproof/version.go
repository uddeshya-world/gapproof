package main

import (
	"crypto/fips140"
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// Set at release time via -ldflags "-X main.version=... -X main.commit=... -X main.date=...".
var (
	version = "v0.0.0-dev"
	commit  = "none"
	date    = "unknown"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version, build and crypto-module information",
		Args:  exactArgs(0),
		RunE: runE(func(cmd *cobra.Command, _ []string) error {
			fmt.Fprint(cmd.OutOrStdout(), versionString())
			return nil
		}),
	}
}

// versionString reports what crypto Gapproof itself uses, as the README
// promises. It states facts about the build; it makes no certification claim.
func versionString() string {
	module := "none (GOFIPS140 not set at build time)"
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "GOFIPS140" && s.Value != "" && s.Value != "off" {
				module = s.Value
			}
		}
	}
	mode := "off"
	if fips140.Enabled() {
		mode = "on"
		if fips140.Enforced() {
			mode = "on (enforced)"
		}
	}
	return fmt.Sprintf(
		"gapproof %s (commit %s, built %s)\n"+
			"go:            %s %s/%s\n"+
			"fips140 mode:  %s\n"+
			"fips140 module: %s (runtime reports %q)\n"+
			"crypto used:   SHA-256 (hashing), Ed25519 (signing)\n"+
			"network:       none; gapproof never makes a network call\n",
		version, commit, date,
		runtime.Version(), runtime.GOOS, runtime.GOARCH,
		mode, module, fips140.Version(),
	)
}
