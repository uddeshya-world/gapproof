package main

import (
	"encoding/json"
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/uddeshya-world/gapproof/internal/crypto"
	"github.com/uddeshya-world/gapproof/internal/phonehome"
)

func newRulesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Inspect the embedded phone-home rule pack",
		Args:  exactArgs(0),
	}

	var asJSON bool
	list := &cobra.Command{
		Use:   "list",
		Short: "List embedded rules and the CMVP snapshot date",
		Args:  exactArgs(0),
		RunE: runE(func(cmd *cobra.Command, _ []string) error {
			rs, err := phonehome.Builtin()
			if err != nil {
				return err
			}
			snap, err := crypto.BuiltinSnapshot()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{"phonehome": rs, "cmvp_snapshot_date": snap.SnapshotDate})
			}
			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tSEVERITY\tCONFIDENCE\tTITLE")
			for _, r := range rs {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.ID, r.Severity, r.Confidence, r.Title)
			}
			tw.Flush()
			fmt.Fprintf(out, "\n%d phone-home rules. CMVP snapshot dated %s (informative; confirm on the NIST CMVP site).\n", len(rs), snap.SnapshotDate)
			return nil
		}),
	}
	list.Flags().BoolVar(&asJSON, "json", false, "print the rules as JSON")

	var expect string
	test := &cobra.Command{
		Use:   "test <rule-id> <fixture-dir>",
		Short: "Run one rule against a fixture directory (rootfs/ + optional env.txt)",
		Long: "Run one phone-home rule against a fixture directory laid out as:\n\n" +
			"  <dir>/rootfs/   files to scan\n" +
			"  <dir>/env.txt   optional image environment, KEY=VALUE per line\n\n" +
			"With --expect, exit 1 when the result doesn't match (for rule authors' CI).",
		Args: exactArgs(2),
		RunE: runE(func(cmd *cobra.Command, args []string) error {
			if expect != "" && expect != "match" && expect != "none" {
				return usagef("--expect must be match or none")
			}
			rs, err := phonehome.Builtin()
			if err != nil {
				return err
			}
			r := phonehome.ByID(rs, args[0])
			if r == nil {
				return usagef("unknown rule %q (see `gapproof rules list`)", args[0])
			}
			in, closeFn, err := phonehome.LoadFixture(cmd.Context(), args[1])
			if err != nil {
				return usagef("%v", err)
			}
			defer closeFn()
			fs, err := phonehome.Evaluate(cmd.Context(), []*phonehome.Rule{r}, in)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if len(fs) == 0 {
				fmt.Fprintf(out, "%s: NO MATCH\n", r.ID)
			} else {
				fmt.Fprintf(out, "%s: MATCH (%d finding(s))\n", r.ID, len(fs))
				for _, f := range fs {
					fmt.Fprintf(out, "  [%s] %s\n      %s\n", f.Severity, f.Evidence.Path, f.Evidence.Detail)
				}
			}
			switch {
			case expect == "match" && len(fs) == 0:
				return &checkFailedError{"expected a match"}
			case expect == "none" && len(fs) > 0:
				return &checkFailedError{"expected no match"}
			}
			return nil
		}),
	}
	test.Flags().StringVar(&expect, "expect", "", "match|none: exit 1 if the result differs")

	cmd.AddCommand(list, test)
	return cmd
}
