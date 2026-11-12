package main

import (
	"fmt"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/uddeshya-world/gapproof/internal/agents"
	"github.com/uddeshya-world/gapproof/internal/bundle"
	"github.com/uddeshya-world/gapproof/internal/diff"
	"github.com/uddeshya-world/gapproof/internal/evidence"
	"github.com/uddeshya-world/gapproof/internal/harness"
	"github.com/uddeshya-world/gapproof/internal/licence"
	"github.com/uddeshya-world/gapproof/internal/sinkhole"
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
			in, _ := cmd.Flags().GetString("in")
			f, _ := cmd.Flags().GetString("format")
			b, err := evidence.Load(in)
			if err != nil {
				return usagef("--in: %v", err)
			}
			if err := writeReports(in, b, f); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote the %s report in %s (re-run `gapproof sign --rehash` if the directory was signed)\n", f, in)
			return nil
		}),
	}
	cmd.Flags().String("in", "", "evidence directory")
	cmd.Flags().String("format", "both", "html|md|both")
	return cmd
}

func newDiffCmd() *cobra.Command {
	var lic string
	var gate bool
	cmd := &cobra.Command{
		Use:   "diff <old-evidence-dir> <new-evidence-dir>",
		Short: "Show what changed between two evidence directories",
		Long: "Compare two runs: the AGR change, new/resolved/changed findings, new egress\n" +
			"destinations and model/crypto hash changes. Findings are matched on rule and\n" +
			"evidence, not on ID. The itemised diff is a Pro feature (offline licence); without\n" +
			"one, the level change and counts are shown.\n\n" +
			"With --exit-code, exit 1 when the new run regressed (lower level or a new open finding).",
		Args: exactArgs(2),
		RunE: runE(func(cmd *cobra.Command, args []string) error {
			old, err := evidence.Load(args[0])
			if err != nil {
				return usagef("%v", err)
			}
			cur, err := evidence.Load(args[1])
			if err != nil {
				return usagef("%v", err)
			}
			r := diff.Compare(old, cur)
			out := cmd.OutOrStdout()
			if st := licenceStatus(lic); st.Has("diff") {
				r.WriteFull(out)
			} else {
				r.WriteSummary(out)
				fmt.Fprintf(out, "\n(itemised diff is a Pro feature: %s)\n", st.Reason)
			}
			if gate && r.Regressed() {
				return &checkFailedError{fmt.Sprintf("regressed: %s → %s", r.OldLevel, r.NewLevel)}
			}
			return nil
		}),
	}
	cmd.Flags().StringVar(&lic, "licence", "", "Pro licence file (default $GAPPROOF_LICENCE); checked offline")
	cmd.Flags().BoolVar(&gate, "exit-code", false, "exit 1 if the new run regressed")
	return cmd
}

func licenceStatus(path string) licence.Status {
	if path == "" {
		path = os.Getenv("GAPPROOF_LICENCE")
	}
	return licence.Check(path, licence.PublicKey, time.Now())
}

func newLicenceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "licence",
		Short: "Show the offline Pro licence status (never checked online)",
		Args:  exactArgs(0),
		RunE: runE(func(cmd *cobra.Command, _ []string) error {
			lic, _ := cmd.Flags().GetString("licence")
			st := licenceStatus(lic)
			if !st.Valid {
				fmt.Fprintf(cmd.OutOrStdout(), "no valid Pro licence: %s (free features only)\n", st.Reason)
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Pro licence: %s, features %s, valid through %s\n", st.Licence.Org, strings.Join(st.Licence.Features, ","), st.Licence.Expires)
			return nil
		}),
	}
	cmd.Flags().String("licence", "", "licence file (default $GAPPROOF_LICENCE)")
	issue := &cobra.Command{
		Use:    "issue",
		Short:  "Sign a licence with an Ed25519 key from `gapproof keygen` (release tooling)",
		Hidden: true,
		Args:   exactArgs(0),
		RunE: runE(func(cmd *cobra.Command, _ []string) error {
			if err := requireFlags(cmd, "key", "org", "expires"); err != nil {
				return err
			}
			kp, _ := cmd.Flags().GetString("key")
			org, _ := cmd.Flags().GetString("org")
			exp, _ := cmd.Flags().GetString("expires")
			feats, _ := cmd.Flags().GetStringSlice("features")
			if _, err := time.Parse(time.DateOnly, exp); err != nil {
				return usagef("--expires must be YYYY-MM-DD")
			}
			key, err := bundle.LoadPrivateKey(kp)
			if err != nil {
				return usagef("--key: %v", err)
			}
			b, err := licence.Sign(licence.Licence{Org: org, Expires: exp, Features: feats}, key)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(b)
			return err
		}),
	}
	issue.Flags().String("key", "", "Ed25519 private key")
	issue.Flags().String("org", "", "licensee organisation")
	issue.Flags().String("expires", "", "last valid day, YYYY-MM-DD")
	issue.Flags().StringSlice("features", []string{"diff"}, "granted features")
	cmd.AddCommand(issue)
	return cmd
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
		RunE: runE(func(cmd *cobra.Command, args []string) error {
			if _, err := os.Stat(args[0]); err != nil {
				return usagef("harness image tarball: %v", err)
			}
			e, err := harness.DetectEngine(cmd.Context())
			if err != nil {
				return err
			}
			cfg, err := harness.Load(cmd.Context(), e, args[0])
			if err != nil {
				return err
			}
			pin := "pinned by this build"
			if !harness.Pinned() {
				pin = "UNPINNED: development build of gapproof"
			}
			fmt.Fprintf(cmd.OutOrStdout(), "loaded %s (config %s, %s)\n", harness.ImageRef(), cfg, pin)
			return nil
		}),
	})
	cmd.AddCommand(&cobra.Command{
		Use:    "digest <gapproof-harness.oci.tar>",
		Short:  "Print the config digest and layer diff_ids to pin (release tooling)",
		Hidden: true,
		Args:   exactArgs(1),
		RunE: runE(func(cmd *cobra.Command, args []string) error {
			cfg, layers, err := harness.Digest(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", cfg, strings.Join(layers, ","))
			return nil
		}),
	})
	return cmd
}

func newSinkholeCmd() *cobra.Command {
	var pcap string
	cmd := &cobra.Command{
		Use:    "sinkhole",
		Short:  "Internal: run the egress sinkhole inside the harness sidecar",
		Hidden: true,
		Args:   exactArgs(0),
		RunE: runE(func(cmd *cobra.Command, _ []string) error {
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			cfg := sinkhole.Config{Events: cmd.OutOrStdout()}
			if pcap != "" {
				f, err := os.OpenFile(pcap, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
				if err != nil {
					return err
				}
				defer f.Close()
				cfg.Pcap = f
			}
			return sinkhole.Run(ctx, cfg)
		}),
	}
	cmd.Flags().StringVar(&pcap, "pcap", "", "also write NFLOG packets (first 256 bytes) as pcapng to this path")
	return cmd
}

func newAgentsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agents",
		Short: "Work with agent manifests (agents.yaml)",
		Args:  exactArgs(0),
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "import-mcp <tools-list.json>...",
		Short: "Suggest an agents.yaml from MCP tools/list dumps (labels are low-confidence: review them)",
		Args: func(c *cobra.Command, args []string) error {
			if len(args) == 0 {
				return usagef("give at least one tools/list JSON dump")
			}
			return nil
		},
		RunE: runE(func(cmd *cobra.Command, args []string) error {
			var dumps [][]byte
			for _, a := range args {
				b, err := os.ReadFile(a)
				if err != nil {
					return usagef("%v", err)
				}
				dumps = append(dumps, b)
			}
			y, err := agents.SuggestManifest(dumps...)
			if err != nil {
				return usagef("%v", err)
			}
			_, err = cmd.OutOrStdout().Write(y)
			return err
		}),
	})
	return cmd
}
