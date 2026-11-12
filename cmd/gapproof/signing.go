package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/uddeshya-world/gapproof/internal/bundle"
)

// keygen, sign and verify (docs/02_SPEC.md §3.6). All offline.

func newKeygenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate an Ed25519 signing key pair (<prefix>.key, <prefix>.pub)",
		Long: "Generate an Ed25519 key pair. <prefix>.key is the private key (mode 0600;\n" +
			"keep it off the build host if you can). <prefix>.pub goes to the approver.\n" +
			"Existing files are never overwritten.",
		Args: exactArgs(0),
		RunE: runE(func(cmd *cobra.Command, _ []string) error {
			if err := requireFlags(cmd, "out"); err != nil {
				return err
			}
			prefix, _ := cmd.Flags().GetString("out")
			fp, err := bundle.Keygen(prefix)
			if errors.Is(err, bundle.ErrKeyExists) {
				return usagef("%v", err)
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s.key (private, 0600) and %s.pub\nfingerprint: %s\n", prefix, prefix, fp)
			return nil
		}),
	}
	cmd.Flags().String("out", "", "output path prefix")
	return cmd
}

func newSignCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign an evidence directory's MANIFEST.sha256 with an Ed25519 key and pack the bundle",
		Long: "Sign an evidence directory and write the bundle tar the approver verifies.\n\n" +
			"If MANIFEST.sha256 is absent it is written first (with --artifact-digest, if\n" +
			"given). If it exists and no longer matches the directory, sign refuses unless\n" +
			"--rehash is given, so evidence edited after the scan is never signed silently.\n" +
			"Writes <in>/MANIFEST.sig and the bundle (default <in>.bundle.tar).",
		Args: exactArgs(0),
		RunE: runE(func(cmd *cobra.Command, _ []string) error {
			if err := requireFlags(cmd, "in", "key"); err != nil {
				return err
			}
			in, _ := cmd.Flags().GetString("in")
			keyPath, _ := cmd.Flags().GetString("key")
			digest, _ := cmd.Flags().GetString("artifact-digest")
			out, _ := cmd.Flags().GetString("bundle")
			rehash, _ := cmd.Flags().GetBool("rehash")

			if fi, err := os.Stat(in); err != nil || !fi.IsDir() {
				return usagef("--in %s is not an evidence directory", in)
			}
			if out == "" {
				out = filepath.Clean(in) + ".bundle.tar"
			}
			// Work on the real directory: walking a symlinked root would
			// see no files at all.
			display := in
			resolved, err := filepath.EvalSymlinks(in)
			if err != nil {
				return usagef("--in %s: %v", in, err)
			}
			in = resolved
			key, err := bundle.LoadPrivateKey(keyPath)
			if err != nil {
				return usagef("--key: %v", err)
			}
			if w := bundle.PrivateKeyWarning(keyPath); w != "" {
				fmt.Fprintln(cmd.ErrOrStderr(), w)
			}

			m, err := bundle.ReadManifest(in)
			switch {
			case errors.Is(err, fs.ErrNotExist):
				if _, err := bundle.WriteManifest(in, digest); err != nil {
					return usagef("writing %s: %v", bundle.ManifestName, err)
				}
			case err != nil:
				return usagef("existing %s: %v", bundle.ManifestName, err)
			default:
				if digest != "" && digest != m.Artifact {
					return usagef("--artifact-digest %s differs from the digest recorded in %s (%s)", digest, bundle.ManifestName, m.Artifact)
				}
				if rehash {
					if _, err := bundle.WriteManifest(in, m.Artifact); err != nil {
						return usagef("rehashing: %v", err)
					}
				}
			}
			m, err = bundle.ReadManifest(in)
			if err != nil {
				return err
			}

			fp, err := bundle.Sign(in, key)
			if err != nil {
				if errors.Is(err, bundle.ErrNoFiles) {
					return usagef("--in %s: %v", display, err)
				}
				return usagef("%v (re-run with --rehash to sign the directory as it is now)", err)
			}
			if err := bundle.Pack(in, out); err != nil {
				return usagef("packing: %v", err)
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "signed %s (%d files) with %s\nbundle: %s\n", display, len(m.Files), fp, out)
			if m.Artifact == "" {
				fmt.Fprintln(cmd.ErrOrStderr(), "warning: no artifact digest recorded, so `verify --artifact` can't bind this bundle to an image")
			} else {
				fmt.Fprintf(w, "artifact: %s\n", m.Artifact)
			}
			fmt.Fprintf(w, "verify with: gapproof verify %s --pub <key>.pub [--artifact <image.tar>]\n", out)
			return nil
		}),
	}
	cmd.Flags().String("in", "", "evidence directory")
	cmd.Flags().String("key", "", "Ed25519 private key file (from `gapproof keygen`)")
	cmd.Flags().String("artifact-digest", "", "scanned image config digest (sha256:<hex>), recorded when MANIFEST.sha256 is written")
	cmd.Flags().String("bundle", "", "bundle tar to write (default <in>.bundle.tar)")
	cmd.Flags().Bool("rehash", false, "rewrite a stale MANIFEST.sha256 from the directory's current content before signing")
	return cmd
}

func newVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify <bundle.tar>",
		Short: "Verify a signed evidence bundle, fully offline",
		Long: "Verify a bundle fully offline: the Ed25519 signature against --pub, every\n" +
			"file's SHA-256, no missing or extra files, and with --artifact that the image\n" +
			"tar you received is the one that was scanned. Prints one line, e.g.\n\n" +
			"  AGR-4 · signed by ed25519:3f9a0c1d2e3f4a5b · artifact digest matches\n\n" +
			"The level is the scan's result; the signature is a property of the bundle,\n" +
			"not of the product (docs/AGR_SPEC.md §1). Exit 1 if any check fails.",
		Args: exactArgs(1),
		RunE: runE(func(cmd *cobra.Command, args []string) error {
			if err := requireFlags(cmd, "pub"); err != nil {
				return err
			}
			pubPath, _ := cmd.Flags().GetString("pub")
			artifact, _ := cmd.Flags().GetString("artifact")
			pub, err := bundle.LoadPublicKey(pubPath)
			if err != nil {
				return usagef("--pub: %v", err)
			}
			if fi, err := os.Stat(args[0]); err != nil || !fi.Mode().IsRegular() {
				return usagef("%s is not a bundle file", args[0])
			}
			res, err := bundle.Verify(cmd.Context(), args[0], pub, artifact)
			switch {
			case err == nil:
				fmt.Fprintln(cmd.OutOrStdout(), res.String())
				return nil
			case errors.Is(err, bundle.ErrArtifactMismatch):
				fmt.Fprintln(cmd.OutOrStdout(), res.String())
				return &checkFailedError{err.Error()}
			case errors.Is(err, bundle.ErrVerification), errors.Is(err, bundle.ErrKey):
				return &checkFailedError{"verify FAILED: " + err.Error()}
			case errors.Is(err, fs.ErrNotExist):
				return usagef("%v", err)
			default:
				return err
			}
		}),
	}
	cmd.Flags().String("pub", "", "Ed25519 public key file")
	cmd.Flags().String("artifact", "", "image tar the customer received; checks its digest matches the evidence")
	return cmd
}
