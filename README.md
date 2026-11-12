# Gapproof

**Prove your AI is ready for the air gap.** Gapproof is an open-source CLI that checks whether an AI product (container images, model weights, agent tool graphs) can run inside a disconnected network, and emits signed, offline-verifiable evidence for the customer's security approver.

![it passes its own test: TestNoEgress](https://img.shields.io/badge/no--egress%20self--test-TestNoEgress-brightgreen)

> Status: pre-release (M3–M7 built, demo apps and v0.1 tag pending). See `docs/03_BUILD_PLAN.md`.

<!-- GIF placeholder: `gapproof scan --replay evidence/leaky-rag` then fixed-rag, recorded with asciinema/vhs. -->

## 30-second quickstart
```sh
gapproof harness load gapproof-harness-<version>-linux-<arch>.oci.tar   # once; shipped with each release, never pulled
docker save myapp:1.4 -o myapp.tar                                      # or pass the local ref directly
gapproof scan --image myapp.tar --observe 10m --agents agents.yaml --out evidence/
open evidence/report.html
gapproof keygen --out vendor && gapproof sign --in evidence/ --key vendor.key
gapproof verify evidence.bundle.tar --pub vendor.pub --artifact myapp.tar   # the approver, fully offline
gapproof verify evidence.bundle.tar --pub vendor.pub --artifact myapp.tar --rescan   # also re-run the static modules on the tar and diff against the evidence
```
`scan` runs five modules on the same image:
- **egress:** runs the image with every packet blocked and logged, behind a sinkhole that owns its network namespace;
- **phonehome:** static telemetry and hosted-API rules;
- **crypto:** an inventory matched against a dated CMVP snapshot;
- **models:** a pickle opcode scan, safetensors/GGUF/ONNX checks and hashes;
- **agents:** INV-01 (MESA's graded lattice): flags any agent whose closure combines private data, untrusted input and egress at or above (2, 2, 2), from a declared manifest, with witness paths and a minimal cut.

It writes `evidence.json`, `summary.json`, a CycloneDX AI-BOM, OSCAL assessment-results and the HTML/Markdown reports, plus a `MANIFEST.sha256` that `sign` signs.

Exit codes: `0` ok, `1` below `--min-agr` (CI gate), `2` usage error, `3` internal error.

## AGR levels (`docs/AGR_SPEC.md`)
| Level | Name | Meaning |
|---|---|---|
| `unassessed` | Not assessed | The egress module didn't run. Static findings are still reported, but no level is claimed. |
| **AGR-0** | Fails offline | Assessed. With all egress blocked, the target didn't start or the workload failed. |
| **AGR-1** | Runs offline | Started and the workload passed with all egress blocked. |
| **AGR-2** | Silent | AGR-1, and no out-of-scope egress attempt during the observed window (always shown, e.g. `AGR-2 (observed 10m)`). |
| **AGR-3** | Provable | AGR-2, and phone-home, crypto and models ran with no open high or critical finding, no unwaivable finding, and every model hashed. |
| **AGR-4** | Contained | AGR-3, and the agents module found zero INV-01 violations in a declared manifest (`agents: []` declares none). |

Accepted risks go in `gapproof.waivers.yaml` (with an owner and an expiry). Waived findings stay in the report. Internal names and CIDRs go in `gapproof.scope.yaml`.

## In CI
`action/` is a GitHub Action. It scans the image you built, comments the Markdown report on the PR, and fails below `min-agr` (see `action/README.md`). `gapproof diff old/ new/ --exit-code` gates on regressions between two runs.

## It passes its own test
Gapproof never makes a network call: no telemetry, no update checks, no licence pings (the Pro licence is an offline, Ed25519-signed file). CI enforces this two ways:
- `TestNoNetworkImports` fails if anything in the binary links an HTTP/TLS client, or reaches package `net` without a written justification.
- `TestNoEgress` runs full scans with the static binary under `--network none`.

The scanned image is never pulled, and the harness image is pinned by digest in every release binary.

## Build
```sh
make build    # static binary at bin/gapproof, FIPS 140-3 module mode, size-gated
make test     # unit tests
make lint     # gofmt, go vet, staticcheck
make harness  # build + pin the egress harness image (needs Docker or Podman)
make e2e      # container tests: no-egress, real images, the 9-attempt egress probe
```

## Verifying a release
Each release ships `checksums.sha256` with a keyless cosign signature (`checksums.sha256.sigstore.json`) and a GitHub build-provenance attestation for every archive. Both are checked online, by you, before the binary goes into the air gap; the binary itself never makes a network call.
```sh
sha256sum -c checksums.sha256 --ignore-missing
cosign verify-blob checksums.sha256 --bundle checksums.sha256.sigstore.json \
  --certificate-identity-regexp '^https://github.com/uddeshya-world/gapproof/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify gapproof_<version>_<os>_<arch>.tar.gz --repo uddeshya-world/gapproof
```

## Crypto Gapproof itself uses
SHA-256 (hashing evidence and artefacts) and Ed25519 (signing). Release builds use Go's FIPS 140-3 module mode (`GOFIPS140=v1.0.0`), and `gapproof version` prints the mode and module version.

What that does and doesn't mean:
- The Go Cryptographic Module v1.0.0 is listed on NIST's CMVP as certificate #5247 (status Active on 2026-11-12, security level 1, "when operated in approved mode"). Source: https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5247 and https://go.dev/doc/security/fips140.
- Gapproof is **not** a validated product. Building against a validated module doesn't validate the program, and a validation applies to the tested operating environments listed in the CMVP record, which we haven't matched to your platform. Whether this satisfies a requirement of yours is for you and your assessor to decide.
- The module version Gapproof is built with, v1.0.0, is the validated one. Newer module versions (v1.26.0) are not yet validated.
- This describes how Gapproof is built. It isn't a claim about any product Gapproof scans.

## What Gapproof is not
Gapproof produces an **inventory and findings**. It does not certify FIPS 140-3, grant an ATO, or guarantee anything. Its control mappings (NIST 800-53) are informative, and every report says so.

## Docs
- What it builds: `docs/02_SPEC.md`
- How levels are computed: `docs/AGR_SPEC.md` (CC-BY-4.0)
- Design decisions: `docs/DECISIONS.md`. Dependencies: `docs/DEPENDENCIES.md`
- Reporting a vulnerability: `SECURITY.md`

Licence: Apache-2.0.
