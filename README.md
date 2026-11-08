# Gapproof

**Prove your AI is ready for the air gap.** Gapproof is an open-source CLI that checks whether an AI product (container images, model weights, agent tool graphs) can run inside a disconnected network, and emits offline-verifiable evidence for the customer's security approver.

> Status: pre-alpha. M0 (skeleton + no-egress self-test) is in progress; commands other than `version` are stubs. See `docs/03_BUILD_PLAN.md`.

## Build
```sh
make build    # static binary at bin/gapproof, FIPS 140-3 module mode, size-gated
make test     # unit tests
make lint     # gofmt, go vet, staticcheck
make e2e      # container tests (needs Docker or Podman)
bin/gapproof version
```

## It passes its own test
Gapproof never makes a network call: no telemetry, no update checks, no licence pings. CI enforces this in two ways:
- `TestNoNetworkImports` fails if anything in the binary links an HTTP/TLS client, or reaches package `net` without a written justification.
- `TestNoEgress` runs the static binary with no network at all.

## Crypto Gapproof itself uses
SHA-256 (hashing evidence and artefacts) and Ed25519 (signing). Release builds use Go's FIPS 140-3 module mode (`GOFIPS140=v1.0.0`), and `gapproof version` prints the mode and module version. This describes how Gapproof is built. It isn't a claim about any product Gapproof scans.

## Docs
- What it builds: `docs/02_SPEC.md`
- How readiness levels work: `docs/AGR_SPEC.md` (AGR, CC-BY-4.0)
- Design decisions: `docs/DECISIONS.md`. Dependencies: `docs/DEPENDENCIES.md`

Gapproof produces an inventory and findings. It does not certify FIPS 140-3, grant an ATO, or guarantee anything. Its control mappings are informative.

Licence: Apache-2.0.
