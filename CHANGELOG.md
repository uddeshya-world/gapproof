# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: SemVer.

## [Unreleased]

## [0.1.0] - 2026-11-12

Quiet release for design partners (D-001): no announcement.

### Added (verify --rescan, D-041)
- `gapproof verify --rescan` (requires `--artifact`): after the signature, hashes and artifact digest pass, re-runs the static modules offline on the delivered image tar and diffs the result against the signed evidence (`rescan: match` or the differences, exit 1). Egress is not re-run. `scan` now also copies the `--agents` manifest into the evidence directory (`gapproof.agents.yaml`); bundles made before this can still be rescanned, with the agents result not compared.

### Added (one-shot targets, D-040)
- `scan --one-shot` for batch jobs: the target passes AGR-1 liveness by exiting 0 inside the observation window. Still running counts as hung, and a non-zero exit fails. Evidence records `one_shot`, and the reports show the mode.

### Changed (models, D-039)
- numpy's pre-1.0 `numpy.core._internal._reconstruct` alias is a safe pickle import. Attribute access through it (`__globals__` etc.) stays critical.

### Changed (rule promotion)
- Phone-home: `PH-ANTHROPIC-SDK-HOSTED`, `PH-OPENAI-SDK-HOSTED` and `PH-UNSTRUCTURED-ANALYTICS` are now high confidence, each checked against upstream source (anthropic-sdk-python v2.8.0, openai-python v3.49.0, unstructured 0.27.37, on 2026-11-12) with permalinks in `source`. `PH-UNSTRUCTURED-ANALYTICS` now treats any non-empty `SCARF_NO_ANALYTICS` or `DO_NOT_TRACK` as opted out, as upstream does.

### Changed (CI)
- `actions/checkout@v5` and `actions/setup-go@v6` (Node 24). A manual `demo` workflow runs `make demo demo-e2e` on an amd64 runner and uploads the evidence.

### Fixed
- Image identity: every `index.json` entry pinned to the config digest is accepted as the loaded image's ID, so attested `docker save` archives scan.
- Egress dedupe folds bare teardown flows into the detailed entry for the same endpoint, which made rescans byte-identical.
- GNU sparse layer members are rejected.
- Zip fixture checks compare decompressed members, so CI passes on Go 1.26 and 1.27.

### Changed (demo follow-ups, D-035…D-038)
- Models: `builtins.range` and the other side-effect-free value constructors (`int`, `float`, `bool`, `str`, `bytes`, `tuple`, `list`, `dict`, plus the Python 2 `xrange`/`unicode`/`long`) are safe pickle imports. Every other builtin and every dotted name stays critical. There is no path-based exemption for test fixtures (D-035).
- Phone-home: rules take `python_package_version` (a PEP 440 range that fails closed). `PH-CHROMA-TELEMETRY` is bounded to `<1.5.4`, because upstream made telemetry a no-op and dropped posthog (D-036).
- Sinkhole: a duplicate NFLOG record for one flow (back-to-back A/AAAA queries) is no longer reported as an unexplained flow. That record showed up as a phantom `udp 127.0.0.11:53` egress entry under Docker (D-037).
- Demo: the amd64 fixed-rag waivers are generated from the arm64 file and kept in sync by a test, and `demo/tools/verify_amd64_waivers.sh` checks them statically (D-038).

### Changed (M5: INV-01 is MESA's definition, D-032)
- `internal/agents` now ports MESA's graded lattice (mesa-ibi-scanner 0.4.0 `docs/LATTICE.md`): closure fixpoint over (P, U, E) with flow caps and gated edges removed, a fixed production threshold of (2, 2, 2), witness paths and a minimal edge cut. The old two-label path rule (D-030) is gone.
- Findings: one `AGENT-INV01-<agent>` per violating agent (high, unwaivable) and `AGENT-NEARMISS-<agent>` (info, never affects AGR).
- `agents.yaml` gains the read labels `internal` (P=2) and `untrusted` (U=3); `public` is now U=2 and no longer harmless. `zone` and `thresholds` are rejected.
- The evidence `agents` section records `mesa_spec`, `inv01_threshold` and `inv01_near_misses`.
- `agents import-mcp` labels tools that fetch web pages, mail, issues or comments as `reads: [untrusted]` (low confidence).
- Golden parity on all 104 public MESA lattice fixtures, nine of them also as converted `agents.yaml`; property tests P-01, P-03, P-04, P-05, P-11 and P-12.

### Added (M7: diff, CI gate, offline licence)
- `gapproof diff <old> <new> [--exit-code]` compares two runs:
  - the AGR change;
  - new, resolved and changed findings (matched on rule plus evidence, not on ID);
  - egress destinations;
  - model and crypto hash changes.

  The itemised view needs a Pro licence; without one, `diff` shows the level change and counts.
- `internal/licence`: an offline Ed25519-signed JSON licence (org, expiry, features). The public key is pinned at build time (`LICENCE_PUB`). There is never a network check. An expired or invalid licence degrades to the free features. `gapproof licence` shows the status, and a hidden `licence issue` command signs licences for release tooling.
- `action/`: the composite `gapproof-scan` GitHub Action. It downloads a checksum-verified release (or uses a local binary), writes the report to the job summary, keeps a single PR comment up to date, and gates on `min-agr`. A CI job runs it against a smoke image and asserts AGR-2.
- Releases build, pin and ship the harness image per arch (`make release-harness`). goreleaser refuses to build unpinned binaries.

### Added (M4: scan pipeline, evidence, AGR, reports)
- `gapproof scan` runs every module end to end:
  - extracts the tar, or saves a local ref (never pulled);
  - runs inventory, phone-home, crypto, models (plus `--models`) and agents;
  - then runs the egress harness on the same image. The engine's image ID must match the extracted config digest.
- `internal/evidence`:
  - deterministic `evidence.json` and `summary.json`;
  - AGR computation per AGR_SPEC, with `unassessed`, blocking reasons, `--skip` caps, scope files and waivers (stale and expired handling);
  - an unwaivable allowlist;
  - per-module finding IDs.
- `internal/report`: a self-contained HTML report (no scripts or external assets, print CSS) and a Markdown twin, both with a "fix first" list and the disclaimer.
- A live TTY summary: a line per module, the egress table, the AGR badge and blocking reasons. `scan --replay <dir> [--only] [--replay-speed]` reprints it from saved evidence.
- `gapproof report --in <dir>` regenerates the reports. `gapproof agents import-mcp` suggests an `agents.yaml` from MCP `tools/list` dumps.
- Two live scans of the same image give a byte-identical `evidence.json`. `TestNoEgress` now runs full static scans under `--network none`.

### Added (M6: sign/verify, AI-BOM, OSCAL)
- `keygen`, `sign` and `verify` (`internal/bundle`):
  - `MANIFEST.sha256` and `MANIFEST.sig` over every file;
  - deterministic bundle tars;
  - `verify --artifact` checks that the image the customer received is the one that was scanned, fully offline.
- `internal/aibom`: a CycloneDX 1.6 AI-BOM. `internal/oscal`: OSCAL 1.1.2 assessment-results. Both validate against the official schemas in a test-only container.

### Added (M5: agent containment)
- `internal/agents`: a strict `agents.yaml` loader, an INV-01 path analysis over the tool and handoff graph, and a provably minimal cut set where the graph is small enough (otherwise flagged "not proven minimal"). Also an MCP `tools/list` import that produces low-confidence suggestions.

### Added (M3: egress harness)
- `internal/sinkhole`, which runs as `gapproof sinkhole` and owns the target's netns:
  - NFLOG on every new flow, redirects to DNS/TCP/UDP catch-all listeners and a deny-all filter, with no exemptions;
  - synthetic DNS answers;
  - TLS SNI and ALPN, the HTTP Host, QUIC Initial SNI (decrypted), and NTP, statsd and syslog classification;
  - pcapng output.
- `internal/harness`: Docker/Podman orchestration that never pulls:
  - an internal network, the sinkhole sidecar, the target sharing its netns, and a driver container running the workload;
  - a pinned harness image;
  - targets that request capabilities are refused;
  - cleanup on cancel.
- The 9-attempt probe passes, and a host-side capture sees zero packets.

### Added (M2: phone-home rules + crypto inventory)
- `rules/`: embedded rule pack of 16 phone-home rules, each with a verified source URL or `confidence: low`, plus positive and negative fixtures and golden output.
- `rules/cmvp_snapshot.json` (2026-11-09): OpenSSL FIPS provider 3.1.2 (#4985, active), 3.0.8/3.0.9 (#4282, historical since 2026-09-21), Go Cryptographic Module v1.0.0 (#5247, active), v1.26.0 (in process).
- `internal/inventory`: Python distributions (with wheel tags) and application source files in one walk.
- `internal/phonehome`: strict YAML rule engine. Conditions cover installed packages, image env values, public URLs in env, and application source. `unless_env` and `unless_file` suppress a rule. Evidence anchors to METADATA, a source line, or the image config digest.
- `internal/crypto`:
  - Finds OpenSSL, LibreSSL, BoringSSL, NSS, Mbed TLS, GnuTLS, libgcrypt, wolfSSL and nettle, including static copies inside wheels and node addons.
  - Detects the OpenSSL FIPS provider and whether `openssl.cnf` activates it, and Go binaries' FIPS mode via buildinfo.
  - Assigns statuses from the CMVP snapshot, and flags weak hashes and non-CSPRNG secrets in application code.
- `gapproof rules list [--json]` and `gapproof rules test <id> <fixture-dir> [--expect match|none]`.
- e2e: a real `python:3.12-slim` + `cryptography` image. The wheel's bundled OpenSSL 3.4.1 is reported as unvalidated, with the snapshot date.

### Added (M1: safe filesystem + model scanner)
- `internal/fsscan`: extracts `docker save` / `podman save` archives (Docker and OCI layouts) layer by layer with OCI whiteouts.
  - Every write goes through `os.Root`, and symlinks resolve with chroot semantics. `../` traversal, absolute and climbing symlinks, symlink loops and write-through-symlink are all contained or rejected.
  - Limits on entries, file size, total bytes, metadata and decompression ratio. zstd and xz layers are refused with a clear error.
  - Integrity chain: config digest, then every `diff_id`, then OCI blob digests. The engine image ID is recorded too.
  - Device files are never created and setuid bits are dropped. Case collisions on macOS are reported.
- `internal/models`: finds and SHA-256-hashes model artefacts and checks them without loading anything:
  - A pickle opcode walker for protocols 0–5, raw and inside PyTorch zips, including legacy torch files, with stack and memo emulation.
  - safetensors header validation, GGUF metadata and tensor infos, and ONNX external-data checks (including subgraphs).
  - TorchScript code, Keras Lambda layers and non-Keras modules, NumPy object arrays (their pickle payload is walked), Hugging Face `auto_map`, and SSTI-style chat templates.
  - Zip-bomb and duplicate-member detection.
  - It fails closed, and pickle imports are deny-by-default.
- 30 generated fixtures, a golden `scan.json` and a determinism test. Coverage is 91% on `internal/models`.
- The import-policy test now covers every package in the module and forbids `os/exec` and `plugin` outside the harness (rule 3).

### Added (M0: skeleton + no-egress self-test)
- Go module `github.com/uddeshya-world/gapproof` (Go 1.26+) and the package layout from CLAUDE.md.
- Cobra CLI: `scan`, `report`, `sign`, `verify`, `diff`, `keygen`, `rules list|test`, `harness load`, the hidden `sinkhole`, and `version`. All argument validation is real now: exit 2 for usage errors, and exit 3 for stubs until their milestone lands.
- `version` reports the FIPS 140-3 mode and the Go Cryptographic Module version the binary was built with.
- `TestNoNetworkImports`: checks the binary's import graph. There's no HTTP/TLS/RPC/SMTP stack, and `net` is reachable only through justified packages. The checker has its own tests.
- `TestNoEgress`: runs the static Linux binary under `--network none --read-only --cap-drop ALL` in a distroless container.
- Makefile (`build`, `test`, `lint`, `e2e`, `size`), GoReleaser v2 config (static linux/darwin amd64+arm64, `GOFIPS140=v1.0.0`, checksums, SBOMs, draft releases), and GitHub Actions CI and release workflows.
- `docs/AGR_SPEC.md`, `docs/DECISIONS.md`, `docs/DEPENDENCIES.md`, LICENSE (Apache-2.0).
