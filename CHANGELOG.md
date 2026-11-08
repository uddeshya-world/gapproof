# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: SemVer.

## [Unreleased]

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
